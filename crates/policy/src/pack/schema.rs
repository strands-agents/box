//! The Cedar schema fragment that a checked tool pack generates.

use std::fmt::Write as _;

use super::Pack;
use super::grammar::{BASE_FIELDS, FieldKind};
use super::model::UNMODELED_ACTION;
use crate::dogwood::check_against;
use crate::error::PolicyError;
use crate::schema::{ActionSchema, composed_action_schema};
use crate::spelling::{Operator, PolicyWarning};

/// The namespace that holds the vocabulary of every tool pack.
pub(crate) const PACK_NAMESPACE: &str = "Tool";

/// The action group that holds every action of one pack.
pub(crate) const ALL_ACTIONS: &str = "*";

impl Pack {
    /// `Tool::<pack>` for version 1, and `Tool::<pack>::v<version>` after it.
    pub(crate) fn namespace(&self) -> String {
        if self.version > 1 {
            format!("{PACK_NAMESPACE}::{}::v{}", self.name, self.version)
        } else {
            format!("{PACK_NAMESPACE}::{}", self.name)
        }
    }

    /// The Cedar schema fragment that declares the actions and effects of this pack.
    ///
    /// A pack that declares no effect has no `Effect` type and no `effects` field.
    pub(crate) fn schema(&self) -> String {
        let mut schema = String::new();
        let _ = writeln!(schema, "namespace {} {{", self.namespace());
        if !self.effects.is_empty() {
            let values: Vec<String> = self
                .effects
                .keys()
                .map(|effect| format!("{:?}", effect.as_str()))
                .collect();
            let _ = writeln!(schema, "  entity Effect enum [{}];", values.join(", "));
        }
        schema.push_str("  type Output = { status: Long };\n");
        let _ = writeln!(schema, "  action {ALL_ACTIONS:?};");
        let actions = self
            .grammar()
            .action_fields()
            .map(|(action, fields)| (action.as_str(), fields))
            .chain([(UNMODELED_ACTION, Vec::new())]);
        for (action, fields) in actions {
            let [program, program_path, cwd, args, effects, credential_reads] = BASE_FIELDS;
            let mut record = format!(
                "{program}: String, {program_path}: String, {cwd}: String, {args}: Set<String>, \
                 {credential_reads}?: Set<String>"
            );
            if !self.effects.is_empty() {
                let _ = write!(record, ", {effects}: Set<Effect>");
            }
            for (name, kind) in fields {
                let _ = match kind {
                    FieldKind::Bool => write!(record, ", {name:?}: Bool"),
                    FieldKind::String => write!(record, ", {name:?}?: String"),
                    FieldKind::Set => write!(record, ", {name:?}: Set<String>"),
                };
            }
            let _ = writeln!(schema, "  type {action}Input = {{ {record} }};");
            let _ = writeln!(
                schema,
                "  action {action:?} in [{ALL_ACTIONS:?}] appliesTo {{ principal: [Box::Agent], \
                 resource: [Box::Resource], context: {{ input: {action}Input, output?: Output }} }};"
            );
        }
        schema.push_str("}\n");
        schema
    }
}

/// The canonical schema, composed with the fragment of each pack and then each MCP fragment.
pub(crate) fn pack_action_schema(
    packs: &[Pack],
    mcp_schemas: &[String],
) -> Result<ActionSchema, PolicyError> {
    let fragments: Vec<String> = packs.iter().map(Pack::schema).collect();
    composed_action_schema(&fragments, mcp_schemas)
}

/// Strict-validate `source` against the canonical schema, `packs`, and `mcp_schemas`.
pub(crate) fn validate_with_packs(
    source: &str,
    packs: &[Pack],
    mcp_schemas: &[String],
    operator: &Operator,
) -> Result<Vec<PolicyWarning>, PolicyError> {
    let schema = pack_action_schema(packs, mcp_schemas)?;
    check_against(source, schema, operator, true, &[])
        .map(|(_, _, warnings)| warnings)
        .map_err(|refused| refused.into_error())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::mcp_schema::generate_mcp_schema;

    const PACKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/packs");

    const PUSH_TOOL: &str = r#"{"result": {"tools": [{"name": "push", "inputSchema": {
        "type": "object", "properties": {"branch": {"type": "string"}}, "required": ["branch"]}}]}}"#;

    fn valid(name: &str) -> Pack {
        let path = Path::new(PACKS)
            .join("valid")
            .join(format!("{name}.pack.toml"));
        Pack::load(&path).expect("the fixture pack loads")
    }

    /// The valid fixture `name`, at major version `version`.
    fn at_version(name: &str, version: u32) -> Pack {
        let path = Path::new(PACKS)
            .join("valid")
            .join(format!("{name}.pack.toml"));
        let text = std::fs::read_to_string(path).expect("the fixture pack reads");
        let text: String = text
            .lines()
            .map(|line| {
                if line.starts_with("version") {
                    format!("version = {version}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect();
        Pack::parse(&text).expect("the fixture pack loads at another version")
    }

    /// Every pack that loads: each valid fixture, and each pack beside a corpus.
    fn every_valid_pack() -> Vec<(PathBuf, Pack)> {
        let mut paths = Vec::new();
        for directory in ["valid", "corpus"] {
            let directory = Path::new(PACKS).join(directory);
            for entry in std::fs::read_dir(&directory).expect("the fixture directory reads") {
                let path = entry.expect("a fixture entry").path();
                if path.to_string_lossy().ends_with(".pack.toml") {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        assert!(!paths.is_empty(), "no pack loads");
        paths
            .into_iter()
            .map(|path| {
                let pack = Pack::load(&path).expect("the fixture pack loads");
                (path, pack)
            })
            .collect()
    }

    fn load(source: &str, packs: &[Pack], mcp_schemas: &[String]) -> Result<(), String> {
        validate_with_packs(source, packs, mcp_schemas, &Operator::unanchored())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn every_valid_pack_composes_with_the_canonical_and_an_mcp_schema_and_loads_in_dogwood() {
        let mcp = generate_mcp_schema("git", PUSH_TOOL).expect("the MCP schema generates");
        let mut failures = Vec::new();
        for (path, pack) in every_valid_pack() {
            let namespace = pack.namespace();
            let source = format!(
                "permit (principal, action in {namespace}::Action::\"*\", resource);\n\
                 permit (principal, action == {namespace}::Action::\"unmodeled\", resource);\n\
                 permit (principal, action == git::Action::\"push\", resource)\n\
                 when {{ context.input.branch == \"main\" }};\n\
                 permit (principal, action == Box::Action::\"shell:spawn\", resource);\n"
            );
            let file = path.display();
            if let Err(error) = load(
                &source,
                std::slice::from_ref(&pack),
                std::slice::from_ref(&mcp),
            ) {
                failures.push(format!("{file}: {error}"));
                continue;
            }
            let schema =
                pack_action_schema(std::slice::from_ref(&pack), std::slice::from_ref(&mcp))
                    .expect("the schema composes");
            let tools: Vec<String> = schema
                .tool_actions
                .iter()
                .map(ToString::to_string)
                .collect();
            if tools != [r#"git::Action::"push""#] {
                failures.push(format!("{file}: the MCP tool actions are {tools:?}"));
            }
        }

        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    #[test]
    fn a_policy_loads_or_is_refused_against_the_packs_installed() {
        let git = || valid("git-push-commit-status");
        let cargo = || valid("cargo");
        let cases: Vec<(&str, Vec<Pack>, &str, Option<&str>)> = vec![
            (
                "a rule loads with its pack",
                vec![git()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   when { context.input.effects.contains(Tool::git::Effect::"force_push") };"#,
                None,
            ),
            (
                "a rule is refused without its pack",
                vec![],
                r#"forbid (principal, action == Tool::git::Action::"push", resource);"#,
                Some("unrecognized action"),
            ),
            (
                "a v1 rule is refused against a v2 pack",
                vec![at_version("git-push-commit-status", 2)],
                r#"forbid (principal, action == Tool::git::Action::"push", resource);"#,
                Some("unrecognized action"),
            ),
            (
                "a v2 rule loads against a v2 pack",
                vec![at_version("git-push-commit-status", 2)],
                r#"forbid (principal, action == Tool::git::v2::Action::"push", resource)
                   when { context.input.effects.contains(Tool::git::v2::Effect::"force_push") };"#,
                None,
            ),
            (
                "an effect rule over the group loads with two packs",
                vec![git(), cargo()],
                r#"permit (principal, action in Tool::git::Action::"*", resource);
                   forbid (principal, action in Tool::cargo::Action::"*", resource)
                   when { context.input.effects.contains(Tool::cargo::Effect::"update_lockfile") };"#,
                None,
            ),
            (
                "a rule over the group of a pack that is not installed is refused",
                vec![git()],
                r#"permit (principal, action in Tool::cargo::Action::"*", resource);"#,
                Some("unrecognized action"),
            ),
            (
                "an effect of another pack is refused",
                vec![git(), cargo()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   when { context.input.effects.contains(Tool::cargo::Effect::"update_lockfile") };"#,
                Some("are not compatible"),
            ),
            (
                "an effect the pack does not declare is refused",
                vec![git()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   when { context.input.effects.contains(Tool::git::Effect::"delete_data") };"#,
                Some("is not declared as a valid eid"),
            ),
            (
                "a field the action does not have is refused",
                vec![git()],
                r#"forbid (principal, action == Tool::git::Action::"status", resource)
                   when { context.input.force };"#,
                Some(
                    "attribute `input.force` in context for Tool::git::Action::\"status\" not found",
                ),
            ),
            (
                "an unmodeled command has the base fields only",
                vec![git()],
                r#"permit (principal, action == Tool::git::Action::"unmodeled", resource)
                   when { context.input.program == "git" && context.input.program_path == "/usr/bin/git"
                          && context.input.cwd == "/work" && context.input.args.contains("--version")
                          && context.input.effects.isEmpty() };"#,
                None,
            ),
            (
                "every action of a pack is in its group, and unmodeled is too",
                vec![git()],
                r#"permit (principal, action in Tool::git::Action::"*", resource)
                   when { action == Tool::git::Action::"unmodeled" };"#,
                None,
            ),
            (
                "a pack that declares no effect has no effects field",
                vec![valid("no-effects")],
                r#"forbid (principal, action == Tool::fmt::Action::"check", resource)
                   when { context.input.effects.contains(Tool::fmt::Effect::"delete_data") };"#,
                Some(
                    "attribute `input.effects` in context for Tool::fmt::Action::\"check\" not found",
                ),
            ),
            (
                "credential_reads is optional on a pack action",
                vec![git()],
                r#"forbid (principal, action in Tool::git::Action::"*", resource)
                   when { context.input has credential_reads
                          && context.input.credential_reads.contains("/home/a/.git-credentials") };"#,
                None,
            ),
            (
                "an unguarded read of credential_reads is refused",
                vec![git()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   when { context.input.credential_reads.isEmpty() };"#,
                Some(
                    "unable to guarantee safety of access to optional attribute `input.credential_reads`",
                ),
            ),
            (
                "a temporal rule reads the exit status of a pack action",
                vec![git(), cargo()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   unless temporal {
                       formerly within 10m Tool::cargo::Action::"test"::response{ output.status: 0 }
                   };"#,
                None,
            ),
            (
                "a temporal rule over a field of a pack action loads",
                vec![git()],
                r#"forbid (principal, action == Tool::git::Action::"push", resource)
                   when temporal {
                       formerly within 1h Tool::git::Action::"commit"::response{ input.no_verify: true }
                   };"#,
                None,
            ),
        ];
        let mut failures = Vec::new();
        for (name, packs, source, refused) in cases {
            match (load(source, &packs, &[]), refused) {
                (Ok(()), None) => {}
                (Err(error), Some(expected)) if error.contains(expected) => {}
                (Ok(()), Some(_)) => {
                    failures.push(format!("{name}: loads, but expected a refusal"))
                }
                (Err(error), _) => failures.push(format!("{name}: {error}")),
            }
        }

        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    #[test]
    fn two_packs_with_one_namespace_do_not_compose() {
        let packs = [valid("git"), valid("git-push-commit-status")];

        assert!(pack_action_schema(&packs, &[]).is_err());
    }

    #[test]
    fn version_one_has_no_suffix_and_a_later_version_names_itself() {
        assert_eq!(valid("git").namespace(), "Tool::git");
        assert_eq!(at_version("git", 2).namespace(), "Tool::git::v2");
        assert_eq!(at_version("git", 13).namespace(), "Tool::git::v13");
    }
}
