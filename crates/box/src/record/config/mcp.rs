//! `box.toml`'s `[mcp.<name>]` tables: which local MCP servers exist, and how each one starts.
//!
//! An entry declares identity and authorizes nothing. It holds only what is the operator's: a name,
//! a program, and its arguments.
//!
//! It lives in the selected configuration, whose loaded filesystem identity cannot be mutated
//! through either interpreter. That matters more here than for any other key, because the trusted
//! `run` process starts the program an entry names outside containment.
//!
//! Two namespaces answer different questions. `name` is the policy identity a rule reads as
//! `context.input.server`. `program` is what the harness executes, so the alias in `bin/` carries
//! it. A client can execute `uvx` while the policy identifies the server as `aws-mcp`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{BoxError, ConfigError};
use crate::record::config::egress::EgressSecret;
use crate::record::config::process::{ContainedMcp, Filesystem, NetworkConfig, ProcessSpec};

/// One `[mcp.<name>]` entry, as the operator writes it. The `type` field selects the transport:
/// a `stdio` server is a child process started behind the broker; an `http` server is a remote
/// endpoint reached — and gated — through the egress gateway.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum McpEntry {
    /// A local MCP server. Element 0 of `command` is the program and names the alias in `bin/`;
    /// the rest are its arguments, fixed here so the agent cannot choose them.
    ///
    /// Every stdio server is contained — that is not optional. The grant fields below are the
    /// server's reach; an entry that declares none runs on the leaf baseline alone (its command's
    /// own load closure plus the OS paths). Only the network posture is a knob: `[mcp.<name>.network]`
    /// `contain_egress = false` lets a client that cannot honor `HTTPS_PROXY` egress directly.
    Stdio {
        /// What to start.
        command: Vec<String>,
        /// The initial working directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        workspace: Option<PathBuf>,
        /// Literal variables, applied beneath every name Core owns.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        /// What the server's own syscalls reach, from `[mcp.<name>.filesystem]`.
        #[serde(default, skip_serializing_if = "Filesystem::is_empty")]
        filesystem: Filesystem,
        /// How the server reaches the network, from `[mcp.<name>.network]`.
        #[serde(default, skip_serializing_if = "NetworkConfig::is_default")]
        network: NetworkConfig,
    },
    /// A remote MCP server reached over HTTP. `destinations` are its egress hosts; `secret` is the
    /// optional credential the gateway attaches.
    Http {
        /// The egress destinations that name this server's host(s).
        destinations: Vec<String>,
        /// The credential to attach, if the entry names one.
        #[serde(default)]
        secret: Option<EgressSecret>,
    },
}

/// A remote (HTTP) MCP entry the operator declared under `[mcp.<name>] type = "http"`, carried until
/// the caller fans it out into the egress structures (the runtime still sees remote MCP as an
/// egress entry).
pub(crate) struct HttpMcp {
    /// The entry key: the server name a rule reads as `context.input.server`.
    pub(crate) name: String,
    /// The egress destinations that name this server's host(s).
    pub(crate) destinations: Vec<String>,
    /// The credential to attach, if the entry names one.
    pub(crate) secret: Option<EgressSecret>,
}

/// One declared server, with the name the operator keyed it under folded in. Identity only: a
/// server's containment, if any, is carried beside this in `Record::contained_mcp` so this type
/// stays what a rule matches — a name and a program — and every consumer of it is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpServer {
    /// What this server is called: the name a rule reads as `context.input.server`.
    pub(crate) name: String,

    /// What to start. Element 0 names the alias in `bin/`.
    pub(crate) command: Vec<String>,
}

impl McpServer {
    /// The program to start, which is the name its alias takes in `bin/`.
    pub(crate) fn program(&self) -> &str {
        self.command.first().map_or("", String::as_str)
    }

    /// Its arguments, fixed by the operator's file.
    pub(crate) fn arguments(&self) -> &[String] {
        self.command.get(1..).unwrap_or_default()
    }
}

/// Every local (stdio) MCP server an operator authored, as `(name, ContainedMcp)` pairs. Each spec
/// is the server's `command` combined with its `[mcp.<name>]` grants; containment is not optional,
/// so every stdio entry produces one. A remote (http) entry produces no pair. The command is the
/// one source of truth, carried once on the entry.
pub(crate) fn contained_specs(
    entries: &BTreeMap<String, McpEntry>,
) -> BTreeMap<String, ContainedMcp> {
    entries
        .iter()
        .filter_map(|(name, entry)| match entry {
            McpEntry::Stdio {
                command,
                workspace,
                env,
                filesystem,
                network,
            } => Some((
                name.clone(),
                ContainedMcp {
                    spec: ProcessSpec {
                        command: command.clone(),
                        workspace: workspace.clone(),
                        env: env.clone(),
                        filesystem: filesystem.clone(),
                        network: (!network.is_default()).then(|| network.clone()),
                    },
                },
            )),
            McpEntry::Http { .. } => None,
        })
        .collect()
}

/// Split the authored `[mcp.<name>]` entries by transport: the local (stdio) servers, validated as
/// records; and the remote (http) specs, which the caller fans out into the egress structures.
pub(crate) fn partition(
    entries: &BTreeMap<String, McpEntry>,
) -> Result<(Vec<McpServer>, Vec<HttpMcp>), BoxError> {
    let mut stdio = Vec::new();
    let mut http = Vec::new();
    for (name, entry) in entries {
        match entry {
            McpEntry::Stdio { command, .. } => stdio.push(McpServer {
                name: name.clone(),
                command: command.clone(),
            }),
            McpEntry::Http {
                destinations,
                secret,
            } => http.push(HttpMcp {
                name: name.clone(),
                destinations: destinations.clone(),
                secret: secret.clone(),
            }),
        }
    }
    validate_authored(&stdio)?;
    Ok((stdio, http))
}

/// The local (stdio) MCP servers an operator authored, as records, refusing what no run could honor.
pub(crate) fn from_entries(
    entries: &BTreeMap<String, McpEntry>,
) -> Result<Vec<McpServer>, BoxError> {
    Ok(partition(entries)?.0)
}

/// The server an alias selects, keyed by the program the alias is named for.
pub(crate) fn for_alias<'a>(servers: &'a [McpServer], program: &str) -> Option<&'a McpServer> {
    servers.iter().find(|server| server.program() == program)
}

/// Refuse a declared server set no run could honor.
pub(crate) fn validate_authored(servers: &[McpServer]) -> Result<(), ConfigError> {
    // Two namespaces, two sets. One shared set would let a `name` collide with an unrelated
    // `program`.
    let mut names = BTreeSet::new();
    let mut programs = BTreeSet::new();
    for server in servers {
        let refuse = |reason: String| {
            Err(ConfigError::Mcp {
                name: server.name.clone(),
                reason,
            })
        };
        if let Some(reason) = unrepresentable(server) {
            return refuse(reason);
        }
        if !names.insert(server.name.as_str()) {
            return refuse(SHARED_NAME.to_string());
        }
        if !programs.insert(server.program()) {
            return refuse(SHARED_PROGRAM.to_string());
        }
    }
    Ok(())
}

/// Why two entries may not share one `name`.
const SHARED_NAME: &str = "two entries share this `name`; one name is one identity, and a rule \
                           naming it would reach both";

/// Why two entries may not share one `program`.
const SHARED_PROGRAM: &str = "two entries share this `program`; the alias is named for the program, \
                              so both would want one path in `bin/` and only one could be placed";

/// Why the box cannot represent `server` on its own terms, or `None` when it can.
fn unrepresentable(server: &McpServer) -> Option<String> {
    let reason = |text: &str| Some(text.to_string());
    if server.name.is_empty() {
        return reason("`name` is empty");
    }
    if server.command.is_empty() || server.program().is_empty() {
        return reason("`program` is empty, so nothing would start");
    }
    // `name` is an attribute a rule matches, so it takes the box-name character set.
    if let Some(character) = server
        .name
        .chars()
        .find(|character| !crate::record::config::nameable(*character))
    {
        return Some(format!(
            "`name` contains {character:?}; a server name is an attribute a rule matches, so it \
             may hold only letters, digits, '.', '_', and '-'"
        ));
    }
    // `program` becomes a filename in `bin/`, so the filename rules follow it rather than `name`.
    if let Some(character) = server
        .program()
        .chars()
        .find(|character| !crate::record::config::nameable(*character))
    {
        return Some(format!(
            "`program` contains {character:?}; it becomes a filename on the agent's PATH, so it \
             may hold only letters, digits, '.', '_', and '-'"
        ));
    }
    // `.` and `..` pass the character set and are not filenames. Each already exists in `bin/`, so
    // the failure used to arrive later as "link the Shell alias: File exists".
    if server.program() == "." || server.program() == ".." {
        return reason(
            "`program` is `.` or `..`, which names a directory rather than a program; the alias \
             for it could not be placed",
        );
    }
    // The alias image picks the interpreter from `argv[0]`, so a program called `zsh` gets
    // `bin/zsh` routed to the Shell.
    if crate::run::broker::protocol::SHELL_ALIAS_NAMES.contains(&server.program())
        || crate::run::broker::protocol::PYTHON_ALIAS_NAMES.contains(&server.program())
    {
        return reason(
            "`program` is one of the box's own interpreter aliases; the alias image selects the \
             interpreter from its own name, so this server would be routed to the shell or the \
             Python runtime and could never be reached",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `[[server]]` entries the way `box.toml`'s `[[mcp]]` array reaches `authored`.
    fn parse(text: &str) -> Result<Vec<McpServer>, BoxError> {
        #[derive(serde::Deserialize)]
        struct Fixture {
            #[serde(default, rename = "server")]
            servers: Vec<McpServer>,
        }
        let fixture: Fixture = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: std::path::PathBuf::from("box.toml"),
            source,
        })?;
        validate_authored(&fixture.servers)?;
        Ok(fixture.servers)
    }

    #[test]
    fn a_local_server_declares_a_name_a_program_and_its_argv() {
        let file = parse(
            r#"
            [[server]]
            name = "issues-mcp"
            command = ["issues-mcp"]

            [[server]]
            name = "aws-mcp"
            command = ["uvx", "mcp-proxy-for-aws@latest", "https://aws-mcp.us-east-1.api.aws/mcp"]
            "#,
        )
        .expect("valid");

        assert_eq!(file.len(), 2);
        let aws = for_alias(&file, "uvx")
            .expect("the second server, reached by the program its harness executes");
        assert_eq!(aws.name, "aws-mcp", "the policy identity is still the name");
        assert_eq!(aws.arguments().len(), 2, "the argv is fixed by the file");
        assert!(
            for_alias(&file, "not-declared").is_none(),
            "a program the file does not declare selects nothing"
        );
    }

    /// The lookup key is `program`, and the server's `name` selects nothing.
    #[test]
    fn a_server_is_reached_by_its_program_and_not_by_its_name() {
        let file = parse(
            r#"
            [[server]]
            name = "aws-mcp"
            command = ["uvx"]
            "#,
        )
        .expect("valid");

        assert!(
            for_alias(&file, "uvx").is_some(),
            "the alias is named for the program, so the program must select the server"
        );
        assert!(
            for_alias(&file, "aws-mcp").is_none(),
            "the server's name places no alias, so it must select nothing"
        );
    }

    /// Two entries sharing one `program` want one alias path, so the file is refused.
    #[test]
    fn two_servers_sharing_one_program_are_refused() {
        let refusal = parse(
            r#"
            [[server]]
            name = "aws-mcp"
            command = ["uvx"]

            [[server]]
            name = "other-mcp"
            command = ["uvx"]
            "#,
        )
        .expect_err("two entries cannot share one alias path");
        let text = refusal.to_string();
        assert!(
            text.contains("program"),
            "the refusal must name the colliding key, got: {text}"
        );
    }

    /// An absent `[[mcp]]` array is a box with no MCP servers, not an error.
    #[test]
    fn an_absent_array_is_no_servers() {
        let file = parse("").expect("a box.toml with no [[mcp]] entries");
        assert!(
            file.is_empty(),
            "a box with no MCP servers is the ordinary case, not a refusal"
        );
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let error = parse(
            r#"
            [[server]]
            name = "issues-mcp"
            command = ["one"]

            [[server]]
            name = "issues-mcp"
            command = ["two"]
            "#,
        )
        .expect_err("two entries may not share a name");
        assert!(error.to_string().contains("share this `name`"), "{error}");
    }

    /// A name that cannot be an attribute is refused rather than sanitized, because `a/b` and `a_b`
    /// becoming one name means a rule written for either reaches both.
    #[test]
    fn a_name_outside_the_character_set_is_refused() {
        for name in ["has space", "a/b", "tab\t", "sémantic"] {
            let error =
                parse(&format!("[[server]]\nname = {name:?}\ncommand = [\"x\"]")).unwrap_err();
            assert!(
                error.to_string().contains("may hold only"),
                "{name:?} must be refused: {error}"
            );
        }
    }

    /// A program the alias image would route to an interpreter is refused.
    #[test]
    fn a_program_that_collides_with_an_interpreter_alias_is_refused() {
        for taken in ["zsh", "bash", "sh", "python3", "python"] {
            let error = parse(&format!(
                "[[server]]\nname = \"issues-mcp\"\ncommand = [{taken:?}]"
            ))
            .expect_err("an interpreter alias name must be refused");
            assert!(
                error.to_string().contains("interpreter aliases"),
                "{taken:?} must be refused for colliding with an alias: {error}"
            );
        }

        // A `name` is free to be any of them, because a name places no alias. Asserted so the check
        // is known to have moved rather than to have been copied to both fields.
        for free in ["zsh", "bash", "sh", "python3", "python"] {
            parse(&format!(
                "[[server]]\nname = {free:?}\ncommand = [\"issues-mcp\"]"
            ))
            .unwrap_or_else(|error| {
                panic!("a server NAMED {free:?} places no alias, so it must load: {error}")
            });
        }
    }

    /// `.` and `..` pass the character set and name a directory rather than a program.
    #[test]
    fn a_relative_directory_program_is_refused() {
        for program in [".", ".."] {
            let error = parse(&format!(
                "[[server]]\nname = \"x\"\ncommand = [{program:?}]"
            ))
            .expect_err("a directory name is not a program");
            assert!(
                error.to_string().contains("names a directory"),
                "{program:?} must be refused for what it is: {error}"
            );
        }
    }

    /// An entry naming no program would start nothing.
    #[test]
    fn an_empty_program_is_refused() {
        let error = parse("[[server]]\nname = \"x\"\ncommand = [\"\"]").unwrap_err();
        assert!(error.to_string().contains("`program` is empty"), "{error}");
    }

    /// An unknown key is a hard error, like every other config this box reads.
    #[test]
    fn an_unknown_key_is_refused() {
        assert!(
            parse("[[server]]\nname = \"x\"\ncommand = [\"y\"]\ndestination = \"z\"").is_err(),
            "a remote server's `destination` is not a key this build reads"
        );
    }

    /// Parse one `[mcp.<name>]` table into an entry, the way `box.toml` reaches it.
    fn entry(text: &str) -> Result<McpEntry, toml::de::Error> {
        #[derive(serde::Deserialize)]
        struct Fixture {
            mcp: BTreeMap<String, McpEntry>,
        }
        Ok(toml::from_str::<Fixture>(text)?
            .mcp
            .into_values()
            .next()
            .expect("one entry"))
    }

    /// A `type = "stdio"` entry carries a command.
    #[test]
    fn a_stdio_entry_carries_a_command() {
        let parsed = entry("[mcp.builder]\ntype = \"stdio\"\ncommand = [\"issues-mcp\"]")
            .expect("a stdio entry parses");
        assert_eq!(
            parsed,
            McpEntry::Stdio {
                command: vec!["issues-mcp".to_string()],
                workspace: None,
                env: BTreeMap::new(),
                filesystem: Filesystem::default(),
                network: NetworkConfig::default(),
            }
        );
    }

    /// A `type = "http"` entry carries destinations and an optional secret.
    #[test]
    fn an_http_entry_carries_destinations_and_a_secret() {
        let parsed = entry(
            "[mcp.github]\ntype = \"http\"\ndestinations = [\"api.githubcopilot.com\"]\n\
             secret.ref = \"env://GITHUB_MCP_TOKEN\"",
        )
        .expect("an http entry parses");
        match parsed {
            McpEntry::Http {
                destinations,
                secret,
            } => {
                assert_eq!(destinations, ["api.githubcopilot.com"]);
                assert!(secret.is_some(), "the named credential is carried");
            }
            other => panic!("expected an http entry, got {other:?}"),
        }
    }

    /// The transport tag is mandatory: an entry with no `type` cannot be resolved to either variant.
    #[test]
    fn a_missing_type_is_refused() {
        assert!(
            entry("[mcp.builder]\ncommand = [\"issues-mcp\"]").is_err(),
            "`type` selects the transport and has no default, so it must be required"
        );
    }

    /// A field belonging to the other transport is refused, so a stdio entry cannot smuggle
    /// destinations and an http entry cannot smuggle a command.
    #[test]
    fn a_field_for_the_wrong_transport_is_refused() {
        assert!(
            entry("[mcp.a]\ntype = \"stdio\"\ndestinations = [\"api.test\"]").is_err(),
            "a stdio entry has no `destinations`"
        );
        assert!(
            entry("[mcp.a]\ntype = \"http\"\ncommand = [\"x\"]").is_err(),
            "an http entry has no `command`"
        );
    }

    /// Parse a set of `[mcp.<name>]` tables the way `box.toml` reaches them.
    fn entries(text: &str) -> BTreeMap<String, McpEntry> {
        #[derive(serde::Deserialize)]
        struct Fixture {
            mcp: BTreeMap<String, McpEntry>,
        }
        toml::from_str::<Fixture>(text)
            .expect("the tables parse")
            .mcp
    }

    /// A stdio entry's grants live directly under `[mcp.<name>]`, and its synthesized `ProcessSpec`
    /// carries the entry's command plus those grants.
    #[test]
    fn a_stdio_entry_synthesizes_a_process_spec_from_its_command_and_grants() {
        let map = entries(
            "[mcp.builder]\ntype = \"stdio\"\ncommand = [\"issues-mcp\", \"--stdio\"]\n\
             [mcp.builder.filesystem]\nread = [\"~/.local/share/issues-mcp\"]\n\
             write = [\"~/.issues-mcp\"]",
        );
        let specs = contained_specs(&map);
        let entry = specs.get("builder").expect("every stdio server has a spec");
        assert!(
            !entry.spec.native_egress(),
            "default (no [network]) is gateway-routed egress"
        );
        assert_eq!(entry.spec.network, None);
        let spec = &entry.spec;
        assert_eq!(
            spec.command,
            ["issues-mcp", "--stdio"],
            "the command is carried from the entry, not restated among the grants"
        );
        assert_eq!(
            spec.filesystem.read,
            [std::path::PathBuf::from("~/.local/share/issues-mcp")]
        );
        assert_eq!(
            spec.filesystem.write,
            [std::path::PathBuf::from("~/.issues-mcp")]
        );
    }

    /// `[mcp.<name>.network] contain_egress = false` marks the server native-egress
    /// (Network::AllowAll); omitting the table, or `true`, keeps it gateway-routed.
    #[test]
    fn contain_egress_false_marks_native_egress() {
        let native = entries(
            "[mcp.builder]\ntype = \"stdio\"\ncommand = [\"issues-mcp\"]\n\
             [mcp.builder.network]\ncontain_egress = false",
        );
        let native = &contained_specs(&native)["builder"];
        assert!(native.spec.native_egress());
        assert_eq!(
            crate::run::contain::boundary::EgressMode::for_spec(&native.spec),
            crate::run::contain::boundary::EgressMode::Native,
            "an MCP spec selects its egress through the same function a tool's does"
        );

        let gateway = entries(
            "[mcp.builder]\ntype = \"stdio\"\ncommand = [\"issues-mcp\"]\n\
             [mcp.builder.network]\ncontain_egress = true",
        );
        let gateway = &contained_specs(&gateway)["builder"];
        assert!(!gateway.spec.native_egress());
        assert_eq!(
            crate::run::contain::boundary::EgressMode::for_spec(&gateway.spec),
            crate::run::contain::boundary::EgressMode::Gateway
        );
    }

    /// Containment is not optional: a stdio entry that declares no grants is still contained. It
    /// produces a spec carrying only its command, and runs on the leaf baseline alone.
    #[test]
    fn a_grantless_stdio_entry_is_still_contained() {
        let map = entries("[mcp.fetch]\ntype = \"stdio\"\ncommand = [\"mcp-server-fetch\"]");
        let specs = contained_specs(&map);
        let entry = specs
            .get("fetch")
            .expect("every stdio server is contained, even with no grants");
        assert!(
            !entry.spec.native_egress(),
            "the default posture is gateway-routed egress"
        );
        let spec = &entry.spec;
        assert_eq!(spec.command, ["mcp-server-fetch"]);
        assert!(
            spec.filesystem.entries().next().is_none(),
            "no extra grants"
        );
    }

    /// Only remote (http) servers produce no contained spec; every stdio server does.
    #[test]
    fn an_http_entry_produces_no_contained_spec() {
        let map =
            entries("[mcp.github]\ntype = \"http\"\ndestinations = [\"api.githubcopilot.com\"]");
        assert!(
            contained_specs(&map).is_empty(),
            "a remote server has no leaf to contain"
        );
    }

    /// A stdio entry carrying a key no build reads is a load error, like every other config.
    #[test]
    fn an_unknown_stdio_field_is_refused() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            #[allow(dead_code)]
            mcp: BTreeMap<String, McpEntry>,
        }
        assert!(
            toml::from_str::<Fixture>(
                "[mcp.a]\ntype = \"stdio\"\ncommand = [\"x\"]\ncontain = true"
            )
            .is_err(),
            "the migration-era `contain = true` bool is not a key this build reads"
        );
        assert!(
            toml::from_str::<Fixture>(
                "[mcp.a]\ntype = \"stdio\"\ncommand = [\"x\"]\n[mcp.a.filesystem]\nreadonly = [\"/a\"]"
            )
            .is_err(),
            "a typo in the filesystem table must fail loudly"
        );
        assert!(
            toml::from_str::<Fixture>(
                "[mcp.a]\ntype = \"stdio\"\ncommand = [\"x\"]\n[mcp.a.contain]\nworkspace = \"/x\""
            )
            .is_err(),
            "the old `[mcp.<name>.contain]` wrapper is gone; grants live directly on the entry"
        );
    }

    /// An `[mcp.<name>.filesystem]` refuses `metadata` and `exec`, as a tool table does.
    #[test]
    fn mcp_filesystem_refuses_metadata_and_exec_like_a_tool() {
        let path = std::path::Path::new("box.toml");
        let head = "name = \"codex\"\nbox_dir = \"/var/lib/boxes/codex\"\n";
        for (table, list) in [
            ("[mcp.builder]\ntype = \"stdio\"\ncommand", "mcp.builder"),
            ("[tool.builder]\ncommand", "tool.builder"),
        ] {
            for key in ["metadata", "exec"] {
                let document = format!(
                    "{head}{table} = [\"issues-mcp\"]\n[{list}.filesystem]\n{key} = [\"/usr/bin\"]\n"
                );
                let error = super::super::ConfigFile::parse(&document, path)
                    .expect_err("the removed list is refused");
                assert!(
                    matches!(error, ConfigError::RemovedKey { .. }),
                    "{list} refuses `{key}`: {error}"
                );
            }
        }
    }
}
