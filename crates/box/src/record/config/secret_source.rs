//! `box.toml`'s `[secret-source.<scheme>]` tables: the host program that reads a secret for a scheme.
//!
//! | Type | Is |
//! |---|---|
//! | [`SecretSourceEntry`] | one `[secret-source.<scheme>]` table, as the operator writes it |
//! | [`DeclaredSources`] | the checked declarations that each secret reference is judged against |

use std::collections::BTreeMap;
use std::path::Path;

use credentials::SecretSourceCommand;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// One `[secret-source.<scheme>]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct SecretSourceEntry {
    /// The version of the contract between Box and the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) protocol: Option<String>,

    /// The program, as an absolute path, then its arguments.
    #[serde(default)]
    pub(crate) command: Vec<String>,

    /// How the program's stdout becomes the secret: `text` or `json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) output: Option<String>,

    /// The operator's plain settings that the program receives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pass_env: Vec<String>,

    /// The operator's credentials that the program receives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pass_secret_env: Vec<String>,

    /// The paths that the program reads, which no workload may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reads: Vec<String>,

    /// The other paths to the vault, which no workload may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny: Vec<String>,
}

impl SecretSourceEntry {
    /// This table as the declaration that `credentials` checks.
    fn declaration(&self, scheme: &str) -> Result<SecretSourceCommand, ConfigError> {
        let refuse = |reason: String| ConfigError::SecretSource {
            scheme: scheme.to_string(),
            reason,
        };
        let refused = |source: credentials::CredentialError| refuse(source.to_string());
        SecretSourceCommand::check_scheme(scheme).map_err(refused)?;
        let Some(protocol) = &self.protocol else {
            return Err(refuse(format!(
                "`protocol` is absent; write `protocol = {:?}`",
                SecretSourceCommand::PROTOCOL
            )));
        };
        let mut declaration =
            SecretSourceCommand::new(scheme, protocol, &self.command).map_err(refused)?;
        if let Some(output) = &self.output {
            declaration = declaration.output(output).map_err(refused)?;
        }
        let declaration = declaration
            .pass_env(self.pass_env.iter().cloned())
            .and_then(|declaration| {
                declaration.pass_secret_env(self.pass_secret_env.iter().cloned())
            })
            .map_err(refused)?;
        for (list, entries) in [("reads", &self.reads), ("deny", &self.deny)] {
            if let Some(entry) = entries.iter().find(|entry| !protectable(entry)) {
                return Err(refuse(format!(
                    "`{list}` entry {entry:?} is not a path that Box can protect; write an \
                     absolute path, or one that begins with `~/`"
                )));
            }
        }
        Ok(declaration)
    }
}

/// Whether `entry` names one host path: an absolute path, the operator's home, or a path under it.
fn protectable(entry: &str) -> bool {
    entry == "~" || entry.starts_with("~/") || Path::new(entry).is_absolute()
}

/// The checked declarations of one configuration, keyed by scheme.
#[derive(Debug, Default)]
pub(crate) struct DeclaredSources {
    declarations: BTreeMap<String, SecretSourceCommand>,
    /// Whether `[experimental-features] secret-sources` is on.
    enabled: bool,
}

impl DeclaredSources {
    /// A configuration that declares no source.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// Check each `[secret-source.<scheme>]` table of a configuration whose
    /// `[experimental-features] secret-sources` is `enabled`.
    pub(crate) fn check(
        entries: &BTreeMap<String, SecretSourceEntry>,
        enabled: bool,
    ) -> Result<Self, ConfigError> {
        Self::check_on(entries, enabled, cfg!(target_os = "macos"))
    }

    /// [`check`](Self::check) on an operating system that is `protected` or not.
    fn check_on(
        entries: &BTreeMap<String, SecretSourceEntry>,
        enabled: bool,
        protected: bool,
    ) -> Result<Self, ConfigError> {
        let mut declarations = BTreeMap::new();
        for (scheme, entry) in entries {
            let refuse = |reason: &str| ConfigError::SecretSource {
                scheme: scheme.clone(),
                reason: reason.to_string(),
            };
            if !protected {
                return Err(refuse(
                    "a secret source loads on macOS only: protection of its program and its \
                     files from the workload is not built for Linux yet",
                ));
            }
            if !enabled {
                return Err(refuse(
                    "a secret source is experimental: set `secret-sources = true` in \
                     `[experimental-features]` to load it",
                ));
            }
            declarations.insert(scheme.clone(), entry.declaration(scheme)?);
        }
        Ok(Self {
            declarations,
            enabled,
        })
    }

    /// Whether `[experimental-features] secret-sources` is on.
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a `[secret-source.<scheme>]` table declares `scheme`.
    pub(crate) fn declares(&self, scheme: &str) -> bool {
        self.declarations.contains_key(scheme)
    }

    /// Each checked declaration with its scheme, for the backend that reads through it.
    pub(crate) fn into_declarations(self) -> impl Iterator<Item = (String, SecretSourceCommand)> {
        self.declarations.into_iter()
    }

    /// The scheme of a source whose `pass-secret-env` names the variable `name`.
    pub(crate) fn credential_owner(&self, name: &str) -> Option<&str> {
        self.declarations
            .iter()
            .find(|(_, declaration)| declaration.passes_as_secret(name))
            .map(|(scheme, _)| scheme.as_str())
    }

    /// The checked declarations of `entries` on a protected operating system, with the feature on.
    #[cfg(test)]
    pub(crate) fn for_tests(entries: &BTreeMap<String, SecretSourceEntry>) -> Self {
        Self::check_on(entries, true, true).expect("the test declarations are valid")
    }
}

/// Whether a secret reference names a scheme that a `[secret-source.<scheme>]` table can declare.
pub(crate) fn declarable(scheme: &str) -> bool {
    SecretSourceCommand::check_scheme(scheme).is_ok()
}

/// The refusal of a variable that is the credential of a declared source's own vault.
pub(crate) fn vault_credential_refusal(name: &str, scheme: &str) -> String {
    format!(
        "the variable {name} is a credential of the secret source `{scheme}` (its \
         `pass-secret-env` names it), so no env:// or secret:// reference can read it"
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The `op` and `aws-secretsmanager` declarations of the design, with stand-in programs.
    pub(crate) const DECLARED: &str = r#"
        [secret-source.op]
        protocol = "box.secret-source.v1"
        command = ["/opt/homebrew/bin/op", "read", "op://{ref}"]
        pass-env = ["OP_ACCOUNT"]
        pass-secret-env = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_*"]
        reads = ["~/.config/op"]
        deny = ["/var/run/op"]

        [secret-source.aws-secretsmanager]
        protocol = "box.secret-source.v1"
        command = ["/usr/local/bin/aws", "secretsmanager", "get-secret-value", "--secret-id", "{ref}"]
        output = "json"
        pass-secret-env = ["AWS_SECRET_ACCESS_KEY"]
    "#;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        #[serde(default, rename = "secret-source")]
        secret_source: BTreeMap<String, SecretSourceEntry>,
    }

    /// The `[secret-source.<scheme>]` tables of `text`.
    pub(crate) fn entries(text: &str) -> BTreeMap<String, SecretSourceEntry> {
        toml::from_str::<Fixture>(text)
            .expect("the test declarations parse")
            .secret_source
    }

    /// The checked declarations of [`DECLARED`].
    pub(crate) fn declared() -> DeclaredSources {
        DeclaredSources::for_tests(&entries(DECLARED))
    }

    /// A configuration with the feature on that declares no source.
    pub(crate) fn switched_on() -> DeclaredSources {
        DeclaredSources::for_tests(&BTreeMap::new())
    }

    /// One `[secret-source.op]` table with `body` in place of the valid keys.
    fn refusal(body: &str) -> String {
        let entries = entries(&format!("[secret-source.op]\n{body}"));
        DeclaredSources::check_on(&entries, true, true)
            .expect_err("the declaration is refused")
            .to_string()
    }

    const PROTOCOL: &str = "protocol = \"box.secret-source.v1\"\n";
    const COMMAND: &str = "command = [\"/opt/op\", \"read\", \"op://{ref}\"]\n";

    #[test]
    fn a_valid_declaration_is_checked_and_answers_for_its_scheme() {
        let sources = declared();
        assert_eq!(
            ["op", "aws-secretsmanager", "aws", "vault"].map(|scheme| sources.declares(scheme)),
            [true, true, false, false]
        );
        assert!(sources.enabled());
        assert!(!DeclaredSources::none().declares("op"));
        assert!(!DeclaredSources::none().enabled());
        assert!(switched_on().enabled());
        assert!(
            !DeclaredSources::check_on(&BTreeMap::new(), false, true)
                .expect("no table needs no switch")
                .enabled()
        );
    }

    #[test]
    fn a_declaration_without_the_feature_is_refused() {
        let error = DeclaredSources::check_on(&entries(DECLARED), false, true)
            .expect_err("the feature is off");
        assert_eq!(
            error.to_string(),
            "invalid `[secret-source.aws-secretsmanager]` table: a secret source is experimental: \
             set `secret-sources = true` in `[experimental-features]` to load it"
        );
        DeclaredSources::check_on(&BTreeMap::new(), false, true)
            .expect("a configuration with no declaration needs no feature");
    }

    #[test]
    fn a_declaration_on_an_unprotected_operating_system_is_refused() {
        for enabled in [false, true] {
            let error = DeclaredSources::check_on(&entries(DECLARED), enabled, false)
                .expect_err("the operating system has no protection");
            assert_eq!(
                error.to_string(),
                "invalid `[secret-source.aws-secretsmanager]` table: a secret source loads on \
                 macOS only: protection of its program and its files from the workload is not \
                 built for Linux yet"
            );
        }
        DeclaredSources::check_on(&BTreeMap::new(), false, false)
            .expect("a configuration with no declaration loads on each operating system");
    }

    #[test]
    fn the_operating_system_check_follows_the_build_target() {
        let checked = DeclaredSources::check(&entries(DECLARED), true);
        assert_eq!(checked.is_ok(), cfg!(target_os = "macos"));
    }

    #[test]
    fn a_reserved_or_malformed_scheme_is_refused() {
        for (scheme, reason) in [
            (
                "env",
                "a secret source cannot claim the scheme \"env\", which the box reserves \
                 (reserved: env, file, aws, credsd, secret, cmd, oauth2, aws-signed, strip-phantom)",
            ),
            (
                "aws",
                "a secret source cannot claim the scheme \"aws\", which the box reserves \
                 (reserved: env, file, aws, credsd, secret, cmd, oauth2, aws-signed, strip-phantom)",
            ),
            (
                "strip-phantom",
                "a secret source cannot claim the scheme \"strip-phantom\", which the box \
                 reserves (reserved: env, file, aws, credsd, secret, cmd, oauth2, aws-signed, \
                 strip-phantom)",
            ),
            (
                "One_Password",
                "a secret source cannot claim the scheme \"One_Password\": a scheme is a \
                 lowercase letter, then lowercase letters, digits, `+`, `.`, or `-`",
            ),
        ] {
            // No `protocol`, so the scheme check is the first one.
            let entries = entries(&format!("[secret-source.{scheme}]\n{COMMAND}"));
            assert_eq!(
                DeclaredSources::check_on(&entries, true, true)
                    .expect_err("the scheme is refused")
                    .to_string(),
                format!("invalid `[secret-source.{scheme}]` table: credential error: {reason}")
            );
        }
    }

    #[test]
    fn a_declaration_without_a_protocol_is_refused() {
        assert_eq!(
            refusal(COMMAND),
            "invalid `[secret-source.op]` table: `protocol` is absent; write `protocol = \
             \"box.secret-source.v1\"`"
        );
    }

    #[test]
    fn each_refusal_of_the_declaration_constructor_reaches_the_operator() {
        for (body, reason) in [
            (
                format!("protocol = \"box.secret-source.v2\"\n{COMMAND}"),
                "names the protocol \"box.secret-source.v2\", and this box supports only \
                 \"box.secret-source.v1\"",
            ),
            (PROTOCOL.to_string(), "has an empty command"),
            (format!("{PROTOCOL}command = []\n"), "has an empty command"),
            (
                format!("{PROTOCOL}command = [\"op\", \"read\", \"op://{{ref}}\"]\n"),
                "names the program \"op\", which is not an absolute path",
            ),
            (
                format!("{PROTOCOL}command = [\"/opt/op\", \"read\", \"{{REF}}\"]\n"),
                "has no `{ref}` in its arguments, so each reference would read one secret",
            ),
            (
                format!("{PROTOCOL}{COMMAND}output = \"yaml\"\n"),
                "names the output \"yaml\", and an output is `text` or `json`",
            ),
            (
                format!("{PROTOCOL}{COMMAND}pass-env = [\"PATH\"]\n"),
                "has the entry \"PATH\" in `pass-env`, which has no effect, because each program \
                 gets a fixed `PATH`",
            ),
            (
                format!("{PROTOCOL}{COMMAND}pass-secret-env = [\"HOME\"]\n"),
                "has the entry \"HOME\" in `pass-secret-env`, which has no effect, because each \
                 program gets the operator's `HOME`",
            ),
            (
                format!("{PROTOCOL}{COMMAND}pass-secret-env = [\"AWS_*_KEY\"]\n"),
                "has the entry \"AWS_*_KEY\" in `pass-secret-env`, which holds `*` before its \
                 end, and only a last `*` makes a prefix",
            ),
        ] {
            assert_eq!(
                refusal(&body),
                format!(
                    "invalid `[secret-source.op]` table: credential error: the secret source \
                     \"op\" {reason}"
                )
            );
        }
    }

    #[test]
    fn a_reads_or_deny_entry_that_is_not_a_host_path_is_refused() {
        for (list, entry) in [
            ("reads", ".config/op"),
            ("deny", ""),
            ("deny", "~op/socket"),
        ] {
            assert_eq!(
                refusal(&format!("{PROTOCOL}{COMMAND}{list} = [{entry:?}]\n")),
                format!(
                    "invalid `[secret-source.op]` table: `{list}` entry {entry:?} is not a path \
                     that Box can protect; write an absolute path, or one that begins with `~/`"
                )
            );
        }
        let entries = entries(&format!(
            "[secret-source.op]\n{PROTOCOL}{COMMAND}reads = [\"~\", \"~/.config/op\", \"/etc/op\"]\n"
        ));
        DeclaredSources::check_on(&entries, true, true).expect("each spelling names one host path");
    }

    #[test]
    fn an_unknown_key_is_a_parse_error() {
        let error = toml::from_str::<Fixture>(&format!(
            "[secret-source.op]\n{PROTOCOL}{COMMAND}timeout = 5\n"
        ))
        .expect_err("the table takes seven keys");
        assert!(
            error.message().starts_with(
                "unknown field `timeout`, expected one of `protocol`, `command`, `output`, \
                 `pass-env`, `pass-secret-env`, `reads`, `deny`"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_pass_secret_env_entry_names_the_credential_of_its_source() {
        let sources = declared();
        assert_eq!(
            [
                "OP_SERVICE_ACCOUNT_TOKEN",
                "OP_SESSION_",
                "OP_SESSION_abc",
                "OP_SESSION",
                "OP_ACCOUNT",
                "AWS_SECRET_ACCESS_KEY",
                "GH_TOKEN",
            ]
            .map(|name| sources.credential_owner(name)),
            [
                Some("op"),
                Some("op"),
                Some("op"),
                None,
                None,
                Some("aws-secretsmanager"),
                None,
            ]
        );
        assert_eq!(
            vault_credential_refusal("OP_SESSION_abc", "op"),
            "the variable OP_SESSION_abc is a credential of the secret source `op` (its \
             `pass-secret-env` names it), so no env:// or secret:// reference can read it"
        );
    }

    #[test]
    fn a_scheme_is_declarable_unless_it_is_reserved_or_malformed() {
        assert_eq!(
            [
                "op",
                "vault",
                "aws-secretsmanager",
                "env",
                "file",
                "cmd",
                "strip-phantom",
                "Op",
                ""
            ]
            .map(declarable),
            [true, true, true, false, false, false, false, false, false]
        );
    }

    #[test]
    fn a_stored_declaration_keeps_each_key_and_omits_each_absent_one() {
        let entries = entries(DECLARED);
        let stored = toml::to_string(&entries["op"]).expect("the table serializes");
        assert_eq!(
            stored,
            "protocol = \"box.secret-source.v1\"\n\
             command = [\"/opt/homebrew/bin/op\", \"read\", \"op://{ref}\"]\n\
             pass-env = [\"OP_ACCOUNT\"]\n\
             pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_SESSION_*\"]\n\
             reads = [\"~/.config/op\"]\n\
             deny = [\"/var/run/op\"]\n"
        );
        assert_eq!(
            toml::from_str::<SecretSourceEntry>(&stored).expect("the stored table parses"),
            entries["op"]
        );
    }
}
