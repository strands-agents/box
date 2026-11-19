//! `box.toml`'s `[secret-source.<scheme>]` tables: the host program that reads a secret for a scheme.
//!
//! | Type | Is |
//! |---|---|
//! | [`SecretSourceEntry`] | one `[secret-source.<scheme>]` table, as the operator writes it |
//! | [`DeclaredSources`] | the checked declarations that each secret reference is judged against |
//! | [`routed_scheme`] | the one place that finds the scheme of a secret reference, as `credentials` routes it |
//! | [`ProtectedPath`] | one `reads` or `deny` entry, which no grant may reach |

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use credentials::{CredentialError, Locator, SecretSourceCommand};
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

    /// The paths that the program reads, which no grant may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reads: Vec<String>,

    /// The other paths to the vault, which no grant may reach.
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
            for entry in entries {
                if let Some(advice) = unprotectable(entry) {
                    return Err(refuse(format!(
                        "`{list}` entry {entry:?} is not a path that Box can protect; {advice}"
                    )));
                }
            }
        }
        Ok(declaration)
    }
}

/// What to write in place of `entry`, when it does not name one host path that each sandbox can
/// spell: an absolute path, the operator's home, or a path under it, with no `..`, no control
/// character, and no pattern.
fn unprotectable(entry: &str) -> Option<&'static str> {
    let under_home = entry.strip_prefix("~/");
    if entry != "~" && under_home.is_none() && !Path::new(entry).is_absolute() {
        return Some("write an absolute path, or one that begins with `~/`");
    }
    // A second `/` makes the rest an absolute path, which is not under the home.
    if under_home.is_some_and(|rest| rest.starts_with('/')) {
        return Some("write one `/` after `~`");
    }
    if Path::new(entry)
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Some("write the path without `..`");
    }
    if entry.chars().any(char::is_control) {
        return Some("write the path without a control character");
    }
    // The characters that a filesystem list refuses, so a sandbox can spell each entry.
    if entry.contains(['*', '?', '[', ']', '{', '}']) {
        return Some(
            "Box reads no pattern, so write each path without `*`, `?`, `[`, `]`, `{`, or `}`",
        );
    }
    None
}

/// One `reads` or `deny` entry of a `[secret-source.<scheme>]` table, which no grant may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtectedPath {
    /// The scheme of the table that holds the entry.
    pub(crate) scheme: String,
    /// The key that holds the entry: `reads` or `deny`.
    pub(crate) list: &'static str,
    /// The entry as the operator wrote it.
    pub(crate) entry: String,
}

/// What one `reads` or `deny` entry names when Box resolves it, which no grant may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spelled {
    /// The path as written, then as it resolves when that differs.
    pub(crate) spellings: Vec<PathBuf>,
    /// Each symbolic link on the way.
    pub(crate) links: Vec<PathBuf>,
    /// Whether each sandbox denies the path: not where a sandbox denies only a path that is
    /// there, and this one is absent.
    pub(crate) covered: bool,
}

impl ProtectedPath {
    /// This path as written under `operator_home` and as it resolves through each symbolic link,
    /// also a link whose target is not there yet, then each link on the way.
    pub(crate) fn spellings(&self, operator_home: &Path) -> Result<Spelled, ConfigError> {
        self.spellings_on(operator_home, cfg!(target_os = "linux"))
    }

    /// [`spellings`](Self::spellings) on an operating system whose sandbox denies a path that is
    /// absent by its name, or one whose sandbox denies a path only when it is there
    /// (`present_only`).
    fn spellings_on(
        &self,
        operator_home: &Path,
        present_only: bool,
    ) -> Result<Spelled, ConfigError> {
        let refuse = |reason: String| ConfigError::SecretSource {
            scheme: self.scheme.clone(),
            reason: format!("`{}` entry {:?} {reason}", self.list, self.entry),
        };
        let written = super::filesystem::under_home(&self.entry, operator_home)
            .ok_or_else(|| refuse("is not an absolute path or one under `~`".to_string()))?;
        // The sandbox checks the path that a name resolves to, so a file that appears behind a
        // link must be closed too.
        let (resolved, links) = crate::record::layout::resolved_through_links(&written)
            .map_err(|error| refuse(format!("cannot be inspected: {error}")))?;
        let mut covered = true;
        if present_only {
            // A mount covers only a folder or a regular file that is there.
            match std::fs::metadata(&resolved) {
                Ok(metadata) if metadata.is_dir() || metadata.is_file() => {}
                Ok(_) => {
                    return Err(refuse(format!(
                        "names {}, which is not a folder or a regular file. On Linux, Box \
                         protects only a folder or a regular file: name the folder that holds \
                         it, or remove the entry",
                        resolved.display()
                    )));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    covered = false;
                }
                Err(error) => return Err(refuse(format!("cannot be inspected: {error}"))),
            }
        }
        let mut spellings = vec![written];
        if !spellings.contains(&resolved) {
            spellings.push(resolved);
        }
        Ok(Spelled {
            spellings,
            links,
            covered,
        })
    }
}

/// Each `reads` and `deny` entry of `entries`.
pub(crate) fn protected_paths(entries: &BTreeMap<String, SecretSourceEntry>) -> Vec<ProtectedPath> {
    entries
        .iter()
        .flat_map(|(scheme, entry)| {
            [("reads", &entry.reads), ("deny", &entry.deny)]
                .into_iter()
                .flat_map(move |(list, paths)| {
                    paths.iter().map(move |path| ProtectedPath {
                        scheme: scheme.clone(),
                        list,
                        entry: path.clone(),
                    })
                })
        })
        .collect()
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
        let mut declarations = BTreeMap::new();
        for (scheme, entry) in entries {
            let refuse = |reason: &str| ConfigError::SecretSource {
                scheme: scheme.clone(),
                reason: reason.to_string(),
            };
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

    /// The scheme of the declared source that reads the secret that `reference` names.
    pub(crate) fn source_of(&self, reference: &str) -> Option<&str> {
        let scheme = routed_scheme(reference).ok()?;
        self.declarations
            .get_key_value(&scheme)
            .map(|(declared, _)| declared.as_str())
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

    /// The checked declarations of `entries`, with the feature on.
    #[cfg(test)]
    pub(crate) fn for_tests(entries: &BTreeMap<String, SecretSourceEntry>) -> Self {
        Self::check(entries, true).expect("the test declarations are valid")
    }
}

/// The scheme by which `credentials` routes `reference` to a source, or its refusal of a text that
/// is no reference.
pub(crate) fn routed_scheme(reference: &str) -> Result<String, CredentialError> {
    Locator::parse_uri(reference).map(|locator| locator.scheme().to_string())
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
        DeclaredSources::check(&entries, true)
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
            !DeclaredSources::check(&BTreeMap::new(), false)
                .expect("no table needs no switch")
                .enabled()
        );
    }

    #[test]
    fn a_declared_source_reads_a_reference_by_the_scheme_that_credentials_routes() {
        let sources = declared();
        for (reference, source) in [
            ("op://Personal/GitHub/token", Some("op")),
            ("op://item#FIELD", Some("op")),
            ("op://a://b", Some("op")),
            (
                "aws-secretsmanager://box/telemetry#KEY",
                Some("aws-secretsmanager"),
            ),
            // No table declares the scheme.
            ("vault://kv/key", None),
            ("env://NAME", None),
            ("aws://", None),
            // `credentials` refuses the text as a reference, so no source reads it.
            ("op://", None),
            ("://orphan", None),
            ("op:/item", None),
            ("op", None),
            ("", None),
            // The scheme is the text before `://` as written: no trim, and no change of case.
            (" op://item", None),
            ("op ://item", None),
            ("OP://item", None),
        ] {
            assert_eq!(sources.source_of(reference), source, "for {reference:?}");
            // The answer is for the scheme that `credentials` routes the reference by.
            let routed = Locator::parse_uri(reference).ok();
            assert_eq!(
                routed_scheme(reference).ok().as_deref(),
                routed.as_ref().map(Locator::scheme),
                "for {reference:?}"
            );
            assert_eq!(
                source,
                routed
                    .as_ref()
                    .map(Locator::scheme)
                    .filter(|scheme| sources.declares(scheme)),
                "for {reference:?}"
            );
        }
        assert_eq!(DeclaredSources::none().source_of("op://item"), None);
        assert_eq!(
            routed_scheme("op://")
                .expect_err("nothing follows the scheme")
                .to_string(),
            "credential error: malformed credential reference (expected `scheme://locator`): \
             \"op://[REDACTED]\""
        );
    }

    #[test]
    fn a_declaration_without_the_feature_is_refused() {
        let error =
            DeclaredSources::check(&entries(DECLARED), false).expect_err("the feature is off");
        assert_eq!(
            error.to_string(),
            "invalid `[secret-source.aws-secretsmanager]` table: a secret source is experimental: \
             set `secret-sources = true` in `[experimental-features]` to load it"
        );
        DeclaredSources::check(&BTreeMap::new(), false)
            .expect("a configuration with no declaration needs no feature");
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
                DeclaredSources::check(&entries, true)
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
        DeclaredSources::check(&entries, true).expect("each spelling names one host path");
    }

    #[test]
    fn a_reads_or_deny_entry_that_does_not_name_one_place_is_refused() {
        const PATTERN: &str =
            "Box reads no pattern, so write each path without `*`, `?`, `[`, `]`, `{`, or `}`";
        for (list, entry, advice) in [
            ("reads", "~/.config/../op", "write the path without `..`"),
            ("deny", "/var/run/op/..", "write the path without `..`"),
            ("reads", "~/.config/op*", PATTERN),
            ("deny", "/var/run/op-?.sock", PATTERN),
            ("deny", "~/Library/Group Containers/[A-Z", PATTERN),
            ("deny", "/var/run/op]", PATTERN),
            // The sandbox profile of macOS cannot hold these two.
            ("reads", "~/.config/{{op", PATTERN),
            ("reads", "~/.config/op}", PATTERN),
            (
                "reads",
                "~/.config/op\nconfig",
                "write the path without a control character",
            ),
            // A second `/` after `~` names a path under `/`, not under the home.
            ("reads", "~//.config/op", "write one `/` after `~`"),
            ("deny", "~//", "write one `/` after `~`"),
        ] {
            assert_eq!(
                refusal(&format!("{PROTOCOL}{COMMAND}{list} = [{entry:?}]\n")),
                format!(
                    "invalid `[secret-source.op]` table: `{list}` entry {entry:?} is not a path \
                     that Box can protect; {advice}"
                )
            );
        }
        // A name that only holds two dots is one place.
        let entries = entries(&format!(
            "[secret-source.op]\n{PROTOCOL}{COMMAND}reads = [\"~/.config/op..d\", \"/etc/..op\"]\n"
        ));
        DeclaredSources::check(&entries, true).expect("no `..` component, no refusal");
    }

    #[test]
    fn each_reads_and_deny_entry_is_a_protected_path_of_its_scheme() {
        let protected = |scheme: &str, list: &'static str, entry: &str| ProtectedPath {
            scheme: scheme.to_string(),
            list,
            entry: entry.to_string(),
        };
        assert_eq!(
            protected_paths(&entries(DECLARED)),
            [
                protected("op", "reads", "~/.config/op"),
                protected("op", "deny", "/var/run/op"),
            ],
            "the `aws-secretsmanager` table of the fixture names no path"
        );
        assert_eq!(protected_paths(&BTreeMap::new()), []);
    }

    /// **Where a sandbox denies only a present folder or file, an entry whose path is absent
    /// keeps its spellings with no cover, and an entry that names a socket is refused**, and a
    /// present folder or file is covered.
    #[test]
    fn an_absent_path_is_skipped_and_a_socket_is_refused_where_only_a_present_path_is_protected() {
        let directory = tempfile::tempdir().expect("a home");
        let home = directory.path().canonicalize().expect("the home resolves");
        std::fs::create_dir_all(home.join("vault/store")).expect("a folder of the vault");
        std::fs::write(home.join("vault/token"), "").expect("a file of the vault");
        std::os::unix::fs::symlink(home.join("vault/store"), home.join("linked"))
            .expect("a link to the folder");
        std::os::unix::fs::symlink(home.join("app/socket"), home.join("dangling"))
            .expect("a link whose target is not there");
        let protected = |entry: &str| ProtectedPath {
            scheme: "op".to_string(),
            list: "deny",
            entry: entry.to_string(),
        };
        // An absent name, an absent name below one, a link whose target is absent, and a name
        // below a file.
        for (entry, named) in [
            ("~/later", home.join("later")),
            ("~/later/socket", home.join("later/socket")),
            ("~/dangling", home.join("app/socket")),
            ("~/vault/token/below", home.join("vault/token/below")),
        ] {
            let path = protected(entry);
            let by_name = path.spellings_on(&home, false).expect("an absent path");
            assert!(by_name.covered, "{entry}");
            assert_eq!(by_name.spellings.last(), Some(&named), "{entry}");
            // No grant reaches the same spellings, and no sandbox denies them.
            assert_eq!(
                path.spellings_on(&home, true).expect("an absent path"),
                Spelled {
                    covered: false,
                    ..by_name
                },
                "{entry}"
            );
        }
        for entry in ["~/vault/store", "~/vault/token", "~/linked", "~"] {
            let path = protected(entry);
            let spelled = path.spellings_on(&home, true).expect("the path is there");
            assert!(spelled.covered, "{entry}");
            assert_eq!(
                spelled,
                path.spellings_on(&home, false).expect("the path is there"),
                "{entry}"
            );
        }
        // A socket, and a link to it: a mount covers a folder or a regular file alone.
        let _socket =
            std::os::unix::net::UnixListener::bind(home.join("agent.sock")).expect("a socket");
        std::os::unix::fs::symlink(home.join("agent.sock"), home.join("linked.sock"))
            .expect("a link to the socket");
        for entry in ["~/agent.sock", "~/linked.sock"] {
            let path = protected(entry);
            assert_eq!(
                path.spellings_on(&home, true)
                    .expect_err("the path is a socket")
                    .to_string(),
                format!(
                    "invalid `[secret-source.op]` table: `deny` entry {entry:?} names {}, which \
                     is not a folder or a regular file. On Linux, Box protects only a folder or \
                     a regular file: name the folder that holds it, or remove the entry",
                    home.join("agent.sock").display()
                )
            );
            path.spellings_on(&home, false)
                .expect("the other rule protects a socket by its name");
        }
    }

    /// **The rule for an absent path follows the build target**: on Linux no sandbox denies it,
    /// and macOS denies it by its name.
    #[test]
    fn the_rule_for_an_absent_path_follows_the_build_target() {
        let directory = tempfile::tempdir().expect("a home");
        let home = directory.path().canonicalize().expect("the home resolves");
        let path = ProtectedPath {
            scheme: "op".to_string(),
            list: "reads",
            entry: "~/.config/op".to_string(),
        };
        let present = Spelled {
            spellings: vec![home.join(".config/op")],
            links: Vec::new(),
            covered: true,
        };
        assert_eq!(
            path.spellings(&home).expect("an absent path"),
            Spelled {
                covered: !cfg!(target_os = "linux"),
                ..present.clone()
            }
        );
        std::fs::create_dir_all(home.join(".config/op")).expect("the folder of the vault");
        assert_eq!(path.spellings(&home).expect("a present path"), present);
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
