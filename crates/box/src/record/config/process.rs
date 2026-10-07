//! `box.toml`'s `[agent]` and `[tool.<name>]` tables: one process each, in one shape.
//!
//! | Field | Meaning |
//! |---|---|
//! | `command` | the executable and its fixed leading arguments |
//! | `workspace` | the initial working directory; grants nothing |
//! | `env` | the literal environment, with no host inheritance |
//! | `filesystem` | the eight path lists the process's own syscalls reach |

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

use super::env::{reserved_workload_environment, valid_environment_name};

/// One process declaration, shared by `[agent]` and every `[tool.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessSpec {
    /// The executable and its fixed leading arguments.
    pub(crate) command: Vec<String>,

    /// The initial working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workspace: Option<PathBuf>,

    /// Literal variables, applied beneath every name Core owns.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,

    /// What the process's own syscalls reach.
    #[serde(default, skip_serializing_if = "Filesystem::is_empty")]
    pub(crate) filesystem: Filesystem,

    /// How a leaf reaches the network, from `[tool.<name>.network]` or `[mcp.<name>.network]`.
    /// `[agent]` refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<NetworkConfig>,
}

/// The eight path lists. A directory entry is recursive, and a file entry is exact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filesystem {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) read: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) write: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) read_file: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) write_file: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) list: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) metadata: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) exec: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny: Vec<PathBuf>,
}

/// Which of the eight lists an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Grant {
    Read,
    Write,
    ReadFile,
    WriteFile,
    List,
    Metadata,
    Exec,
    Deny,
}

impl Grant {
    /// Every list, in the order the contract states them.
    pub(crate) const ALL: [Grant; 8] = [
        Grant::Read,
        Grant::Write,
        Grant::ReadFile,
        Grant::WriteFile,
        Grant::List,
        Grant::Metadata,
        Grant::Exec,
        Grant::Deny,
    ];

    /// The `box.toml` key.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Grant::Read => "read",
            Grant::Write => "write",
            Grant::ReadFile => "read_file",
            Grant::WriteFile => "write_file",
            Grant::List => "list",
            Grant::Metadata => "metadata",
            Grant::Exec => "exec",
            Grant::Deny => "deny",
        }
    }

    /// Whether the list authorizes a write.
    pub(crate) fn writes(self) -> bool {
        matches!(self, Grant::Write | Grant::WriteFile)
    }
}

impl Filesystem {
    pub(crate) fn is_empty(&self) -> bool {
        Grant::ALL.iter().all(|kind| self.list(*kind).is_empty())
    }

    /// One list, by kind.
    pub(crate) fn list(&self, kind: Grant) -> &[PathBuf] {
        match kind {
            Grant::Read => &self.read,
            Grant::Write => &self.write,
            Grant::ReadFile => &self.read_file,
            Grant::WriteFile => &self.write_file,
            Grant::List => &self.list,
            Grant::Metadata => &self.metadata,
            Grant::Exec => &self.exec,
            Grant::Deny => &self.deny,
        }
    }

    /// Every entry with the list it came from, in list order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (Grant, &Path)> {
        Grant::ALL.into_iter().flat_map(|kind| {
            self.list(kind)
                .iter()
                .map(move |path| (kind, path.as_path()))
        })
    }
}

/// `[mcp.<name>.network]` and `[tool.<name>.network]`: how a leaf box reaches the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkConfig {
    /// Route egress through the box's egress gateway (`true`, the default and safe posture) or allow
    /// direct/native egress that bypasses it (`false`). Set `false` only for a trusted workload
    /// whose client cannot honor `HTTPS_PROXY` (e.g. a single sign-on client): it gives up gateway
    /// mediation, credential injection, and per-request `net:*` policy for this process.
    #[serde(default = "contain_egress_default")]
    pub(crate) contain_egress: bool,
}

fn contain_egress_default() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            contain_egress: contain_egress_default(),
        }
    }
}

impl NetworkConfig {
    pub(crate) fn is_default(&self) -> bool {
        self.contain_egress
    }
}

/// One contained local MCP server, stored in `Record::contained_mcp`: the `ProcessSpec` its
/// `[mcp.<name>]` table describes, its `network` included. Every stdio server produces one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContainedMcp {
    /// The synthesized process shape (command, grants, and network).
    pub(crate) spec: ProcessSpec,
}

impl ProcessSpec {
    /// Whether `[tool.<name>.network] contain_egress = false` gives this process direct egress.
    pub(crate) fn native_egress(&self) -> bool {
        self.network
            .as_ref()
            .is_some_and(|network| !network.contain_egress)
    }

    /// The executable, which is element 0 of `command`.
    pub(crate) fn program(&self) -> &str {
        self.command.first().map_or("", String::as_str)
    }

    /// The fixed arguments after the executable.
    pub(crate) fn fixed_arguments(&self) -> &[String] {
        self.command.get(1..).unwrap_or_default()
    }

    /// Refuse a table no run could honor, naming `table` in every refusal.
    pub(crate) fn validate(&self, table: &str) -> Result<(), ConfigError> {
        let refuse = |reason: String| ConfigError::Process {
            table: table.to_string(),
            reason,
        };
        if table == "[agent]" && self.network.is_some() {
            return Err(refuse(
                "`network` is refused on `[agent]`: the agent always reaches the network through \
                 the egress gateway, and only a `[tool.<name>]` or a stdio `[mcp.<name>]` takes \
                 `network.contain_egress`"
                    .into(),
            ));
        }
        match self.command.first() {
            None => {
                return Err(refuse(
                    "`command` must name a program as its first entry".into(),
                ));
            }
            Some(program) if program.is_empty() => {
                return Err(refuse("`command` element 0 is empty".into()));
            }
            Some(program) => {
                let path = Path::new(program);
                if !path.is_absolute() && path.components().count() > 1 {
                    return Err(refuse(format!(
                        "`command` element 0 {program:?} is a relative path; write an absolute \
                         path, or a bare name that `env.PATH` resolves"
                    )));
                }
            }
        }
        if let Some(workspace) = &self.workspace
            && !workspace.is_absolute()
        {
            return Err(refuse(format!(
                "`workspace` must be absolute: {}",
                workspace.display()
            )));
        }
        for name in self.env.keys() {
            if name.is_empty() || !valid_environment_name(name) {
                return Err(refuse(format!(
                    "`env` name {name:?} is not a valid environment-variable name"
                )));
            }
            if reserved_workload_environment(name) {
                return Err(refuse(format!(
                    "`env` name {name:?} is set by the box itself, so a table cannot claim it"
                )));
            }
        }
        for name in ["HOME", "TMPDIR"] {
            if let Some(value) = self.env.get(name)
                && !Path::new(value).is_absolute()
            {
                return Err(refuse(format!(
                    "`env.{name}` must be an absolute path: {value:?}"
                )));
            }
        }
        for kind in Grant::ALL {
            let mut seen = BTreeSet::new();
            for entry in self.filesystem.list(kind) {
                validate_spelling(kind, entry).map_err(refuse)?;
                if !seen.insert(entry.as_path()) {
                    return Err(refuse(format!(
                        "`filesystem.{}` path {} is duplicated",
                        kind.key(),
                        entry.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// The search path that resolves this process's program: its own `PATH`, else the operator's,
    /// else `/usr/bin:/bin`.
    pub(crate) fn search_path(&self) -> std::ffi::OsString {
        self.env
            .get("PATH")
            .map(std::ffi::OsString::from)
            .or_else(|| std::env::var_os("PATH"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| std::ffi::OsString::from("/usr/bin:/bin"))
    }

    /// The `filesystem` spellings that name a credential store, with their list.
    pub(crate) fn credential_store_entries(&self, operator_home: &Path) -> Vec<(Grant, String)> {
        self.filesystem
            .entries()
            .filter(|(kind, _)| !matches!(kind, Grant::Deny))
            .filter_map(|(kind, entry)| {
                let spelling = entry.display().to_string();
                let relative = match spelling.strip_prefix("~/") {
                    Some(relative) => Some(format!("~/{relative}")),
                    None => entry
                        .strip_prefix(operator_home)
                        .ok()
                        .map(|rest| format!("~/{}", rest.display())),
                };
                relative
                    .filter(|home_relative| {
                        containment::home_relative_path_refusal(home_relative).is_some()
                    })
                    .map(|_| (kind, spelling))
            })
            .collect()
    }
}

/// Refuse a spelling no list may carry: empty, patterned, relative, or naming a box's own authority.
fn validate_spelling(kind: Grant, entry: &Path) -> Result<(), String> {
    let spelling = entry.display().to_string();
    let key = kind.key();
    if spelling.is_empty()
        || spelling.chars().any(char::is_control)
        || spelling
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Err(format!(
            "`filesystem.{key}` path {spelling:?} must be exact and contain no pattern or control \
             character"
        ));
    }
    let home_relative = spelling == "~" || spelling.starts_with("~/");
    if !home_relative && !entry.is_absolute() {
        return Err(format!(
            "`filesystem.{key}` path {spelling:?} must be absolute or start with `~/`, so a \
             checked-in configuration holds in every clone"
        ));
    }
    if entry
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(format!(
            "`filesystem.{key}` path {spelling:?} carries `..`; name the path it means"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(text: &str) -> ProcessSpec {
        toml::from_str(text).expect("the table parses")
    }

    fn refusal(text: &str) -> String {
        let parsed: Result<ProcessSpec, _> = toml::from_str(text);
        match parsed {
            Err(error) => error.to_string(),
            Ok(parsed) => match parsed.validate("[agent]") {
                Ok(()) => panic!("{text:?} must be refused"),
                Err(error) => error.to_string(),
            },
        }
    }

    #[test]
    fn a_tool_network_table_selects_native_egress() {
        let native = spec("command = [\"sso-cli\"]\n[network]\ncontain_egress = false\n");
        assert!(
            native.native_egress(),
            "contain_egress = false gives the tool direct egress"
        );
        native
            .validate("[tool.sso-cli]")
            .expect("a tool takes a network table");

        let explicit = spec("command = [\"sso-cli\"]\n[network]\ncontain_egress = true\n");
        assert!(
            !explicit.native_egress(),
            "contain_egress = true stays on the gateway"
        );
        let empty = spec("command = [\"sso-cli\"]\n[network]\n");
        assert!(
            !empty.native_egress(),
            "an empty network table stays on the gateway"
        );
        let absent = spec("command = [\"sso-cli\"]\n");
        assert!(
            !absent.native_egress(),
            "no network table stays on the gateway"
        );
        assert_eq!(absent.network, None);
    }

    #[test]
    fn the_agent_refuses_a_network_table_whatever_it_holds() {
        for table in [
            "[network]\ncontain_egress = false\n",
            "[network]\ncontain_egress = true\n",
            "[network]\n",
        ] {
            let refused = refusal(&format!("command = [\"claude\"]\n{table}"));
            assert!(
                refused.contains("`network` is refused on `[agent]`"),
                "{table:?}: {refused}"
            );
        }
    }

    #[test]
    fn a_network_table_refuses_an_unknown_key() {
        let parsed: Result<ProcessSpec, _> =
            toml::from_str("command = [\"sso-cli\"]\n[network]\nproxy = false\n");
        assert!(parsed.is_err(), "only contain_egress is a network key");
    }

    #[test]
    fn a_spec_carries_the_four_fields_and_the_eight_lists() {
        let parsed = spec(
            r#"
            command = ["claude", "--version"]
            workspace = "/work/project"
            env = { HOME = "/home/me", IS_SANDBOX = "true" }
            [filesystem]
            read = ["/work/project"]
            write = ["/work/project/src"]
            read_file = ["/etc/localtime"]
            write_file = ["/work/log"]
            list = ["/work"]
            metadata = ["/etc"]
            exec = ["/bin/sh"]
            deny = ["/work/project/.env"]
            "#,
        );
        assert_eq!(parsed.program(), "claude");
        assert_eq!(parsed.fixed_arguments(), ["--version"]);
        assert_eq!(parsed.workspace, Some(PathBuf::from("/work/project")));
        assert_eq!(parsed.env["HOME"], "/home/me");
        assert_eq!(parsed.filesystem.entries().count(), 8);
        parsed
            .validate("[agent]")
            .expect("a complete table validates");
    }

    #[test]
    fn every_removed_or_unknown_key_is_a_load_error() {
        for unknown in [
            "command = [\"x\"]\ndefault_command = [\"x\"]",
            "command = [\"x\"]\nread = [\"/a\"]",
            "command = [\"x\"]\nwrite = [\"/a\"]",
            "command = [\"x\"]\nexec = [\"x\"]",
            "command = [\"x\"]\n[filesystem]\nreadonly = [\"/a\"]",
            "command = [\"x\"]\n[filesystem]\nworkspace = \"read-write\"",
        ] {
            assert!(
                toml::from_str::<ProcessSpec>(unknown).is_err(),
                "{unknown:?} must be a load error on the production type"
            );
        }
    }

    /// **One case per refusal class, each asserting the message names the table and the cause.**
    #[test]
    fn every_shape_refusal_fires_and_names_its_cause() {
        let cases: [(&str, &str); 8] = [
            ("command = []", "first entry"),
            ("command = [\"\"]", "element 0 is empty"),
            ("command = [\"bin/tool\"]", "relative path"),
            (
                "command = [\"x\"]\nworkspace = \"relative\"",
                "`workspace` must be absolute",
            ),
            (
                "command = [\"x\"]\nenv = { \"1BAD\" = \"v\" }",
                "not a valid environment-variable",
            ),
            (
                "command = [\"x\"]\nenv = { HTTPS_PROXY = \"v\" }",
                "set by the box itself",
            ),
            (
                "command = [\"x\"]\nenv = { HOME = \"relative\" }",
                "`env.HOME` must be an absolute",
            ),
            (
                "command = [\"x\"]\n[filesystem]\nread = [\"relative/path\"]",
                "must be absolute or start with `~/`",
            ),
        ];
        for (text, expected) in cases {
            let message = refusal(text);
            assert!(
                message.contains(expected) && message.contains("[agent]"),
                "{text:?} must be refused for {expected:?} and name the table: {message}"
            );
        }
        for (text, expected) in [
            (
                "command = [\"x\"]\n[filesystem]\nwrite = [\"/a/*\"]",
                "no pattern",
            ),
            (
                "command = [\"x\"]\n[filesystem]\nread = [\"/a/../b\"]",
                "carries `..`",
            ),
            (
                "command = [\"x\"]\n[filesystem]\nread = [\"/a\", \"/a\"]",
                "is duplicated",
            ),
        ] {
            let message = refusal(text);
            assert!(message.contains(expected), "{text:?}: {message}");
        }
    }

    #[test]
    fn un_reserved_names_are_accepted_in_env() {
        let parsed = spec(
            "command = [\"x\"]\nenv = { HOME = \"/h\", PATH = \"/usr/bin\", TMPDIR = \"/t\", \
             TERM = \"xterm\", LANG = \"C\" }",
        );
        parsed
            .validate("[tool.x]")
            .expect("HOME, PATH, TMPDIR, and terminal names are the operator's to set");
    }

    #[test]
    fn credential_store_entries_are_classified_by_spelling() {
        let parsed = spec(
            "command = [\"aws\"]\n[filesystem]\nread = [\"~/.aws\", \"/Users/me/.ssh\", \
             \"~/.gitconfig\"]\nwrite = [\"~/.aws/sso/cache\"]\ndeny = [\"~/.aws/credentials\"]",
        );
        let stores = parsed.credential_store_entries(Path::new("/Users/me"));
        assert_eq!(
            stores,
            [
                (Grant::Read, "~/.aws".to_string()),
                (Grant::Read, "/Users/me/.ssh".to_string()),
                (Grant::Write, "~/.aws/sso/cache".to_string()),
            ],
            "a denial is not a punch-through, and an ordinary dotfile is not a store"
        );
    }
}
