//! `[locations]`: the names a filesystem rule reads as `context.input.locations`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// The longest location name.
const MAXIMUM_LOCATION_NAME: usize = 64;

/// The words Cedar reserves, which a rule cannot read as `context.input.locations.<name>`.
const RESERVED_WORDS: [&str; 10] = [
    "true", "false", "if", "then", "else", "in", "is", "like", "has", "__cedar",
];

/// The declared locations, each a name and the directories as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Locations(BTreeMap<String, Vec<String>>);

/// Each location's roots as written, which is the text a filesystem rule matches.
pub(crate) type LocationRoots = BTreeMap<String, Vec<PathBuf>>;

impl Locations {
    /// Whether no location is declared.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Refuse a name or a directory that no rule could match by.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        for (name, directories) in &self.0 {
            let refuse = |reason: String| ConfigError::Contract {
                reason: format!("`[locations] {name}` {reason}"),
            };
            if let Some(reason) = invalid_name(name) {
                return Err(refuse(format!(
                    "is not a location name: {reason}; a name starts with a letter, holds at most \
                     {MAXIMUM_LOCATION_NAME} letters, digits, or '_', and is not a word Cedar \
                     reserves"
                )));
            }
            if directories.is_empty() {
                return Err(refuse(
                    "lists no directory; a location names at least one".to_string(),
                ));
            }
            for (index, entry) in directories.iter().enumerate() {
                if let Some(reason) = invalid_directory(entry) {
                    return Err(refuse(format!("entry {entry:?} is refused: {reason}")));
                }
                if directories[..index]
                    .iter()
                    .any(|earlier| Path::new(earlier) == Path::new(entry))
                {
                    return Err(refuse(format!(
                        "lists {entry:?} twice; name each directory once"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The policy operator anchored at `operator_home` with these roots as written, or the refusal
    /// that names the entry no reported path can match.
    pub(crate) fn operator(&self, operator_home: &Path) -> Result<policy::Operator, ConfigError> {
        policy::Operator::unanchored()
            .anchored_at(operator_home)
            .with_locations(self.roots())
            .map_err(|error| match error {
                policy::PolicyError::UnresolvableLocation {
                    name,
                    directory,
                    reason,
                } => ConfigError::Contract {
                    reason: format!(
                        "`[locations] {name}` entry {:?} cannot be resolved: {reason}",
                        directory.display().to_string()
                    ),
                },
                policy::PolicyError::UnmatchableLocation {
                    name,
                    directory,
                    reason,
                } => ConfigError::Contract {
                    reason: format!(
                        "`[locations] {name}` entry {:?} can never match a reported path: \
                         {reason}",
                        directory.display().to_string()
                    ),
                },
                other => ConfigError::Contract {
                    reason: format!("`[locations]` is refused: {other}"),
                },
            })
    }

    /// Each location's roots as written.
    pub(crate) fn roots(&self) -> LocationRoots {
        self.0
            .iter()
            .map(|(name, entries)| (name.clone(), entries.iter().map(PathBuf::from).collect()))
            .collect()
    }
}

/// Why `name` is not a location name, or `None` when it is one.
fn invalid_name(name: &str) -> Option<&'static str> {
    let Some(first) = name.chars().next() else {
        return Some("it is empty");
    };
    if !first.is_ascii_alphabetic() {
        return Some("it does not start with a letter");
    }
    if name.len() > MAXIMUM_LOCATION_NAME {
        return Some("it is too long");
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Some("it holds a character other than a letter, a digit, or '_'");
    }
    if RESERVED_WORDS.contains(&name) {
        return Some("it is a word Cedar reserves");
    }
    None
}

/// Why `entry` is not a directory a location can name, or `None` when it is one.
fn invalid_directory(entry: &str) -> Option<&'static str> {
    if entry == "~" {
        return None;
    }
    let rest = match entry.strip_prefix("~/") {
        Some(relative) if relative.starts_with('/') => {
            return Some("it holds an empty component after `~/`");
        }
        Some(relative) => relative,
        None if Path::new(entry).is_absolute() => entry,
        None => return Some("it is neither absolute nor `~/`-relative"),
    };
    if rest
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Some("it holds a `.` or `..` component");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locations(entries: &[(&str, &[&str])]) -> Locations {
        Locations(
            entries
                .iter()
                .map(|(name, directories)| {
                    (
                        (*name).to_string(),
                        directories
                            .iter()
                            .map(|entry| (*entry).to_string())
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn a_valid_table_is_accepted() {
        let table = locations(&[
            ("project", &["/work/app"]),
            ("caches", &["~/.cache/my-agent", "~/.npm"]),
            ("a", &["/"]),
            ("Build_output_2", &["/work/app/target/"]),
            ("permit", &["/work/permit"]),
            (&"x".repeat(MAXIMUM_LOCATION_NAME), &["/x"]),
        ]);
        table.validate().expect("the table is valid");
        assert!(!table.is_empty());
        assert!(Locations::default().is_empty());
    }

    #[test]
    fn a_name_outside_the_rule_is_refused_by_its_key() {
        for name in [
            "",
            "1project",
            "_project",
            "-project",
            "pro ject",
            "pro.ject",
            "my-project",
            "projé",
            "true",
            "in",
            "has",
            "like",
            &"x".repeat(MAXIMUM_LOCATION_NAME + 1),
        ] {
            let error = locations(&[(name, &["/work"])])
                .validate()
                .expect_err(name)
                .to_string();
            assert!(error.contains(&format!("`[locations] {name}`")), "{error}");
            assert!(error.contains("is not a location name"), "{error}");
        }
    }

    #[test]
    fn an_empty_list_is_refused() {
        let error = locations(&[("project", &[])])
            .validate()
            .expect_err("an empty list")
            .to_string();
        assert!(error.contains("`[locations] project`"), "{error}");
        assert!(error.contains("lists no directory"), "{error}");
    }

    #[test]
    fn a_relative_or_dotted_entry_is_refused() {
        for (entry, reason) in [
            ("work/app", "neither absolute nor `~/`-relative"),
            ("./work", "neither absolute nor `~/`-relative"),
            ("~//etc", "an empty component after `~/`"),
            ("~user/app", "neither absolute nor `~/`-relative"),
            ("", "neither absolute nor `~/`-relative"),
            ("/work/./app", "a `.` or `..` component"),
            ("/work/../etc", "a `.` or `..` component"),
            ("/work/..", "a `.` or `..` component"),
            ("~/../other", "a `.` or `..` component"),
            ("~/./app", "a `.` or `..` component"),
        ] {
            let error = locations(&[("project", &["/fine", entry])])
                .validate()
                .expect_err(entry)
                .to_string();
            assert!(
                error.contains("`[locations] project`"),
                "{entry:?}: {error}"
            );
            assert!(error.contains(reason), "{entry:?}: {error}");
        }
        for entry in ["/work/.app", "/work/..app", "~/.cache", "~"] {
            locations(&[("project", &[entry])])
                .validate()
                .unwrap_or_else(|error| panic!("{entry:?}: {error}"));
        }
    }

    #[test]
    fn a_duplicate_entry_in_one_location_is_refused() {
        for (first, second) in [("/work", "/work"), ("/work", "/work/"), ("~/a", "~/a")] {
            let error = locations(&[("project", &[first, second])])
                .validate()
                .expect_err(second)
                .to_string();
            assert!(error.contains("`[locations] project`"), "{error}");
            assert!(error.contains("twice"), "{error}");
        }
        locations(&[("project", &["/work"]), ("other", &["/work"])])
            .validate()
            .expect("two locations may share a directory");
    }

    #[test]
    fn each_entry_reaches_the_operator_as_written() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("canonical");
        let table = locations(&[("caches", &["~/.cache/agent", "/absent/elsewhere", "~"])]);
        let written = BTreeMap::from([(
            "caches".to_string(),
            vec![
                PathBuf::from("~/.cache/agent"),
                PathBuf::from("/absent/elsewhere"),
                PathBuf::from("~"),
            ],
        )]);
        assert_eq!(table.roots(), written);
        assert_eq!(
            table
                .operator(&home)
                .expect("the operator builds")
                .locations(),
            &written,
            "a root is not expanded or resolved"
        );
    }

    #[test]
    fn an_entry_no_reported_path_can_match_is_refused_by_its_key() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("canonical");
        std::fs::create_dir(home.join("real")).expect("the real directory");
        std::os::unix::fs::symlink(home.join("real"), home.join("link")).expect("the link");
        let absolute = home.join("real").display().to_string();
        for (entry, reason) in [
            (
                "~/link",
                "it crosses a symbolic link, and a path is reported as resolved; write \
                 \"~/real\""
                    .to_string(),
            ),
            (
                absolute.as_str(),
                "a path under the operator home is reported as `~/…`; write \"~/real\"".to_string(),
            ),
        ] {
            let error = locations(&[("project", &["~/fine", entry])])
                .operator(&home)
                .expect_err(entry)
                .to_string();
            assert_eq!(
                error,
                format!(
                    "invalid Box configuration: `[locations] project` entry {entry:?} can never \
                     match a reported path: {reason}"
                )
            );
        }
    }

    #[test]
    fn an_unresolvable_entry_is_refused_by_its_key() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("canonical");
        std::os::unix::fs::symlink(home.join("absent"), home.join("dangling")).expect("the link");
        let error = locations(&[("project", &["~/fine", "~/dangling"])])
            .operator(&home)
            .expect_err("a dangling link")
            .to_string();
        assert!(
            error.starts_with(
                "invalid Box configuration: `[locations] project` entry \"~/dangling\" cannot \
                 be resolved: "
            ),
            "{error}"
        );
        assert!(
            error.contains("symbolic link whose target does not exist"),
            "{error}"
        );
    }

    #[test]
    fn the_table_parses_from_toml_and_refuses_another_shape() {
        let parsed: Locations =
            toml::from_str("project = [\"/work/app\"]\ncaches = [\"~/.npm\"]").expect("parses");
        assert_eq!(
            parsed,
            locations(&[("caches", &["~/.npm"]), ("project", &["/work/app"])])
        );
        for text in [
            "project = \"/work/app\"",
            "project = [1]",
            "project = { a = 1 }",
        ] {
            assert!(toml::from_str::<Locations>(text).is_err(), "{text}");
        }
    }
}
