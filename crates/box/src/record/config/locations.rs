//! `[locations]`: the names a filesystem rule reads as `context.input.locations`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// The longest location name.
const MAXIMUM_LOCATION_NAME: usize = 64;

/// The declared locations, each a name and the directories as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Locations(BTreeMap<String, Vec<String>>);

/// Each location's directories, absolute and canonical where they exist.
pub(crate) type ResolvedLocations = BTreeMap<String, Vec<PathBuf>>;

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
                    "is not a location name: {reason}; a name starts with a letter and holds at \
                     most {MAXIMUM_LOCATION_NAME} letters, digits, '_', or '-'"
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

    /// Each location's directories with `~/` expanded against `operator_home`, and each one that
    /// exists canonicalized.
    pub(crate) fn resolved(&self, operator_home: &Path) -> ResolvedLocations {
        self.0
            .iter()
            .map(|(name, directories)| {
                let mut resolved: Vec<PathBuf> = Vec::new();
                for entry in directories {
                    let expanded = match entry.strip_prefix("~/") {
                        Some(relative) => operator_home.join(relative),
                        None => PathBuf::from(entry),
                    };
                    let directory = expanded.canonicalize().unwrap_or(expanded);
                    if !resolved.contains(&directory) {
                        resolved.push(directory);
                    }
                }
                (name.clone(), resolved)
            })
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
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Some("it holds a character other than a letter, a digit, '_', or '-'");
    }
    None
}

/// Why `entry` is not a directory a location can name, or `None` when it is one.
fn invalid_directory(entry: &str) -> Option<&'static str> {
    let rest = match entry.strip_prefix("~/") {
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
            ("Build_output-2", &["/work/app/target/"]),
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
            "projé",
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
            ("~", "neither absolute nor `~/`-relative"),
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
        for entry in ["/work/.app", "/work/..app", "~/.cache"] {
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
    fn a_home_relative_entry_expands_against_the_operator_home() {
        let home = Path::new("/nonexistent-box-home/operator");
        let resolved =
            locations(&[("caches", &["~/.cache/agent", "/absent/elsewhere"])]).resolved(home);
        assert_eq!(
            resolved,
            BTreeMap::from([(
                "caches".to_string(),
                vec![
                    PathBuf::from("/nonexistent-box-home/operator/.cache/agent"),
                    PathBuf::from("/absent/elsewhere"),
                ],
            )])
        );
    }

    #[test]
    fn an_existing_entry_is_canonicalized_and_a_missing_one_is_kept() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let real = directory.path().join("real");
        std::fs::create_dir(&real).expect("the real directory");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("the link");
        let missing = directory.path().join("missing");
        let spelled = |path: &Path| path.to_str().expect("UTF-8").to_string();
        let table = Locations(BTreeMap::from([(
            "project".to_string(),
            vec![spelled(&link), spelled(&missing), spelled(&real)],
        )]));
        table.validate().expect("the table is valid");
        assert_eq!(
            table.resolved(Path::new("/unused")),
            BTreeMap::from([(
                "project".to_string(),
                vec![real.canonicalize().expect("canonical"), missing],
            )]),
            "the link resolves to its target, which then appears once"
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
