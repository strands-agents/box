use std::ffi::OsString;
use std::path::Path;

use crate::installation::saved_choice;

/// What decided whether telemetry is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentSource {
    /// `BOX_TELEMETRY` is set.
    BoxTelemetry,
    /// `DO_NOT_TRACK` is `1` or `true`.
    DoNotTrack,
    /// The `telemetry` key in `installation.toml`.
    Saved,
    /// Nothing chose, so telemetry is on.
    Default,
    /// `installation.toml` could not be read, so telemetry is off.
    Unreadable,
}

/// Whether telemetry is on for this invocation, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consent {
    pub enabled: bool,
    pub source: ConsentSource,
}

impl Consent {
    /// Resolve `BOX_TELEMETRY`, then `DO_NOT_TRACK`, then the saved choice in `box_dir`, else on.
    /// An empty variable counts as unset, and a `BOX_TELEMETRY` that is not UTF-8 turns it off.
    pub fn resolve(box_dir: &Path, variable: impl Fn(&str) -> Option<OsString>) -> Self {
        let text = |name| variable(name).map(|value| value.to_str().map(str::to_ascii_lowercase));
        if let Some(value) = text("BOX_TELEMETRY").filter(|value| value.as_deref() != Some("")) {
            return Self {
                enabled: matches!(value.as_deref(), Some("1" | "true" | "on")),
                source: ConsentSource::BoxTelemetry,
            };
        }
        if text("DO_NOT_TRACK").is_some_and(|value| matches!(value.as_deref(), Some("1" | "true")))
        {
            return Self {
                enabled: false,
                source: ConsentSource::DoNotTrack,
            };
        }
        match saved_choice(box_dir) {
            Ok(Some(enabled)) => Self {
                enabled,
                source: ConsentSource::Saved,
            },
            Ok(None) => Self {
                enabled: true,
                source: ConsentSource::Default,
            },
            Err(_) => Self {
                enabled: false,
                source: ConsentSource::Unreadable,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::installation::save_telemetry_choice;

    fn resolve(box_dir: &Path, variables: &[(&str, &str)]) -> Consent {
        let variables: BTreeMap<_, _> = variables.iter().copied().collect();
        Consent::resolve(box_dir, |name| variables.get(name).map(OsString::from))
    }

    #[test]
    fn telemetry_is_on_by_default_without_creating_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let box_dir = directory.path().join(".strands/box");
        assert_eq!(
            resolve(&box_dir, &[]),
            Consent {
                enabled: true,
                source: ConsentSource::Default
            }
        );
        assert!(!directory.path().join(".strands").exists());
    }

    #[test]
    fn box_telemetry_overrides_do_not_track_and_the_saved_choice() {
        let directory = tempfile::tempdir().unwrap();
        save_telemetry_choice(directory.path(), false).unwrap();
        for (value, enabled) in [
            ("1", true),
            ("true", true),
            ("ON", true),
            ("0", false),
            ("false", false),
            ("off", false),
            ("nope", false),
        ] {
            let consent = resolve(
                directory.path(),
                &[("BOX_TELEMETRY", value), ("DO_NOT_TRACK", "1")],
            );
            assert_eq!(consent.enabled, enabled, "{value}");
            assert_eq!(consent.source, ConsentSource::BoxTelemetry, "{value}");
        }
        assert_eq!(
            resolve(directory.path(), &[("BOX_TELEMETRY", "")]).source,
            ConsentSource::Saved
        );
    }

    #[test]
    fn a_value_that_is_not_utf8_disables_through_box_telemetry_only() {
        use std::os::unix::ffi::OsStringExt as _;

        let directory = tempfile::tempdir().unwrap();
        let invalid = |set: &'static str| {
            move |name: &str| (name == set).then(|| OsString::from_vec(vec![0xff]))
        };
        assert_eq!(
            Consent::resolve(directory.path(), invalid("BOX_TELEMETRY")),
            Consent {
                enabled: false,
                source: ConsentSource::BoxTelemetry
            }
        );
        assert_eq!(
            Consent::resolve(directory.path(), invalid("DO_NOT_TRACK")).source,
            ConsentSource::Default
        );
    }

    #[test]
    fn do_not_track_turns_telemetry_off_only_for_one_or_true() {
        let directory = tempfile::tempdir().unwrap();
        for value in ["1", "true", "TRUE"] {
            assert_eq!(
                resolve(directory.path(), &[("DO_NOT_TRACK", value)]),
                Consent {
                    enabled: false,
                    source: ConsentSource::DoNotTrack
                },
                "{value}"
            );
        }
        for value in ["0", "", "no"] {
            assert_eq!(
                resolve(directory.path(), &[("DO_NOT_TRACK", value)]).source,
                ConsentSource::Default,
                "{value}"
            );
        }
    }

    #[test]
    fn the_saved_choice_applies_and_unreadable_metadata_turns_telemetry_off() {
        let directory = tempfile::tempdir().unwrap();
        save_telemetry_choice(directory.path(), false).unwrap();
        assert_eq!(
            resolve(directory.path(), &[]),
            Consent {
                enabled: false,
                source: ConsentSource::Saved
            }
        );
        save_telemetry_choice(directory.path(), true).unwrap();
        assert!(resolve(directory.path(), &[]).enabled);
        std::fs::write(
            directory.path().join("installation.toml"),
            "telemetry = \"maybe\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve(directory.path(), &[]),
            Consent {
                enabled: false,
                source: ConsentSource::Unreadable
            }
        );
    }
}
