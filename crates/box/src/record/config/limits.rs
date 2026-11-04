//! Operator-selected execution limits for hosted interpreters.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub(crate) const DEFAULT_SHELL_TIMEOUT: Duration = Duration::from_secs(30);

/// The time the broker leaves for Shell to report a timeout and release its work.
pub(crate) const SHELL_TIMEOUT_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    #[serde(default, skip_serializing_if = "ShellLimits::is_default")]
    pub(crate) shell: ShellLimits,
}

impl Limits {
    pub(super) fn is_default(&self) -> bool {
        self.shell.is_default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShellLimits {
    #[serde(
        default,
        deserialize_with = "timeout_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    timeout: Option<NonZeroU64>,
}

impl ShellLimits {
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout.map_or(DEFAULT_SHELL_TIMEOUT, |seconds| {
            Duration::from_secs(seconds.get())
        })
    }

    fn is_default(&self) -> bool {
        self.timeout.is_none()
    }
}

fn timeout_seconds<'de, D>(deserializer: D) -> Result<Option<NonZeroU64>, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds = Option::<NonZeroU64>::deserialize(deserializer)?;
    if let Some(seconds) = seconds {
        let duration = Duration::from_secs(seconds.get());
        if duration
            .checked_add(SHELL_TIMEOUT_GRACE)
            .and_then(|duration| Instant::now().checked_add(duration))
            .is_none()
        {
            return Err(D::Error::custom(
                "limits.shell.timeout is too large for this platform's clock",
            ));
        }
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_omitted_timeout_preserves_thirty_seconds() {
        for text in ["", "[shell]\n"] {
            let limits: Limits = toml::from_str(text).unwrap();
            assert_eq!(limits.shell.timeout(), Duration::from_secs(30));
            assert!(limits.is_default());
            assert_eq!(toml::to_string(&limits).unwrap(), "");
        }
    }

    #[test]
    fn a_timeout_is_a_positive_integer_number_of_seconds() {
        for seconds in [1, 30, 600, 86_400] {
            let limits: Limits =
                toml::from_str(&format!("[shell]\ntimeout = {seconds}\n")).unwrap();
            assert_eq!(limits.shell.timeout(), Duration::from_secs(seconds));
            assert!(!limits.is_default());
            assert_eq!(
                toml::to_string(&limits).unwrap(),
                format!("[shell]\ntimeout = {seconds}\n")
            );
        }
    }

    #[test]
    fn invalid_or_unrepresentable_timeouts_are_refused() {
        for value in [
            "0",
            "-1",
            "1.5",
            "\"60s\"",
            "true",
            "9223372036854775807",
            "18446744073709551616",
        ] {
            assert!(
                toml::from_str::<Limits>(&format!("[shell]\ntimeout = {value}\n")).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn unknown_limit_names_are_refused() {
        for text in [
            "timeout = 60",
            "[python]\ntimeout = 60",
            "[shell]\ntimout = 60",
        ] {
            assert!(toml::from_str::<Limits>(text).is_err(), "{text}");
        }
    }
}
