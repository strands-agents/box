//! Operator-selected execution limits for hosted interpreters.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout: Option<ShellTimeout>,
}

impl ShellLimits {
    pub(crate) fn timeout(&self) -> Option<Duration> {
        match self.timeout {
            None => Some(DEFAULT_SHELL_TIMEOUT),
            Some(ShellTimeout::Seconds(seconds)) => Some(Duration::from_secs(seconds.get())),
            Some(ShellTimeout::Disabled) => None,
        }
    }

    fn is_default(&self) -> bool {
        self.timeout.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellTimeout {
    Seconds(NonZeroU64),
    Disabled,
}

impl Serialize for ShellTimeout {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(seconds.get()),
            Self::Disabled => serializer.serialize_bool(false),
        }
    }
}

impl<'de> Deserialize<'de> for ShellTimeout {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(
            untagged,
            expecting = "a positive integer number of seconds or false to disable the timeout"
        )]
        enum TimeoutValue {
            Seconds(NonZeroU64),
            Disabled(bool),
        }

        let seconds = match TimeoutValue::deserialize(deserializer)? {
            TimeoutValue::Seconds(seconds) => seconds,
            TimeoutValue::Disabled(false) => return Ok(Self::Disabled),
            TimeoutValue::Disabled(true) => {
                return Err(D::Error::custom(
                    "limits.shell.timeout must be a positive integer number of seconds or false",
                ));
            }
        };
        if Duration::from_secs(seconds.get())
            .checked_add(SHELL_TIMEOUT_GRACE)
            .and_then(|duration| Instant::now().checked_add(duration))
            .is_none()
        {
            return Err(D::Error::custom(
                "limits.shell.timeout is too large for this platform's clock",
            ));
        }
        Ok(Self::Seconds(seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_omitted_timeout_preserves_thirty_seconds() {
        for text in ["", "[shell]\n"] {
            let limits: Limits = toml::from_str(text).unwrap();
            assert_eq!(limits.shell.timeout(), Some(Duration::from_secs(30)));
            assert!(limits.is_default());
            assert_eq!(toml::to_string(&limits).unwrap(), "");
        }
    }

    #[test]
    fn a_timeout_is_a_positive_integer_number_of_seconds() {
        for seconds in [1, 30, 600, 86_400] {
            let limits: Limits =
                toml::from_str(&format!("[shell]\ntimeout = {seconds}\n")).unwrap();
            assert_eq!(limits.shell.timeout(), Some(Duration::from_secs(seconds)));
            assert!(!limits.is_default());
            assert_eq!(
                toml::to_string(&limits).unwrap(),
                format!("[shell]\ntimeout = {seconds}\n")
            );
        }
    }

    #[test]
    fn false_disables_the_timeout_and_survives_serialization() {
        let limits: Limits = toml::from_str("[shell]\ntimeout = false\n").unwrap();
        assert_eq!(limits.shell.timeout(), None);
        assert!(!limits.is_default());
        let serialized = toml::to_string(&limits).unwrap();
        assert_eq!(serialized, "[shell]\ntimeout = false\n");
        assert_eq!(toml::from_str::<Limits>(&serialized).unwrap(), limits);
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
