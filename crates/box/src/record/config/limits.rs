//! Operator-selected execution limits for hosted interpreters.

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub(crate) const DEFAULT_SHELL_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_PYTHON_TIMEOUT: Duration = Duration::from_secs(120);

/// The time the broker leaves for Shell to report a timeout and release its work.
pub(crate) const SHELL_TIMEOUT_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    #[serde(default, skip_serializing_if = "InterpreterLimits::is_default")]
    pub(crate) shell: InterpreterLimits,
    #[serde(default, skip_serializing_if = "InterpreterLimits::is_default")]
    pub(crate) python: InterpreterLimits,
}

impl Limits {
    pub(crate) fn shell_timeout(&self) -> Option<Duration> {
        self.shell.timeout(DEFAULT_SHELL_TIMEOUT)
    }

    pub(crate) fn python_timeout(&self) -> Option<Duration> {
        self.python.timeout(DEFAULT_PYTHON_TIMEOUT)
    }

    pub(super) fn is_default(&self) -> bool {
        self.shell.is_default() && self.python.is_default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterpreterLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout: Option<ExecutionTimeout>,
}

impl InterpreterLimits {
    fn timeout(&self, default: Duration) -> Option<Duration> {
        match self.timeout {
            None => Some(default),
            Some(ExecutionTimeout::Seconds(seconds)) => Some(Duration::from_secs(seconds.get())),
            Some(ExecutionTimeout::Disabled) => None,
        }
    }

    pub(super) fn is_default(&self) -> bool {
        self.timeout.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionTimeout {
    Seconds(NonZeroU64),
    Disabled,
}

impl Serialize for ExecutionTimeout {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(seconds.get()),
            Self::Disabled => serializer.serialize_bool(false),
        }
    }
}

impl<'de> Deserialize<'de> for ExecutionTimeout {
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
                    "timeout must be a positive integer number of seconds or false",
                ));
            }
        };
        if Duration::from_secs(seconds.get())
            .checked_add(SHELL_TIMEOUT_GRACE)
            .and_then(|duration| Instant::now().checked_add(duration))
            .is_none()
        {
            return Err(D::Error::custom(
                "timeout is too large for this platform's clock",
            ));
        }
        Ok(Self::Seconds(seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_timeouts_use_the_interpreter_defaults() {
        for text in ["", "[shell]\n", "[python]\n", "[shell]\n[python]\n"] {
            let limits: Limits = toml::from_str(text).unwrap();
            assert_eq!(limits.shell_timeout(), Some(Duration::from_secs(30)));
            assert_eq!(limits.python_timeout(), Some(Duration::from_secs(120)));
            assert!(limits.is_default());
            assert_eq!(toml::to_string(&limits).unwrap(), "");
        }
    }

    #[test]
    fn a_timeout_is_a_positive_integer_number_of_seconds() {
        for interpreter in ["shell", "python"] {
            for seconds in [1, 30, 600, 86_400] {
                let text = format!("[{interpreter}]\ntimeout = {seconds}\n");
                let limits: Limits = toml::from_str(&text).unwrap();
                let (selected, other, default) = if interpreter == "shell" {
                    (
                        limits.shell_timeout(),
                        limits.python_timeout(),
                        DEFAULT_PYTHON_TIMEOUT,
                    )
                } else {
                    (
                        limits.python_timeout(),
                        limits.shell_timeout(),
                        DEFAULT_SHELL_TIMEOUT,
                    )
                };
                assert_eq!(selected, Some(Duration::from_secs(seconds)));
                assert_eq!(other, Some(default));
                assert!(!limits.is_default());
                assert_eq!(toml::to_string(&limits).unwrap(), text);
            }
        }
    }

    #[test]
    fn false_disables_the_timeout_and_survives_serialization() {
        for interpreter in ["shell", "python"] {
            let text = format!("[{interpreter}]\ntimeout = false\n");
            let limits: Limits = toml::from_str(&text).unwrap();
            if interpreter == "shell" {
                assert_eq!(limits.shell_timeout(), None);
                assert_eq!(limits.python_timeout(), Some(DEFAULT_PYTHON_TIMEOUT));
            } else {
                assert_eq!(limits.python_timeout(), None);
                assert_eq!(limits.shell_timeout(), Some(DEFAULT_SHELL_TIMEOUT));
            }
            assert!(!limits.is_default());
            let serialized = toml::to_string(&limits).unwrap();
            assert_eq!(serialized, text);
            assert_eq!(toml::from_str::<Limits>(&serialized).unwrap(), limits);
        }
    }

    #[test]
    fn invalid_or_unrepresentable_timeouts_are_refused() {
        for interpreter in ["shell", "python"] {
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
                    toml::from_str::<Limits>(&format!("[{interpreter}]\ntimeout = {value}\n"))
                        .is_err(),
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn unknown_limit_names_are_refused() {
        for text in [
            "timeout = 60",
            "[ruby]\ntimeout = 60",
            "[shell]\ntimout = 60",
            "[python]\ntimout = 60",
        ] {
            assert!(toml::from_str::<Limits>(text).is_err(), "{text}");
        }
    }
}
