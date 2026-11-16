//! Operator-selected execution limits for hosted interpreters.

use std::num::{NonZeroU64, NonZeroUsize};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub(crate) const DEFAULT_SHELL_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_SHELL_MAX_INPUT: usize = 256 * 1024;
pub(crate) const DEFAULT_SHELL_MAX_OUTPUT: usize = 64 * 1024;
pub(crate) const DEFAULT_SHELL_MAX_STDIN: usize = 64 * 1024;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_input: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_output: Option<usize>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "positive_bytes"
    )]
    max_stdin: Option<NonZeroUsize>,
}

impl ShellLimits {
    pub(crate) fn max_input(&self) -> usize {
        self.max_input.unwrap_or(DEFAULT_SHELL_MAX_INPUT)
    }

    pub(crate) fn max_output(&self) -> usize {
        self.max_output.unwrap_or(DEFAULT_SHELL_MAX_OUTPUT)
    }

    pub(crate) fn max_stdin(&self) -> usize {
        self.max_stdin
            .map_or(DEFAULT_SHELL_MAX_STDIN, NonZeroUsize::get)
    }

    pub(super) fn has_stdin_limit(&self) -> bool {
        self.max_stdin.is_some()
    }

    pub(super) fn has_size_limits(&self) -> bool {
        self.max_input.is_some() || self.max_output.is_some() || self.max_stdin.is_some()
    }

    pub(crate) fn timeout(&self) -> Option<Duration> {
        match self.timeout {
            None => Some(DEFAULT_SHELL_TIMEOUT),
            Some(ShellTimeout::Seconds(seconds)) => Some(Duration::from_secs(seconds.get())),
            Some(ShellTimeout::Disabled) => None,
        }
    }

    fn is_default(&self) -> bool {
        self.timeout.is_none() && !self.has_size_limits()
    }
}

fn positive_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NonZeroUsize>, D::Error> {
    let bytes = usize::deserialize(deserializer)?;
    NonZeroUsize::new(bytes).map(Some).ok_or_else(|| {
        D::Error::custom("limits.shell.max_stdin must be a positive integer number of bytes")
    })
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
            assert_eq!(limits.shell.max_input(), 262144);
            assert_eq!(limits.shell.max_output(), 65536);
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
            assert_eq!(limits.shell.max_input(), 262144);
            assert_eq!(limits.shell.max_output(), 65536);
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
    fn max_stdin_is_a_positive_byte_count() {
        let limits: Limits = toml::from_str("[shell]\nmax_stdin = 1048576\n").unwrap();
        assert_eq!(limits.shell.max_stdin(), 1048576);
        assert_eq!(
            toml::from_str::<Limits>(&toml::to_string(&limits).unwrap()).unwrap(),
            limits
        );
        for value in ["0", "-1", "\"64k\"", "true", "1.5"] {
            assert!(
                toml::from_str::<Limits>(&format!("[shell]\nmax_stdin = {value}\n")).is_err(),
                "{value}"
            );
        }
        let zero = toml::from_str::<Limits>("[shell]\nmax_stdin = 0\n").unwrap_err();
        assert!(zero.to_string().contains("positive integer"), "{zero}");
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

    #[test]
    fn shell_size_limits_round_trip_independently() {
        for text in [
            "[shell]\nmax_input = 1\n",
            "[shell]\nmax_output = 262144\n",
            "[shell]\nmax_input = 524288\nmax_output = 131072\ntimeout = false\n",
            "[shell]\nmax_input = 0\n",
            "[shell]\nmax_output = 0\n",
            "[shell]\nmax_input = 0\nmax_output = 0\ntimeout = false\n",
        ] {
            let limits: Limits = toml::from_str(text).expect("byte limits");
            assert!(!limits.is_default());
            let actual: toml::Value = toml::from_str(&toml::to_string(&limits).unwrap()).unwrap();
            let expected: toml::Value = toml::from_str(text).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                limits.shell.max_input(),
                expected["shell"]
                    .get("max_input")
                    .map_or(262144, |value| value.as_integer().unwrap() as usize)
            );
            assert_eq!(
                limits.shell.max_output(),
                expected["shell"]
                    .get("max_output")
                    .map_or(65536, |value| value.as_integer().unwrap() as usize)
            );
        }
    }

    #[test]
    fn shell_size_limits_refuse_negative_or_non_integer_bytes() {
        for key in ["max_input", "max_output"] {
            for value in ["-1", "1.5", "\"65536\"", "false", "true", "[]", "{}"] {
                assert!(
                    toml::from_str::<Limits>(&format!("[shell]\n{key} = {value}\n")).is_err(),
                    "{key} = {value}"
                );
            }
        }
    }
}
