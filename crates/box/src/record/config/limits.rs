//! Operator-selected execution limits for hosted interpreters, and the box workload's resource caps.

use std::num::{NonZeroU64, NonZeroUsize};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub(crate) const DEFAULT_SHELL_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_SHELL_MAX_INPUT: usize = 256 * 1024;
pub(crate) const DEFAULT_SHELL_MAX_OUTPUT: usize = 1024 * 1024;
pub(crate) const DEFAULT_SHELL_MAX_STDIN: usize = 1024 * 1024;

/// The time the broker leaves for Shell to report a timeout and release its work.
pub(crate) const SHELL_TIMEOUT_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    #[serde(default, skip_serializing_if = "ShellLimits::is_default")]
    pub(crate) shell: ShellLimits,
    /// The most processes and threads the box's workload may hold at once.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "positive_processes"
    )]
    processes: Option<NonZeroU64>,
    /// The most memory, in bytes, the box's workload may use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryBytes>,
}

impl Limits {
    pub(super) fn is_default(&self) -> bool {
        self.shell.is_default() && !self.has_resource_limits()
    }

    /// The workload's caps, when the operator set either.
    pub(crate) fn resources(&self) -> Option<ResourceLimits> {
        self.has_resource_limits().then(|| ResourceLimits {
            processes: self.processes,
            memory: self.memory.map(|memory| memory.0),
        })
    }

    pub(super) fn has_resource_limits(&self) -> bool {
        self.processes.is_some() || self.memory.is_some()
    }

    /// Refuse a resource cap on a platform that cannot enforce one.
    pub(super) fn validate_platform(&self) -> Result<(), crate::error::ConfigError> {
        refuse_off_linux(self, cfg!(target_os = "linux"))
    }
}

/// The caps one box's workload runs under: the agent, its tools, and its MCP servers together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceLimits {
    pub(crate) processes: Option<NonZeroU64>,
    pub(crate) memory: Option<NonZeroU64>,
}

impl ResourceLimits {
    /// The keys set, as `[limits]` spells them.
    pub(crate) fn keys(&self) -> &'static str {
        match (self.processes.is_some(), self.memory.is_some()) {
            (true, true) => "`limits.processes` and `limits.memory`",
            (true, false) => "`limits.processes`",
            (false, _) => "`limits.memory`",
        }
    }

    /// The caps, as the startup disclosure prints them.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn summary(&self) -> String {
        let processes = self.processes.map(|count| format!("processes {count}"));
        let memory = self
            .memory
            .map(|bytes| format!("memory {}", format_bytes(bytes.get())));
        [processes, memory]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn refuse_off_linux(limits: &Limits, linux: bool) -> Result<(), crate::error::ConfigError> {
    match limits.resources() {
        Some(resources) if !linux => Err(crate::error::ConfigError::ResourceLimitsUnsupported {
            keys: resources.keys(),
        }),
        _ => Ok(()),
    }
}

/// The most processes and threads Linux numbers at once (`PID_MAX_LIMIT` on 64-bit kernels).
const MOST_PROCESSES: u64 = 4_194_304;

fn positive_processes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NonZeroU64>, D::Error> {
    let expected = || {
        D::Error::custom(format!(
            "limits.processes must be a positive integer number of processes, at most \
             {MOST_PROCESSES}"
        ))
    };
    let count = u64::deserialize(deserializer).map_err(|_| expected())?;
    NonZeroU64::new(count)
        .filter(|count| count.get() <= MOST_PROCESSES)
        .map(Some)
        .ok_or_else(expected)
}

/// A memory cap: an integer number of bytes, or a string such as `"512M"` or `"8G"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryBytes(NonZeroU64);

const MEMORY_EXPECTED: &str = "limits.memory must be a positive number of bytes, or a string such as \"512M\" or \"8G\" \
     (K, M, G, and T are powers of 1024)";

impl Serialize for MemoryBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.get())
    }
}

impl<'de> Deserialize<'de> for MemoryBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum MemoryValue {
            Bytes(u64),
            Text(String),
        }

        let bytes = match MemoryValue::deserialize(deserializer)
            .map_err(|_| D::Error::custom(MEMORY_EXPECTED))?
        {
            MemoryValue::Bytes(bytes) => Some(bytes),
            MemoryValue::Text(text) => parse_memory(&text),
        };
        bytes
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or_else(|| D::Error::custom(MEMORY_EXPECTED))
    }
}

/// `<digits><unit>`, where the unit is `K`, `M`, `G`, or `T` and each is a power of 1024.
fn parse_memory(text: &str) -> Option<u64> {
    let digits = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(digits);
    let power = match unit {
        "" => 0,
        "K" => 1,
        "M" => 2,
        "G" => 3,
        "T" => 4,
        _ => return None,
    };
    number.parse::<u64>().ok()?.checked_mul(1024_u64.pow(power))
}

/// A byte count in the largest whole power-of-1024 unit that divides it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn format_bytes(bytes: u64) -> String {
    for (power, unit) in [(4, "T"), (3, "G"), (2, "M"), (1, "K")] {
        let scale = 1024_u64.pow(power);
        if bytes.is_multiple_of(scale) {
            return format!("{}{unit}", bytes / scale);
        }
    }
    format!("{bytes} bytes")
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
            assert_eq!(limits.shell.max_output(), 1048576);
            assert_eq!(limits.shell.max_stdin(), 1048576);
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
            assert_eq!(limits.shell.max_output(), 1048576);
            assert_eq!(limits.shell.max_stdin(), 1048576);
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
            "pids = 64",
            "[processes]\nmax = 64",
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
                    .map_or(1048576, |value| value.as_integer().unwrap() as usize)
            );
        }
    }

    #[test]
    fn resource_limits_are_absent_unless_a_key_sets_one() {
        let limits: Limits = toml::from_str("[shell]\ntimeout = 60\n").unwrap();
        assert_eq!(limits.resources(), None);
        assert!(toml::from_str::<Limits>("processes = 4194304\n").is_ok());
        let limits: Limits = toml::from_str("processes = 4096\n").unwrap();
        assert!(!limits.is_default());
        assert_eq!(
            limits.resources().unwrap().processes.map(NonZeroU64::get),
            Some(4096)
        );
        assert_eq!(limits.resources().unwrap().memory, None);
    }

    #[test]
    fn memory_accepts_bytes_or_a_power_of_1024_unit_and_stores_bytes() {
        for (value, bytes, summary) in [
            ("1048576", 1_048_576, "memory 1M"),
            ("\"512M\"", 512 << 20, "memory 512M"),
            ("\"8G\"", 8 << 30, "memory 8G"),
            ("\"1T\"", 1 << 40, "memory 1T"),
            ("\"3K\"", 3 << 10, "memory 3K"),
            ("1000", 1000, "memory 1000 bytes"),
        ] {
            let limits: Limits = toml::from_str(&format!("memory = {value}\n")).unwrap();
            let resources = limits.resources().unwrap();
            assert_eq!(
                resources.memory.map(NonZeroU64::get),
                Some(bytes),
                "{value}"
            );
            assert_eq!(resources.summary(), summary, "{value}");
            let stored = toml::to_string(&limits).unwrap();
            assert_eq!(stored, format!("memory = {bytes}\n"), "{value}");
            assert_eq!(toml::from_str::<Limits>(&stored).unwrap(), limits);
        }
    }

    #[test]
    fn invalid_resource_limits_are_refused_with_the_expected_form() {
        for text in [
            "processes = 0",
            "processes = -1",
            "processes = 1.5",
            "processes = \"4096\"",
            "processes = true",
            "processes = 4194305",
            "memory = 0",
            "memory = -1",
            "memory = \"0G\"",
            "memory = \"1.5G\"",
            "memory = \"8GB\"",
            "memory = \"8g\"",
            "memory = \" 8G\"",
            "memory = \"G\"",
            "memory = \"\"",
            "memory = \"99999999999T\"",
            "memory = true",
        ] {
            let error = toml::from_str::<Limits>(text).expect_err(text).to_string();
            let key = text.split(' ').next().unwrap();
            assert!(
                error.contains(&format!("limits.{key} must be")),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn a_resource_limit_is_refused_off_linux_and_names_its_keys() {
        for (text, keys) in [
            ("processes = 64\n", "`limits.processes`"),
            ("memory = \"1G\"\n", "`limits.memory`"),
            (
                "processes = 64\nmemory = \"1G\"\n",
                "`limits.processes` and `limits.memory`",
            ),
        ] {
            let limits: Limits = toml::from_str(text).unwrap();
            assert!(refuse_off_linux(&limits, true).is_ok(), "{text}");
            let refusal = refuse_off_linux(&limits, false)
                .expect_err(text)
                .to_string();
            assert!(refusal.contains(keys), "{refusal}");
            assert!(refusal.contains("Linux only"), "{refusal}");
        }
        let shell_only: Limits = toml::from_str("[shell]\ntimeout = 60\n").unwrap();
        assert!(refuse_off_linux(&shell_only, false).is_ok());
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
