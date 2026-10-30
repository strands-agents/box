//! Argument parsing for `strands-box-contain-trampoline` — pure, I/O-free, and platform-agnostic,
//! so it is unit-tested on every target (the containment itself is unix-only).

use std::path::PathBuf;

/// A fully-parsed, validated invocation.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Args {
    /// Private channel that holds the workload until its parent completes launch setup.
    pub(super) launch_gate_fd: Option<i32>,
    pub(super) container_lifetime_fd: Option<i32>,
    /// Path to serialized [`containment::ContainmentConfig`] JSON.
    pub(super) config: PathBuf,
    /// Optional inherited descriptor for the serialized config.
    pub(super) config_fd: Option<i32>,
    /// Expected SHA-256 digest of the serialized config bytes.
    pub(super) config_sha256: [u8; 32],
    /// Serialized target environment, kept inert until containment succeeds.
    pub(super) target_env_json: String,
    /// Optional inherited descriptor for compact pre-exec failure reporting.
    pub(super) setup_status_fd: Option<i32>,
    /// Optional inherited socket for returning the workload's egress listener.
    pub(super) relay_control_fd: Option<i32>,
    /// The command to contain-then-`exec`; `command[0]` is the program, the rest
    /// its args. Guaranteed non-empty.
    pub(super) command: Vec<String>,
    /// What the program reads as `argv[0]`, when it differs from `command[0]`.
    pub(super) argv0: Option<String>,
}

/// Why parsing did not yield [`Args`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParseError {
    /// `--help`/`-h` was requested; the caller prints usage and exits.
    HelpRequested,
    /// A genuine usage error, with a human-readable reason.
    Invalid(String),
}

impl Args {
    /// Parse an argv iterator (already skipping `argv[0]`).
    pub(super) fn parse(argv: impl IntoIterator<Item = String>) -> Result<Self, ParseError> {
        let mut launch_gate_fd = None;
        let mut container_lifetime_fd = None;
        let mut config = None;
        let mut config_fd = None;
        let mut config_sha256 = None;
        let mut target_env_json = None;
        let mut setup_status_fd = None;
        let mut relay_control_fd = None;
        let mut argv0 = None;
        let mut command = Vec::new();
        let mut argv = argv.into_iter();

        while let Some(flag) = argv.next() {
            match flag.as_str() {
                "--" => {
                    command.extend(argv.by_ref());
                    break;
                }
                "--help" | "-h" => return Err(ParseError::HelpRequested),
                "--container-lifetime-fd" => {
                    let value = take_value(&mut argv, "--container-lifetime-fd")?;
                    let descriptor = value.parse::<i32>().map_err(|_| {
                        ParseError::Invalid("invalid container lifetime descriptor".into())
                    })?;
                    if descriptor <= 2 {
                        return Err(ParseError::Invalid(
                            "container lifetime must not use standard streams".into(),
                        ));
                    }
                    set_once(
                        &mut container_lifetime_fd,
                        descriptor,
                        "--container-lifetime-fd",
                    )?;
                }
                "--config" => {
                    set_once(
                        &mut config,
                        PathBuf::from(take_value(&mut argv, "--config")?),
                        "--config",
                    )?;
                }
                "--config-sha256" => {
                    let value = take_value(&mut argv, "--config-sha256")?;
                    set_once(&mut config_sha256, parse_sha256(&value)?, "--config-sha256")?;
                }
                "--config-fd" => {
                    let value = take_value(&mut argv, "--config-fd")?;
                    let descriptor = value.parse::<i32>().map_err(|_| {
                        ParseError::Invalid(
                            "--config-fd must be a decimal file descriptor".to_string(),
                        )
                    })?;
                    if descriptor <= 2 {
                        return Err(ParseError::Invalid(
                            "--config-fd must not collide with stdin/stdout/stderr".to_string(),
                        ));
                    }
                    set_once(&mut config_fd, descriptor, "--config-fd")?;
                }
                "--target-env-json" => {
                    let value = take_value(&mut argv, "--target-env-json")?;
                    set_once(&mut target_env_json, value, "--target-env-json")?;
                }
                "--argv0" => {
                    let value = take_value(&mut argv, "--argv0")?;
                    set_once(&mut argv0, value, "--argv0")?;
                }
                "--setup-status-fd" => {
                    let value = take_value(&mut argv, "--setup-status-fd")?;
                    let descriptor = value.parse::<i32>().map_err(|_| {
                        ParseError::Invalid(
                            "--setup-status-fd must be a decimal file descriptor".to_string(),
                        )
                    })?;
                    if descriptor <= 2 {
                        return Err(ParseError::Invalid(
                            "--setup-status-fd must not collide with stdin/stdout/stderr"
                                .to_string(),
                        ));
                    }
                    set_once(&mut setup_status_fd, descriptor, "--setup-status-fd")?;
                }
                "--launch-gate-fd" => {
                    let value = take_value(&mut argv, "--launch-gate-fd")?;
                    let descriptor = value.parse::<i32>().map_err(|_| {
                        ParseError::Invalid("invalid launch gate descriptor".into())
                    })?;
                    if descriptor <= 2 {
                        return Err(ParseError::Invalid(
                            "launch gate must not use standard streams".into(),
                        ));
                    }
                    set_once(&mut launch_gate_fd, descriptor, "--launch-gate-fd")?;
                }
                "--relay-control-fd" => {
                    let value = take_value(&mut argv, "--relay-control-fd")?;
                    let descriptor = value.parse::<i32>().map_err(|_| {
                        ParseError::Invalid(
                            "--relay-control-fd must be a decimal file descriptor".to_string(),
                        )
                    })?;
                    if descriptor <= 2 {
                        return Err(ParseError::Invalid(
                            "--relay-control-fd must not collide with stdin/stdout/stderr"
                                .to_string(),
                        ));
                    }
                    set_once(&mut relay_control_fd, descriptor, "--relay-control-fd")?;
                }
                other => {
                    return Err(ParseError::Invalid(format!(
                        "unknown flag {other:?} (did you forget `--` before the command?)"
                    )));
                }
            }
        }

        if command.is_empty() {
            return Err(ParseError::Invalid(
                "missing command after `--` (the program to contain)".to_string(),
            ));
        }
        let config =
            config.ok_or_else(|| ParseError::Invalid("--config is required".to_string()))?;
        let config_sha256 = config_sha256
            .ok_or_else(|| ParseError::Invalid("--config-sha256 is required".to_string()))?;
        let target_env_json = target_env_json
            .ok_or_else(|| ParseError::Invalid("--target-env-json is required".to_string()))?;
        Ok(Args {
            launch_gate_fd,
            container_lifetime_fd,
            config,
            config_fd,
            config_sha256,
            target_env_json,
            setup_status_fd,
            relay_control_fd,
            command,
            argv0,
        })
    }
}

/// Take the next argv item as a flag's value, or an error naming the flag.
fn take_value(argv: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, ParseError> {
    argv.next()
        .ok_or_else(|| ParseError::Invalid(format!("missing value for {flag}")))
}

/// Set a required option exactly once.
fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::Invalid(format!(
            "{flag} specified more than once"
        )));
    }
    *slot = Some(value);
    Ok(())
}

/// Parse exactly 64 lowercase hexadecimal characters as a SHA-256 digest.
fn parse_sha256(value: &str) -> Result<[u8; 32], ParseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ParseError::Invalid(
            "--config-sha256 must be exactly 64 lowercase hexadecimal characters".to_string(),
        ));
    }

    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    Ok(digest)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("parse_sha256 validates every byte"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parse(args: &[&str]) -> Result<Args, ParseError> {
        Args::parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_a_well_formed_invocation() {
        let a = parse(&[
            "--config",
            "c.json",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            r#"{"A":"b"}"#,
            "--",
            "python3",
            "h.py",
        ])
        .expect("valid");
        assert_eq!(a.config, PathBuf::from("c.json"));
        assert_eq!(a.config_fd, None);
        assert_eq!(
            a.config_sha256,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ]
        );
        assert_eq!(a.target_env_json, r#"{"A":"b"}"#);
        assert_eq!(a.setup_status_fd, None);
        assert_eq!(a.command, vec!["python3".to_string(), "h.py".to_string()]);
        assert_eq!(a.argv0, None);
    }

    #[test]
    fn parses_argument_zero_beside_the_command() {
        let a = parse(&[
            "--config",
            "c.json",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            "{}",
            "--argv0",
            "/proj/.venv/bin/python",
            "--",
            "/usr/bin/python3.9",
            "-c",
            "pass",
        ])
        .expect("valid");
        assert_eq!(a.argv0.as_deref(), Some("/proj/.venv/bin/python"));
        assert_eq!(a.command[0], "/usr/bin/python3.9");
    }

    #[test]
    fn parses_setup_status_descriptor() {
        let a = parse(&[
            "--config",
            "c.json",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            "{}",
            "--setup-status-fd",
            "9",
            "--",
            "node",
        ])
        .expect("valid");

        assert_eq!(a.setup_status_fd, Some(9));
    }

    #[test]
    fn parses_config_descriptor() {
        let a = parse(&[
            "--config",
            "c.json",
            "--config-fd",
            "8",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            "{}",
            "--",
            "node",
        ])
        .expect("valid");

        assert_eq!(a.config_fd, Some(8));
    }

    #[test]
    fn setup_status_descriptor_cannot_collide_with_stdio() {
        assert!(matches!(
            parse(&[
                "--config",
                "c.json",
                "--config-sha256",
                DIGEST,
                "--target-env-json",
                "{}",
                "--setup-status-fd",
                "2",
                "--",
                "node",
            ]),
            Err(ParseError::Invalid(message)) if message.contains("stdin/stdout/stderr")
        ));
    }

    #[test]
    fn parses_one_word_command() {
        let a = parse(&[
            "--target-env-json",
            "{}",
            "--config-sha256",
            DIGEST,
            "--config",
            "c.json",
            "--",
            "node",
        ])
        .expect("valid");
        assert_eq!(a.config, PathBuf::from("c.json"));
        assert_eq!(a.command, vec!["node".to_string()]);
    }

    #[test]
    fn everything_after_dashdash_is_the_command_verbatim() {
        // The command may carry tokens that look like our own flags — they must
        // pass through untouched, never re-interpreted.
        let a = parse(&[
            "--config",
            "c.json",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            "{}",
            "--",
            "node",
            "--config-sha256",
            "--target-env-json",
            "--help",
        ])
        .expect("valid");
        assert_eq!(
            a.command,
            vec![
                "node".to_string(),
                "--config-sha256".to_string(),
                "--target-env-json".to_string(),
                "--help".to_string(),
            ]
        );
    }

    #[test]
    fn help_short_circuits() {
        assert_eq!(parse(&["--help"]), Err(ParseError::HelpRequested));
        assert_eq!(
            parse(&["--config", "c", "-h", "--", "x"]),
            Err(ParseError::HelpRequested)
        );
    }

    #[test]
    fn missing_command_is_invalid() {
        assert!(matches!(
            parse(&[
                "--config",
                "c.json",
                "--config-sha256",
                DIGEST,
                "--target-env-json",
                "{}"
            ]),
            Err(ParseError::Invalid(_))
        ));
        // `--` with nothing after it is still an empty command.
        assert!(matches!(
            parse(&[
                "--config",
                "s.json",
                "--config-sha256",
                DIGEST,
                "--target-env-json",
                "{}",
                "--"
            ]),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn missing_required_flags_are_invalid() {
        assert!(matches!(
            parse(&["--", "x"]),
            Err(ParseError::Invalid(m)) if m.contains("--config")
        ));
        assert!(matches!(
            parse(&["--config", "c", "--", "x"]),
            Err(ParseError::Invalid(m)) if m.contains("--config-sha256")
        ));
        assert!(matches!(
            parse(&[
                "--config",
                "c",
                "--config-sha256",
                DIGEST,
                "--",
                "x"
            ]),
            Err(ParseError::Invalid(m)) if m.contains("--target-env-json")
        ));
    }

    #[test]
    fn missing_flag_value_is_invalid() {
        assert!(matches!(
            parse(&["--config"]),
            Err(ParseError::Invalid(m)) if m.contains("--config")
        ));
        assert!(matches!(
            parse(&["--config-sha256"]),
            Err(ParseError::Invalid(m)) if m.contains("--config-sha256")
        ));
        assert!(matches!(
            parse(&["--target-env-json"]),
            Err(ParseError::Invalid(m)) if m.contains("--target-env-json")
        ));
    }

    #[test]
    fn unknown_flag_before_dashdash_is_invalid() {
        assert!(matches!(
            parse(&["--bogus", "--config", "c", "--", "x"]),
            Err(ParseError::Invalid(m)) if m.contains("--bogus")
        ));
    }

    #[test]
    fn malformed_or_uppercase_digest_is_invalid() {
        for digest in [
            "",
            "00",
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "00123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(matches!(
                parse(&[
                    "--config",
                    "c",
                    "--config-sha256",
                    digest,
                    "--target-env-json",
                    "{}",
                    "--",
                    "x"
                ]),
                Err(ParseError::Invalid(m)) if m.contains("64 lowercase hexadecimal")
            ));
        }
    }

    #[test]
    fn duplicate_required_option_is_invalid() {
        assert!(matches!(
            parse(&[
                "--config",
                "a",
                "--config",
                "b",
                "--config-sha256",
                DIGEST,
                "--target-env-json",
                "{}",
                "--",
                "x"
            ]),
            Err(ParseError::Invalid(m)) if m.contains("--config specified more than once")
        ));
    }

    /// `--relay-control-fd` parses once, and a stdio descriptor or a second flag is refused.
    #[test]
    fn relay_control_fd_parses_and_refuses_collisions() {
        let invocation = |relay: &[&str]| {
            let mut argv = vec![
                "--config",
                "c.json",
                "--config-sha256",
                DIGEST,
                "--target-env-json",
                "{}",
            ];
            argv.extend_from_slice(relay);
            argv.extend_from_slice(&["--", "node"]);
            parse(&argv)
        };
        let a = invocation(&["--relay-control-fd", "7"]).expect("valid");
        assert_eq!(a.relay_control_fd, Some(7));

        for stdio in ["0", "1", "2"] {
            assert!(
                matches!(
                    invocation(&["--relay-control-fd", stdio]),
                    Err(ParseError::Invalid(message))
                        if message.contains("--relay-control-fd must not collide with stdin/stdout/stderr")
                ),
                "descriptor {stdio} is refused"
            );
        }
        assert!(matches!(
            invocation(&["--relay-control-fd", "7", "--relay-control-fd", "8"]),
            Err(ParseError::Invalid(message))
                if message.contains("--relay-control-fd specified more than once")
        ));
    }

    #[test]
    fn every_descriptor_flag_refuses_standard_streams_and_invalid_numbers() {
        for flag in [
            "--config-fd",
            "--setup-status-fd",
            "--launch-gate-fd",
            "--relay-control-fd",
        ] {
            for value in ["-1", "0", "1", "2", "2147483648", "not-a-number"] {
                let error = parse(&[
                    "--config",
                    "c.json",
                    "--config-sha256",
                    DIGEST,
                    "--target-env-json",
                    "{}",
                    flag,
                    value,
                    "--",
                    "program",
                ])
                .unwrap_err();
                let expected = if flag == "--launch-gate-fd" {
                    if ["-1", "0", "1", "2"].contains(&value) {
                        "launch gate must not use standard streams".to_owned()
                    } else {
                        "invalid launch gate descriptor".to_owned()
                    }
                } else if ["-1", "0", "1", "2"].contains(&value) {
                    format!("{flag} must not collide with stdin/stdout/stderr")
                } else {
                    format!("{flag} must be a decimal file descriptor")
                };
                assert_eq!(error, ParseError::Invalid(expected), "{flag} {value}");
            }
            assert!(
                matches!(parse(&[flag]), Err(ParseError::Invalid(message)) if message.contains(flag)),
                "{flag} needs a value"
            );
        }
    }

    #[test]
    fn launch_gate_is_retained_and_cannot_be_declared_twice() {
        let mut argv = vec![
            "--config",
            "c.json",
            "--config-sha256",
            DIGEST,
            "--target-env-json",
            "{}",
            "--launch-gate-fd",
            "3",
        ];
        let mut valid = argv.clone();
        valid.extend(["--", "program"]);
        assert_eq!(parse(&valid).unwrap().launch_gate_fd, Some(3));
        argv.extend(["--launch-gate-fd", "4", "--", "program"]);
        assert!(
            matches!(parse(&argv), Err(ParseError::Invalid(message)) if message.contains("more than once"))
        );
    }

    #[test]
    fn every_value_flag_reports_a_missing_value() {
        for flag in [
            "--config",
            "--config-sha256",
            "--target-env-json",
            "--argv0",
        ] {
            assert!(
                matches!(parse(&[flag]), Err(ParseError::Invalid(message)) if message.contains(flag)),
                "{flag}"
            );
        }
    }

    #[test]
    fn incomplete_required_fields_name_the_missing_field() {
        for (argv, expected) in [
            (vec!["--", "program"], "--config"),
            (
                vec!["--config", "c.json", "--", "program"],
                "--config-sha256",
            ),
            (
                vec![
                    "--config",
                    "c.json",
                    "--config-sha256",
                    DIGEST,
                    "--",
                    "program",
                ],
                "--target-env-json",
            ),
        ] {
            assert!(
                matches!(parse(&argv), Err(ParseError::Invalid(message)) if message.contains(expected)),
                "{expected}"
            );
        }
    }

    #[test]
    fn digest_rejects_uppercase_nonhex_and_multibyte_input() {
        for value in ["A".repeat(64), "g".repeat(64), "é".repeat(32)] {
            assert!(
                matches!(parse_sha256(&value), Err(ParseError::Invalid(message)) if message.contains("lowercase hexadecimal"))
            );
        }
    }
}
