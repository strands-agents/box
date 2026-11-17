//! Tests of the command source, each against a stand-in program: a shell script in a temp dir.

use std::path::PathBuf;
use std::sync::Arc;

use super::*;
use crate::Backend;

/// The shell that runs each stand-in program.
const SHELL: &str = "/bin/sh";

/// One stand-in program in its own directory, which the script reads as `$D`.
struct StandIn {
    directory: PathBuf,
}

impl StandIn {
    /// Write `script`, which appends one line to `$D/runs` each time it starts.
    fn new(test: &str, script: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("box-command-source-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the temp dir is writable");
        let body = format!(
            "D='{}'\necho run >> \"$D/runs\"\n{script}\n",
            directory.display()
        );
        std::fs::write(directory.join("program.sh"), body).expect("the script is written");
        Self { directory }
    }

    /// The declaration's `command`: the shell, the script, then `arguments`.
    fn command(&self, arguments: &[&str]) -> Vec<String> {
        let script = self.directory.join("program.sh");
        [SHELL, script.to_str().expect("a UTF-8 temp dir")]
            .into_iter()
            .chain(arguments.iter().copied())
            .map(str::to_string)
            .collect()
    }

    /// The declaration of this program for `scheme`, with `{ref}` as its one argument.
    fn declaration(&self, scheme: &str) -> SecretSourceCommand {
        SecretSourceCommand::new(
            scheme,
            SecretSourceCommand::PROTOCOL,
            &self.command(&["{ref}"]),
        )
        .expect("a valid declaration")
    }

    /// How many times the program started.
    fn runs(&self) -> usize {
        self.read("runs").lines().count()
    }

    /// A file the program wrote in `$D`, or nothing.
    fn read(&self, leaf: &str) -> String {
        std::fs::read_to_string(self.directory.join(leaf)).unwrap_or_default()
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// The bounds a test runs under, unless it tests a bound.
const TEST_BOUNDS: Bounds = Bounds {
    timeout: Duration::from_secs(10),
    stdout: STDOUT_LIMIT,
};

/// A source over a fixed operator environment, so no test reads the real one.
fn source(
    declaration: SecretSourceCommand,
    operator: &[(&str, &str)],
    bounds: Bounds,
) -> CommandSource {
    let operator: Vec<(OsString, OsString)> = operator
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect();
    CommandSource {
        declaration,
        environment: Box::new(move || operator.clone()),
        bounds,
        held: Mutex::default(),
    }
}

/// The declared backend over one stand-in source with an empty operator environment.
fn backend(declaration: SecretSourceCommand) -> Backend {
    backend_of(source(declaration, &[], TEST_BOUNDS))
}

fn backend_of(source: CommandSource) -> Backend {
    Backend::with_command_sources([source]).expect("the scheme is free")
}

fn resolve(backend: &Backend, reference: &str) -> Result<Zeroizing<String>> {
    backend.resolve(&Locator::Uri(reference.to_string()))
}

fn secret(backend: &Backend, reference: &str) -> String {
    resolve(backend, reference)
        .expect("the reference resolves")
        .to_string()
}

fn refusal(backend: &Backend, reference: &str) -> String {
    let error = resolve(backend, reference).expect_err("the reference is refused");
    assert!(!error.is_soft(), "a command source has no soft failure");
    error.to_string()
}

/// Whether the process whose id the stand-in wrote to `$D/pid` still runs.
fn still_runs(program: &StandIn) -> bool {
    let written = program.read("pid");
    let pid = written.trim();
    assert!(
        !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()),
        "the stand-in wrote its process id: {pid:?}"
    );
    Command::new(SHELL)
        .args(["-c", &format!("kill -0 {pid}")])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The start of each failure of the stand-in program for the scheme `vault`.
fn failed(reason: &str) -> String {
    format!(
        "credential error: the secret source \"vault\" (\"/bin/sh\") for vault://[REDACTED] \
         {reason}"
    )
}

// --- The environment --------------------------------------------------------------------------

#[test]
fn the_program_gets_only_home_the_fixed_path_and_the_passed_variables() {
    let program = StandIn::new(
        "environment",
        "/usr/bin/env > \"$D/environment\"\nprintf ok",
    );
    let declaration = program
        .declaration("vault")
        .pass_env(["OP_ACCOUNT", "OP_CONNECT_HOST", "PA*", "HO*"])
        .and_then(|declaration| {
            declaration.pass_secret_env(["OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_*"])
        })
        .expect("valid pass lists");
    let operator = [
        ("HOME", "/home/operator"),
        ("PATH", "/operator/bin"),
        ("PAGER", "less"),
        ("OP_ACCOUNT", "acme"),
        ("OP_SERVICE_ACCOUNT_TOKEN", "ops_token"),
        ("OP_SESSION_abc", "session-abc"),
        ("OP_SESSION_", "session-bare"),
        ("OP_SESSION", "not-passed"),
        ("OP_ACCOUNT_2", "not-passed"),
        ("GITHUB_TOKEN", "not-passed"),
        ("LD_PRELOAD", "not-passed"),
    ];
    let backend = backend_of(source(declaration, &operator, TEST_BOUNDS));
    assert_eq!(secret(&backend, "vault://item"), "ok");

    // The shell that runs the stand-in adds these names itself.
    let from_the_shell = ["PWD", "OLDPWD", "SHLVL", "_"];
    let written = program.read("environment");
    let mut environment: Vec<&str> = written
        .lines()
        .filter(|line| {
            let name = line.split('=').next().unwrap_or_default();
            !from_the_shell.contains(&name)
        })
        .collect();
    environment.sort_unstable();
    assert_eq!(
        environment,
        [
            "HOME=/home/operator",
            "OP_ACCOUNT=acme",
            "OP_SERVICE_ACCOUNT_TOKEN=ops_token",
            "OP_SESSION_=session-bare",
            "OP_SESSION_abc=session-abc",
            "PAGER=less",
            "PATH=/usr/bin:/bin",
        ]
    );
}

#[test]
fn the_composed_environment_marks_each_credential_and_adds_no_home() {
    let declaration = SecretSourceCommand::new(
        "vault",
        SecretSourceCommand::PROTOCOL,
        &["/opt/vault".to_string(), "{ref}".to_string()],
    )
    .and_then(|declaration| declaration.pass_env(["REGION"]))
    .and_then(|declaration| declaration.pass_secret_env(["TOKEN"]))
    .expect("valid");
    let operator = [("TOKEN", "t"), ("REGION", "r"), ("OTHER", "o")]
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .to_vec();
    let composed: Vec<(String, String, bool)> = compose(&declaration, operator)
        .into_iter()
        .map(|variable| {
            (
                variable.name.to_str().expect("UTF-8").to_string(),
                variable.value.to_str().expect("UTF-8").to_string(),
                variable.secret,
            )
        })
        .collect();
    assert_eq!(
        composed,
        [
            ("PATH".to_string(), "/usr/bin:/bin".to_string(), false),
            ("TOKEN".to_string(), "t".to_string(), true),
            ("REGION".to_string(), "r".to_string(), false),
        ]
    );
}

#[test]
fn home_passes_with_no_entry_and_is_a_credential_only_when_pass_secret_env_matches_it() {
    let composed_home = |plain: &[&str], secret: &[&str]| {
        let declaration = SecretSourceCommand::new(
            "vault",
            SecretSourceCommand::PROTOCOL,
            &["/opt/vault".to_string(), "{ref}".to_string()],
        )
        .and_then(|declaration| declaration.pass_env(plain.iter().copied()))
        .and_then(|declaration| declaration.pass_secret_env(secret.iter().copied()))
        .expect("valid");
        let operator = vec![(OsString::from("HOME"), OsString::from("/home/operator"))];
        compose(&declaration, operator)
            .iter()
            .map(|variable| {
                (
                    variable.name.clone(),
                    variable.value.clone(),
                    variable.secret,
                )
            })
            .collect::<Vec<_>>()
    };
    let path = (
        OsString::from("PATH"),
        OsString::from("/usr/bin:/bin"),
        false,
    );
    let home = |secret| {
        (
            OsString::from("HOME"),
            OsString::from("/home/operator"),
            secret,
        )
    };
    assert_eq!(composed_home(&[], &[]), [path.clone(), home(false)]);
    assert_eq!(composed_home(&["HO*"], &[]), [path.clone(), home(false)]);
    assert_eq!(composed_home(&[], &["HO*"]), [path, home(true)]);
}

#[test]
fn a_variable_with_a_name_that_is_not_utf8_does_not_pass() {
    use std::os::unix::ffi::OsStringExt;

    let declaration = SecretSourceCommand::new(
        "vault",
        SecretSourceCommand::PROTOCOL,
        &["/opt/vault".to_string(), "{ref}".to_string()],
    )
    .and_then(|declaration| declaration.pass_env(["TOK*"]))
    .expect("valid");
    // The start of the name matches the entry, but no entry can name the whole of it.
    let operator = vec![(
        OsString::from_vec(b"TOK\xffEN".to_vec()),
        OsString::from("not-passed"),
    )];
    let names: Vec<OsString> = compose(&declaration, operator)
        .iter()
        .map(|variable| variable.name.clone())
        .collect();
    assert_eq!(names, [OsString::from("PATH")]);
}

// --- The runner -------------------------------------------------------------------------------

#[test]
fn the_program_gets_no_stdin() {
    let program = StandIn::new(
        "stdin",
        "if read line; then printf open; else printf closed; fi",
    );
    assert_eq!(
        secret(&backend(program.declaration("vault")), "vault://item"),
        "closed"
    );
}

#[test]
fn the_program_starts_in_the_root_directory() {
    let program = StandIn::new("directory", "pwd > \"$D/directory\"\nprintf ok");
    assert_eq!(
        secret(&backend(program.declaration("vault")), "vault://item"),
        "ok"
    );
    assert_eq!(program.read("directory"), "/\n");
}

#[test]
fn each_argument_reaches_the_program_as_one_argument_with_no_shell() {
    let program = StandIn::new(
        "arguments",
        "printf '%s\\n' \"$#\" \"$@\" > \"$D/arguments\"\nprintf ok",
    );
    let declaration = SecretSourceCommand::new(
        "vault",
        SecretSourceCommand::PROTOCOL,
        &program.command(&[
            "read",
            "op://{ref}",
            "--id={ref}",
            "{ref}{ref}",
            "a b;$(id)",
        ]),
    )
    .expect("valid");
    let backend = backend(declaration);
    assert_eq!(secret(&backend, "vault://My Vault/it;em/$(id) {ref}"), "ok");
    assert_eq!(
        program.read("arguments"),
        "5\n\
         read\n\
         op://My Vault/it;em/$(id) {ref}\n\
         --id=My Vault/it;em/$(id) {ref}\n\
         My Vault/it;em/$(id) {ref}My Vault/it;em/$(id) {ref}\n\
         a b;$(id)\n"
    );
}

#[test]
fn a_program_that_runs_past_the_timeout_is_stopped() {
    let program = StandIn::new("timeout", "echo $$ > \"$D/pid\"\nexec /bin/sleep 30");
    let bounds = Bounds {
        timeout: Duration::from_millis(300),
        ..TEST_BOUNDS
    };
    let backend = backend_of(source(program.declaration("vault"), &[], bounds));
    let started = Instant::now();
    assert_eq!(
        refusal(&backend, "vault://item"),
        failed("did not finish within 300ms")
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the runner did not wait for the program"
    );
    assert!(!still_runs(&program), "the runner stopped the program");
}

#[test]
fn a_program_that_leaves_its_stdout_open_fails_at_the_deadline() {
    let program = StandIn::new("descendant", "/bin/sleep 5 &\nprintf secret");
    let bounds = Bounds {
        timeout: Duration::from_millis(1500),
        ..TEST_BOUNDS
    };
    let backend = backend_of(source(program.declaration("vault"), &[], bounds));
    let started = Instant::now();
    assert_eq!(
        refusal(&backend, "vault://item"),
        failed("left its stdout open after it exited")
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the runner did not wait for the descendant"
    );
}

#[test]
fn a_descendant_that_holds_stderr_open_costs_only_the_stderr_text() {
    let succeeds = StandIn::new(
        "stderr-held-ok",
        "/bin/sleep 5 > /dev/null &\nprintf secret",
    );
    let started = Instant::now();
    assert_eq!(
        secret(&backend(succeeds.declaration("vault")), "vault://item"),
        "secret"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "a success does not wait for stderr"
    );

    let fails = StandIn::new(
        "stderr-held-fails",
        "echo boom >&2\n/bin/sleep 5 > /dev/null &\nexit 2",
    );
    let started = Instant::now();
    assert_eq!(
        refusal(&backend(fails.declaration("vault")), "vault://item"),
        failed("exited unsuccessfully (exit status: 2)")
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "a failure waits a bounded time for stderr"
    );
}

#[test]
fn stdout_up_to_the_limit_is_read_and_one_more_byte_is_refused() {
    let bounds = Bounds {
        stdout: 16,
        ..TEST_BOUNDS
    };
    let at_the_limit = StandIn::new("limit-at", "printf 0123456789abcdef");
    let backend = backend_of(source(at_the_limit.declaration("vault"), &[], bounds));
    assert_eq!(secret(&backend, "vault://item"), "0123456789abcdef");

    let over_the_limit = StandIn::new("limit-over", "printf 0123456789abcdefg");
    let backend = backend_of(source(over_the_limit.declaration("vault"), &[], bounds));
    assert_eq!(
        refusal(&backend, "vault://item"),
        failed("wrote more than 16 bytes to stdout")
    );
}

#[test]
fn a_program_that_never_stops_writing_is_stopped_at_the_limit() {
    // The program ignores the closed pipe, so only the runner stops it.
    let program = StandIn::new(
        "endless",
        "echo $$ > \"$D/pid\"\ntrap '' PIPE\nwhile :; do echo yyyyyyyyyyyyyyyy; done 2> /dev/null",
    );
    let bounds = Bounds {
        stdout: 4096,
        ..TEST_BOUNDS
    };
    let backend = backend_of(source(program.declaration("vault"), &[], bounds));
    let started = Instant::now();
    assert_eq!(
        refusal(&backend, "vault://item"),
        failed("wrote more than 4096 bytes to stdout")
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the runner did not wait for the timeout"
    );
    assert!(!still_runs(&program), "the runner stopped the program");
}

#[test]
fn a_non_zero_exit_is_a_failure_that_carries_stderr() {
    let program = StandIn::new("exit", "printf partial\necho 'no such entry' >&2\nexit 3");
    assert_eq!(
        refusal(&backend(program.declaration("vault")), "vault://item"),
        format!(
            "{}: no such entry",
            failed("exited unsuccessfully (exit status: 3)")
        )
    );
}

#[test]
fn a_failure_hides_the_reference_and_each_passed_credential_and_each_control_character() {
    let program = StandIn::new(
        "redaction",
        "echo \"no item $1 for $OP_ACCOUNT with $OP_SERVICE_ACCOUNT_TOKEN or $OP_SESSION_abc\" >&2\n\
         printf '\\033[31mred\\tend\\n' >&2\n\
         exit 1",
    );
    let declaration = program
        .declaration("vault")
        .pass_env(["OP_ACCOUNT"])
        .and_then(|declaration| {
            declaration.pass_secret_env(["OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_*"])
        })
        .expect("valid pass lists");
    let operator = [
        ("OP_ACCOUNT", "acme"),
        ("OP_SERVICE_ACCOUNT_TOKEN", "ops_token"),
        ("OP_SESSION_abc", "ops_token_longer"),
    ];
    let backend = backend_of(source(declaration, &operator, TEST_BOUNDS));
    assert_eq!(
        refusal(&backend, "vault://Private/GitHub/token"),
        format!(
            "{}: no item [REDACTED] for acme with [REDACTED] or [REDACTED] [31mred end",
            failed("exited unsuccessfully (exit status: 1)")
        )
    );
}

#[test]
fn a_failure_hides_a_passed_credential_that_is_not_utf8() {
    use std::os::unix::ffi::OsStringExt;

    let program = StandIn::new(
        "not-utf8-credential",
        "printf 'bad token %s here' \"$TOKEN\" >&2\nexit 1",
    );
    let declaration = program
        .declaration("vault")
        .pass_secret_env(["TOKEN"])
        .expect("a valid pass list");
    let source = CommandSource {
        declaration,
        environment: Box::new(|| {
            vec![(
                OsString::from("TOKEN"),
                OsString::from_vec(b"ops_\xfftoken".to_vec()),
            )]
        }),
        bounds: TEST_BOUNDS,
        held: Mutex::default(),
    };
    assert_eq!(
        refusal(&backend_of(source), "vault://item"),
        format!(
            "{}: bad token [REDACTED] here",
            failed("exited unsuccessfully (exit status: 1)")
        )
    );
}

#[test]
fn a_failure_carries_at_most_512_bytes_of_stderr() {
    let program = StandIn::new(
        "stderr",
        "/usr/bin/yes eeeeeee | /usr/bin/head -c 100000 >&2\necho 'the last line' >&2\nexit 1",
    );
    let message = refusal(&backend(program.declaration("vault")), "vault://item");
    let start = format!("{}: ", failed("exited unsuccessfully (exit status: 1)"));
    let said = message
        .strip_prefix(&start)
        .expect("the failure names the exit status first");
    assert_eq!(said.len(), 512);
    let before = said
        .strip_suffix(" the last line")
        .expect("the excerpt ends with the end of stderr");
    assert!(
        before
            .chars()
            .all(|character| character == 'e' || character == ' '),
        "the excerpt holds only what the program wrote: {said}"
    );
}

/// A capture of stderr, which lost its first bytes when `overflowed` is set.
fn captured(bytes: &[u8], overflowed: bool) -> Captured {
    Captured {
        bytes: Zeroizing::new(bytes.to_vec()),
        overflowed,
        failed: false,
    }
}

#[test]
fn the_excerpt_hides_the_end_of_a_hidden_value_at_the_start_of_a_cut_capture() {
    let hidden = ["ops_token_value"];
    // A capture that lost its first bytes can begin with the end of a credential.
    let cut = captured(b"en_value and then the error", true);
    assert_eq!(excerpt(&cut, &hidden), "[REDACTED] and then the error");
    // A whole capture begins where the program began, so the same bytes are not a credential.
    let whole = captured(b"en_value and then the error", false);
    assert_eq!(excerpt(&whole, &hidden), "en_value and then the error");
}

#[test]
fn the_excerpt_hides_a_whole_hidden_value_near_the_start_of_a_cut_capture() {
    // The value starts ten bytes into the capture, so a cut of a fixed length would leave its end.
    let cut = captured(b"eeeeeeeee ops_token_value_0123456789 and the error", true);
    assert_eq!(
        excerpt(&cut, &["ops_token_value_0123456789", "9 and"]),
        "eeeeeeeee [REDACTED] the error"
    );
}

#[test]
fn the_excerpt_hides_each_hidden_value_that_holds_or_meets_another() {
    let said = captured(
        b"a=ops_token_longer b=ops_token c=tokenops_token d=ops",
        false,
    );
    assert_eq!(
        excerpt(&said, &["ops_token", "ops_token_longer", "token"]),
        "a=[REDACTED] b=[REDACTED] c=[REDACTED] d=ops"
    );
}

#[test]
fn a_reader_keeps_the_first_bytes_or_the_last_bytes_of_a_long_output() {
    let long: Vec<u8> = (0..100u8).collect();
    let held = |limit, keep| {
        let captured = reader(Some(std::io::Cursor::new(long.clone())), limit, keep)
            .recv()
            .expect("the reader sends what it held");
        (
            captured.bytes.to_vec(),
            captured.overflowed,
            captured.failed,
        )
    };
    assert_eq!(held(8, Keep::First), (long[..8].to_vec(), true, false));
    assert_eq!(held(8, Keep::Last), (long[92..].to_vec(), true, false));
    assert_eq!(held(7, Keep::Last), (long[93..].to_vec(), true, false));
    assert_eq!(held(100, Keep::First), (long.clone(), false, false));
    assert_eq!(held(100, Keep::Last), (long.clone(), false, false));
    assert_eq!(held(99, Keep::Last), (long[1..].to_vec(), true, false));
    // The output ends where the buffer is full, so only the moved bytes show the loss.
    assert_eq!(held(50, Keep::Last), (long[50..].to_vec(), true, false));
    assert_eq!(held(25, Keep::Last), (long[75..].to_vec(), true, false));
}

#[test]
fn a_program_that_does_not_exist_is_a_failure_that_names_it() {
    let declaration = SecretSourceCommand::new(
        "vault",
        SecretSourceCommand::PROTOCOL,
        &[
            "/nonexistent/box-test/vault".to_string(),
            "{ref}".to_string(),
        ],
    )
    .expect("valid");
    assert_eq!(
        refusal(&backend(declaration), "vault://item"),
        "credential error: the secret source \"vault\" (\"/nonexistent/box-test/vault\") for \
         vault://[REDACTED] did not start (entity not found)"
    );
}

// --- The reference ----------------------------------------------------------------------------

#[test]
fn a_malformed_reference_is_refused_before_the_program_starts() {
    let program = StandIn::new("malformed", "printf ok");
    let backend = backend(program.declaration("vault"));
    for (reference, reason) in [
        (
            "vault://-rf",
            "the text after `://` starts with `-`, which a program can read as a flag",
        ),
        (
            "vault://--help#FIELD",
            "the text after `://` starts with `-`, which a program can read as a flag",
        ),
        ("vault://", "it names no secret after `://`"),
        ("vault://#FIELD", "it names no secret after `://`"),
        ("vault://item#", "it names no field after `#`"),
        ("vault://item#a#b", "it holds more than one `#`"),
        ("vault://it\tem", "it holds a control character"),
        ("vault://item#fie\nld", "it holds a control character"),
    ] {
        assert_eq!(
            refusal(&backend, reference),
            format!("credential error: the reference vault://[REDACTED] is malformed: {reason}"),
            "for {reference:?}"
        );
    }
    assert_eq!(program.runs(), 0);
}

#[test]
fn a_structured_reference_is_refused_before_the_program_starts() {
    let program = StandIn::new("structured", "printf ok");
    let backend = backend(program.declaration("vault"));
    let fields = [("source", "vault"), ("item", "GitHub")]
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .into_iter()
        .collect();
    let error = backend
        .resolve(&Locator::structured(fields).expect("a tagged block"))
        .expect_err("a command source reads a URI");
    assert_eq!(
        error.to_string(),
        "credential error: vault:// source expects a URI-form reference, not a structured block"
    );
    assert_eq!(program.runs(), 0);
}

// --- The output -------------------------------------------------------------------------------

/// A stand-in that prints what its argument names, so one program serves each case.
fn printer(test: &str) -> StandIn {
    StandIn::new(
        test,
        "case \"$1\" in\n\
         plain) printf 'tok-plain' ;;\n\
         newline) printf 'tok-newline\\n' ;;\n\
         crlf) printf 'tok-crlf\\r\\n' ;;\n\
         two-newlines) printf 'tok\\n\\n' ;;\n\
         empty) ;;\n\
         only-newline) printf '\\n' ;;\n\
         not-utf8) printf '\\377\\376' ;;\n\
         string) printf '\"s3cr\\\\u0065t \\\\\"q\\\\\"\"\\n' ;;\n\
         null) printf 'null\\n' ;;\n\
         number) printf '5' ;;\n\
         boolean) printf 'true' ;;\n\
         array) printf '[\"a\"]' ;;\n\
         object) printf '{\"A\":\"a-value\",\"B\":\"b-value\",\"N\":5}\\n' ;;\n\
         object-in-string) printf '\"{\\\\\"A\\\\\":\\\\\"a-value\\\\\"}\"' ;;\n\
         esac",
    )
}

#[test]
fn text_output_is_the_secret_without_one_trailing_newline() {
    let program = printer("text");
    let backend = backend(program.declaration("vault"));
    assert_eq!(secret(&backend, "vault://plain"), "tok-plain");
    assert_eq!(secret(&backend, "vault://newline"), "tok-newline");
    assert_eq!(secret(&backend, "vault://crlf"), "tok-crlf");
    // Only one newline is stripped, and a secret cannot hold the one that stays.
    assert_eq!(
        refusal(&backend, "vault://two-newlines"),
        "credential error: the secret named in \"vault://[REDACTED]\" contains a control \
         character, which would forge a header boundary on the wire"
    );
    // With text output, a JSON value is the secret as written.
    assert_eq!(secret(&backend, "vault://null"), "null");
}

#[test]
fn an_empty_secret_and_output_that_is_not_utf8_are_refused() {
    let program = printer("unusable");
    let backend = backend(program.declaration("vault"));
    for name in ["empty", "only-newline"] {
        assert_eq!(
            refusal(&backend, &format!("vault://{name}")),
            "credential error: the secret named in \"vault://[REDACTED]\" is empty"
        );
    }
    assert_eq!(
        refusal(&backend, "vault://not-utf8"),
        failed("wrote output that is not UTF-8")
    );
}

#[test]
fn json_output_is_one_json_string_and_any_other_value_is_refused() {
    let program = printer("json");
    let declaration = program.declaration("vault").output("json").expect("valid");
    let backend = backend(declaration);
    assert_eq!(secret(&backend, "vault://string"), "s3cret \"q\"");
    for (name, wrote) in [
        ("null", "the JSON value `null`"),
        ("number", "a JSON number"),
        ("boolean", "a JSON boolean"),
        ("array", "a JSON array"),
        ("object", "a JSON object"),
        ("plain", "output that is not JSON"),
        ("empty", "output that is not JSON"),
    ] {
        assert_eq!(
            refusal(&backend, &format!("vault://{name}")),
            failed(&format!(
                "wrote {wrote}, and `output = \"json\"` reads one JSON string"
            )),
            "for {name}"
        );
    }
}

// --- The field --------------------------------------------------------------------------------

#[test]
fn a_field_selects_one_string_of_a_json_object_and_any_other_case_is_refused() {
    let program = printer("field");
    let backend = backend(program.declaration("vault"));
    assert_eq!(secret(&backend, "vault://object#A"), "a-value");
    assert_eq!(secret(&backend, "vault://object#B"), "b-value");
    assert_eq!(
        refusal(&backend, "vault://object#MISSING"),
        failed("returned a JSON object that has no `#FIELD` of that name")
    );
    assert_eq!(
        refusal(&backend, "vault://object#N"),
        failed("returned a JSON object whose `#FIELD` is not a string")
    );
    assert_eq!(
        refusal(&backend, "vault://plain#A"),
        failed("returned a secret that is not a JSON object, so it has no `#FIELD`")
    );
    assert_eq!(
        refusal(&backend, "vault://array#A"),
        failed("returned a secret that is not a JSON object, so it has no `#FIELD`")
    );
}

#[test]
fn a_json_object_without_a_field_is_refused() {
    let program = printer("whole-object");
    let backend = backend(program.declaration("vault"));
    assert_eq!(
        refusal(&backend, "vault://object"),
        failed("returned a JSON object, so the reference must name one field with `#FIELD`")
    );
}

#[test]
fn a_declared_op_refuses_a_json_object_without_a_field_in_text_output() {
    let program = printer("declared-op-object");
    let backend = Backend::declared([program.declaration("op")]).expect("op is free to declare");
    assert_eq!(
        refusal(&backend, "op://object"),
        "credential error: the secret source \"op\" (\"/bin/sh\") for op://[REDACTED] returned a \
         JSON object, so the reference must name one field with `#FIELD`"
    );
}

#[test]
fn a_field_reads_an_object_that_json_output_decoded() {
    let program = printer("field-json");
    let declaration = program.declaration("vault").output("json").expect("valid");
    let backend = backend(declaration);
    assert_eq!(secret(&backend, "vault://object-in-string#A"), "a-value");
    assert_eq!(
        refusal(&backend, "vault://object-in-string"),
        failed("returned a JSON object, so the reference must name one field with `#FIELD`")
    );
}

#[test]
fn a_wipe_empties_each_string_of_a_parsed_value() {
    let mut value: serde_json::Value =
        serde_json::from_str(r#"{"a":"x","b":["y",{"c":"z"}],"n":1,"t":true,"z":null}"#)
            .expect("valid JSON");
    wipe_value(&mut value);
    assert_eq!(
        value.to_string(),
        r#"{"a":"","b":["",{"c":""}],"n":1,"t":true,"z":null}"#
    );
}

// --- The declared backend ---------------------------------------------------------------------

#[test]
fn a_declared_backend_resolves_each_declared_scheme_through_its_program() {
    let first = StandIn::new("declared-first", "printf \"first:$1\"");
    let second = StandIn::new("declared-second", "printf \"second:$1\"");
    let backend = Backend::declared([
        first.declaration("vault"),
        second.declaration("aws-secretsmanager"),
    ])
    .expect("two schemes");
    assert_eq!(secret(&backend, "vault://a/b"), "first:a/b");
    assert_eq!(
        secret(&backend, "aws-secretsmanager://box/telemetry"),
        "second:box/telemetry"
    );
}

#[test]
fn a_declared_op_takes_the_place_of_the_built_in_source() {
    let program = StandIn::new("declared-op", "printf \"declared:$1\"");
    let backend = Backend::declared([program.declaration("op")]).expect("op is free to declare");
    // The built-in source refuses a reference with two segments, and never reads `{ref}`.
    assert_eq!(secret(&backend, "op://vault/item"), "declared:vault/item");
    assert_eq!(
        format!("{backend:?}"),
        "Backend { profile: Declared { registry: SourceRegistry { schemes: [\"env\", \"file\", \
         \"op\"] } } }"
    );
}

#[test]
fn a_declared_backend_keeps_the_built_in_op_when_no_declaration_names_op() {
    let program = StandIn::new("built-in-op", "printf ok");
    let backend = Backend::declared([program.declaration("vault")]).expect("valid");
    // The built-in source refuses this reference before it starts `op`.
    assert_eq!(
        refusal(&backend, "op://vault/item"),
        "credential error: malformed op:// reference (must have at least 3 segments \
         (vault/item/field)): \"op://[REDACTED]\""
    );
    assert_eq!(
        format!("{backend:?}"),
        "Backend { profile: Declared { registry: SourceRegistry { schemes: [\"env\", \"file\", \
         \"op\", \"vault\"] } } }"
    );
}

#[test]
fn two_declarations_of_one_scheme_are_refused() {
    let program = StandIn::new("duplicate", "printf ok");
    let error = Backend::declared([program.declaration("vault"), program.declaration("vault")])
        .expect_err("one scheme has one declaration");
    assert_eq!(
        error.to_string(),
        "credential error: duplicate credential source registered for scheme \"vault\""
    );
}

#[test]
fn a_declared_backend_reads_a_file_reference_and_reports_an_unset_variable_as_soft() {
    let program = StandIn::new("local-sources", "printf ok");
    std::fs::write(program.directory.join("token"), "file-token\n").expect("written");
    let backend = Backend::declared([program.declaration("vault")]).expect("valid");
    let file = format!("file://{}", program.directory.join("token").display());
    assert_eq!(secret(&backend, &file), "file-token");
    let unset = resolve(&backend, "env://BOX_COMMAND_SOURCE_TEST_UNSET")
        .expect_err("the variable is not set");
    assert!(unset.is_soft(), "an unset variable is the soft miss");
    assert_eq!(program.runs(), 0);
}

#[test]
fn two_references_that_differ_only_in_the_field_run_the_program_once() {
    let program = printer("one-run");
    let backend = backend(program.declaration("vault"));
    assert_eq!(secret(&backend, "vault://object#A"), "a-value");
    assert_eq!(secret(&backend, "vault://object#B"), "b-value");
    assert_eq!(secret(&backend, "vault://object#A"), "a-value");
    assert_eq!(program.runs(), 1);

    // Another secret is another run.
    assert_eq!(secret(&backend, "vault://plain"), "tok-plain");
    assert_eq!(program.runs(), 2);
}

#[test]
fn each_clone_of_a_declared_backend_shares_one_fetch() {
    let program = printer("clone");
    let first = backend(program.declaration("vault"));
    let second = first.clone();
    assert_eq!(secret(&first, "vault://object#A"), "a-value");
    assert_eq!(secret(&second, "vault://object#B"), "b-value");
    assert_eq!(secret(&second.clone(), "vault://object#A"), "a-value");
    assert_eq!(program.runs(), 1);
}

#[test]
fn two_callers_at_one_time_run_the_program_once() {
    let program = StandIn::new("at-one-time", "/bin/sleep 0.3\nprintf slow-secret");
    let backend = Arc::new(backend(program.declaration("vault")));
    let callers: Vec<_> = (0..2)
        .map(|_| {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || secret(&backend, "vault://item"))
        })
        .collect();
    for caller in callers {
        assert_eq!(caller.join().expect("the caller finished"), "slow-secret");
    }
    assert_eq!(program.runs(), 1);
}

#[test]
fn a_failed_fetch_is_not_kept() {
    let program = StandIn::new(
        "retry",
        "if [ -e \"$D/second\" ]; then printf ok; else : > \"$D/second\"; exit 1; fi",
    );
    let backend = backend(program.declaration("vault"));
    assert_eq!(
        refusal(&backend, "vault://item"),
        failed("exited unsuccessfully (exit status: 1)")
    );
    assert_eq!(secret(&backend, "vault://item"), "ok");
    assert_eq!(program.runs(), 2);
}

#[test]
fn debug_shows_the_scheme_and_the_program_and_no_secret() {
    let program = printer("debug");
    let source = source(program.declaration("vault"), &[], TEST_BOUNDS);
    let fetched = source
        .fetch(&Locator::Uri("vault://plain".to_string()))
        .expect("resolves");
    assert_eq!(fetched.as_str(), "tok-plain");
    assert_eq!(
        format!("{source:?}"),
        "CommandSource { scheme: \"vault\", program: \"/bin/sh\", .. }"
    );
}
