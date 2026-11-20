//! Credential binding declared in `strands-box.toml`, asserted end to end.
//!
//! These run the shipped `strands-box` binary against a real HTTPS upstream on
//! localhost, so what they prove is what the whole stack does: the config file is
//! read, the vault mints a phantom, the workload receives only the phantom, the proxy
//! swaps it for the real secret, and Cedar authorizes each of the three effects on the
//! way. A failure means the boundary moved, not that a fixture drifted.
//!
//! The upstream **records the `Authorization` header it actually received**, which is
//! what makes the swap observable: if the phantom ever rode upstream, or the real
//! secret ever reached the workload, these fail.
//!
//! # Which verb refuses
//!
//! Authority is stored, so a config the box will not accept is refused by `create`
//! and there is no run at all — the workload cannot "fail to start", because nothing
//! ever asked it to. That is a stronger property than the one these tests used to
//! assert: a rejected config leaves the box's *previous* authority in force rather than
//! half-replacing it, because `create` validates before it writes a byte. Each
//! refusal test below therefore reads `create`'s stderr, and separately asserts the
//! box did not come up.
//!
//! The credentials themselves resolve at configure time too, in the operator's
//! environment. A run resolves nothing — which is why [`fixture::Configured::run`]
//! carries the same environment: a test must not pass merely because the secret was
//! present for one of the two.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/trace_upstream.rs"]
mod trace_upstream;

use fixture::{Configured, Request};
use serde_json::{Value, json};
use trace_upstream::TraceUpstream;

/// The real secret, which must never appear inside the box.
const REAL_SECRET: &str = "sk_live_e2e_realsecret_2f9c";

/// The environment variable the operator points the locator at.
const SECRET_VARIABLE: &str = "STRANDS_BOX_E2E_TOKEN";

/// A tiny HTTPS upstream that records the `Authorization` header of each request.
///
/// Speaks TLS with a self-signed leaf for `localhost`.
struct RecordingUpstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl RecordingUpstream {
    /// Bind an ephemeral localhost port and serve until dropped.
    fn start() -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed leaf for localhost");
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key)
            .expect("server TLS config");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let port = listener.local_addr().expect("upstream addr").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let config = Arc::new(config);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    let _ = serve_one(stream, config, recorded);
                });
            }
        });

        Self { port, seen }
    }

    /// Every `Authorization` value this upstream has received.
    fn authorizations(&self) -> Vec<String> {
        self.seen.lock().expect("upstream lock").clone()
    }
}

/// Terminate one TLS connection, record its `Authorization`, and reply `200`.
fn serve_one(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    recorded: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let connection = rustls::ServerConnection::new(config)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut tls = rustls::StreamOwned::new(connection, stream);

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if tls.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let authorization = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_else(|| "<absent>".to_string());
    recorded.lock().expect("upstream lock").push(authorization);

    // A body the test can look for, and which must not carry the secret.
    let body = br#"{"ok":true}"#;
    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    tls.write_all(body)?;
    tls.flush()
}

/// Configure a box whose `[[credential]]` entries are `credential_toml`.
///
/// The real secret is in the environment `create` sees, because that is where an
/// `env://` locator dereferences — never in the workload's.
fn box_with_credentials(name: &str, policy: &str, credential_toml: &str) -> Configured {
    Request::with_config(name, policy, credential_toml)
        .env(SECRET_VARIABLE, REAL_SECRET)
        .expect()
}

/// Attempt to configure such a box, and answer with `create`'s output.
fn attempt_configure(name: &str, policy: &str, credential_toml: &str) -> (Configured, Output) {
    Request::with_config(name, policy, credential_toml)
        .env(SECRET_VARIABLE, REAL_SECRET)
        .attempt()
}

/// Run the egress probe **as the workload itself**, fetching `url` with the phantom
/// this box provisioned into `variable`.
///
/// No shell and no host HTTP client: the box permits exec on exactly the literals it
/// granted, and macOS `curl` cannot start under containment at all (LibreSSL reads
/// `/private/etc/ssl/openssl.cnf`, which the profile denies). The probe speaks the
/// proxy's CONNECT protocol directly, reading `HTTPS_PROXY` from its environment as an
/// SDK would — so what it writes is the plaintext the boundary inspects, which is what
/// these tests measure.
fn probe(box_: &Configured, variable: &str, url: &str) -> Output {
    box_.run(&[env!("CARGO_BIN_EXE_box-egress-probe"), url, variable])
}

/// Assert `create` refused, naming the reason, and left no box running.
///
/// Both halves matter. The message is what an operator acts on; the absence of a
/// running box is the property that makes the refusal a *refusal* rather than a warning
/// — a `create` that printed an error and started daemons anyway would pass a
/// stderr-only assertion.
fn assert_refused(box_: &Configured, output: &Output, expected: &[&str]) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "configure must refuse this config: {stderr}"
    );
    for fragment in expected {
        assert!(
            stderr.contains(fragment),
            "the refusal must mention {fragment:?}: {stderr}"
        );
    }
    let run = box_.run(&["/bin/bash", "-c", "printf 'NEVER\\n'"]);
    assert!(
        !String::from_utf8_lossy(&run.stdout).contains("NEVER"),
        "a refused configure must leave no box to run in: {run:?}"
    );
}

/// Assert the contained workload actually started, so a negative assertion means
/// something.
fn assert_ran(output: &Output) {
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("READY"),
        "the workload never started, so this test proves nothing: {output:?}"
    );
}

/// The workload's stdout with the readiness marker stripped.
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .strip_prefix("READY")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Run `script` as the contained workload, prefixed with the readiness marker.
fn workload(box_: &Configured, script: &str) -> Output {
    box_.bash(&format!("printf 'READY\\n'; {script}"))
}

/// A policy permitting the three egress effects against one host, and the Shell
/// commands the test workload runs.
fn permit_egress_to(host: &str, port: u16) -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);

permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }};

permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when {{ context.input.host == "{host}" && context.input.port == {port} }};
"#
    )
}

/// One `[[credential]]` binding `endpoint` to the fixture's secret.
fn target(endpoint: &str) -> String {
    format!(
        "[egress.a]\ndestinations = [\"{endpoint}\"]\nsecret.ref = \"env://{SECRET_VARIABLE}\"\n"
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configure — the box refuses what it cannot honor, before anything is stored.
// ═══════════════════════════════════════════════════════════════════════════════

/// A box with no credentials configures and runs: no bindings, nothing injected.
#[test]
fn a_box_with_no_credentials_runs() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_with_credentials("no-creds", &permit_egress_to("api.example.test", 443), "");
    let output = workload(&box_, "printf 'done\\n'");
    assert_ran(&output);
    assert_eq!(stdout(&output), "done");
}

/// A locator naming an unset variable is refused by `create`, not at first request.
///
/// The alternative is a box that starts, reaches the destination, and then cannot
/// attach the credential the operator declared — failing at the least useful moment.
/// Refusing at `create` moves that failure earlier still than it used to be: the
/// operator learns before a single run exists, and the box's previous authority stands.
#[test]
fn an_unset_credential_variable_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "unset-var",
        &permit_egress_to("api.example.test", 443),
        "[egress.b]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"env://STRANDS_BOX_E2E_ABSENT\"\n",
    );
    assert_refused(&box_, &output, &["STRANDS_BOX_E2E_ABSENT", "not set"]);
}

/// A `*.` wildcard endpoint is ACCEPTED, and still reaches only what policy permits.
///
/// This test asserted the opposite until 2026-08-06. The endpoint pattern says which
/// requests *carry this credential*; reachability stays the policy's decision, so a
/// broader pattern attaches a secret in more places and reaches no new host
/// (docs/design/decisions.md#a-credential-binding-is-configuration-not-a-policy-action). The
/// policy here permits only `api.example.test`, so the wildcard cannot widen anything.
#[test]
fn a_wildcard_endpoint_configures_and_reaches_only_what_policy_permits() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_with_credentials(
        "wildcard",
        &permit_egress_to("api.example.test", 443),
        &target("*.example.test"),
    );
    assert_ran(&workload(&box_, "printf 'done\\n'"));
}

/// A bare `*` endpoint is refused: it would attach one credential to every
/// request the policy permits, including hosts the operator never considered.
#[test]
fn a_bare_wildcard_endpoint_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "bare-wildcard",
        &permit_egress_to("api.example.test", 443),
        &target("*"),
    );
    assert_refused(&box_, &output, &["every permitted request"]);
}

/// An all-hosts endpoint is refused however it is spelled, `*:443` included.
///
/// The refusal used to compare the endpoint's authority against the literal `*`, which caught the
/// bare spelling above and missed every `*:<port>` one — because the pattern parser splits the port
/// off *before* classifying the host. Verified against this binary before the fix: `create`
/// exited 0 and the stored record round-tripped `*:443` verbatim.
#[test]
fn an_all_hosts_endpoint_with_a_port_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "star-port",
        &permit_egress_to("api.example.test", 443),
        &target("*:443"),
    );
    assert_refused(&box_, &output, &["matches every host"]);
}

/// A credential scheme the box cannot deliver is refused at `create`.
///
/// This is the class that had **zero** coverage, because every fixture in this file is `env://`. A
/// `file://` target configured, started, and reported healthy — and then refused every request to
/// its destination, because the vault minted a phantom the box had nowhere to place and the gateway
/// requires one. Measured with a real, readable secret. Now it cannot be configured at all.
/// The `op://` row is refused because no table declares it.
#[test]
fn an_undeliverable_credential_scheme_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for (name, locator) in [
        ("file-scheme", "file:///etc/tokens/gh"),
        ("op-scheme", "op://Private/GitHub/token"),
        ("cmd-scheme", "cmd://mint-a-token"),
        ("strip-scheme", "strip-phantom://route"),
    ] {
        let (box_, output) = attempt_configure(
            name,
            &permit_egress_to("api.example.test", 443),
            &format!(
                "[egress.c]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"{locator}\"\n"
            ),
        );
        assert_refused(&box_, &output, &["env://", "aws://"]);
    }
}

/// The body of a configuration that declares `program` as the source for `op://`, with `rest`
/// after the declaration.
fn declared_source(switch: bool, program: &str, rest: &str) -> String {
    let switch = if switch {
        "[experimental-features]\nsecret-sources = true\n"
    } else {
        ""
    };
    format!(
        "{switch}[secret-source.op]\nprotocol = \"box.secret-source.v1\"\n\
         command = [{program:?}, \"read\", \"op://{{ref}}\"]\n\
         pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_SESSION_*\"]\n\
         reads = [\"~/.config/op\"]\n{rest}"
    )
}

/// A request for a box whose `config` declares a secret source, in an operator home that holds
/// each folder that this suite protects.
fn with_vault(name: &str, policy: &str, config: &str) -> Request {
    let request = Request::with_config(name, policy, config);
    for folder in [".config/op", ".aws"] {
        std::fs::create_dir_all(request.operator_home().join(folder))
            .expect("create a folder of the vault");
    }
    request
}

/// A route that reads its secret through the declared `op://` source.
const DECLARED_ROUTE: &str = "[egress.c]\ndestinations = [\"api.example.test\"]\n\
     secret.ref = \"op://Personal/GitHub/token\"\nsecret.env = \"GH_TOKEN\"\n";

/// The secret that a stand-in program prints, which must never appear inside the box.
const DECLARED_SECRET: &str = "sk_live_declared_realsecret_9b3d";

/// The workload variable that holds the placeholder of a declared secret, which no test sets.
const DECLARED_VARIABLE: &str = "STRANDS_BOX_E2E_DECLARED_TOKEN";

/// A stand-in for a vault program, which appends its arguments to `runs` each time it starts.
struct StandInProgram {
    directory: tempfile::TempDir,
}

impl StandInProgram {
    /// Write the program, whose shell text after the `runs` line is `body`.
    fn new(body: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = fixture::short_temporary_home();
        let program = directory.path().join("vault-stand-in");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\n{body}\n",
                directory.path().join("runs").display()
            ),
        )
        .expect("write the stand-in program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("make the stand-in program executable");
        Self { directory }
    }

    fn path(&self) -> String {
        self.directory
            .path()
            .join("vault-stand-in")
            .display()
            .to_string()
    }

    /// The arguments of each start of the program, in order.
    fn runs(&self) -> Vec<String> {
        std::fs::read_to_string(self.directory.path().join("runs"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// A route to `endpoint` whose secret the declared `op://` source reads.
fn declared_route(endpoint: &str, reference: &str) -> String {
    format!(
        "[egress.c]\ndestinations = [\"{endpoint}\"]\nsecret.ref = \"{reference}\"\n\
         secret.env = \"{DECLARED_VARIABLE}\"\n"
    )
}

/// Each `secret_fetched` record in `records`: its outcome, subject, detail, and reason.
fn secret_fetch_records(records: &str) -> Vec<[String; 4]> {
    let mut fetched = Vec::new();
    for line in records.lines() {
        let batch: Value = serde_json::from_str(line).expect("OTLP batch");
        for resource in batch["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                for record in scope["logRecords"].as_array().into_iter().flatten() {
                    let attribute = |name: &str| {
                        record["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == name)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .unwrap_or_default()
                            .to_string()
                    };
                    if attribute("strands.box.control.operation") == "secret_fetched" {
                        fetched.push(
                            ["outcome", "subject", "detail", "reason"]
                                .map(|name| attribute(&format!("strands.box.control.{name}"))),
                        );
                    }
                }
            }
        }
    }
    fetched
}

/// Each file under `directory` that holds `needle`.
fn files_holding(directory: &std::path::Path, needle: &str) -> Vec<std::path::PathBuf> {
    let mut holding = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && std::fs::read(&path).is_ok_and(|bytes| {
                    bytes
                        .windows(needle.len())
                        .any(|window| window == needle.as_bytes())
                })
            {
                holding.push(path);
            }
        }
    }
    holding
}

/// **A run reads a declared secret once before the workload starts**: the workload holds a
/// placeholder in a variable that the operator did not set, the read is recorded, the record
/// stores the declaration, and no file under the operator's home holds the secret.
#[test]
fn a_declared_secret_is_read_at_startup_and_the_workload_holds_a_placeholder() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let upstream = RecordingUpstream::start();
    let endpoint = format!("localhost:{}", upstream.port);
    let (box_, output) = with_vault(
        "declared-read",
        &permit_egress_to("localhost", upstream.port),
        &declared_source(
            true,
            &program.path(),
            &declared_route(&endpoint, "op://Personal/GitHub/token"),
        ),
    )
    .attempt();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    assert!(
        stderr.contains(&format!(
            "strands-box: [secret-source.op]: reads each op:// secret with {}, which runs \
             outside every sandbox\n",
            program.path()
        )),
        "{stderr}"
    );
    assert_eq!(program.runs(), ["read op://Personal/GitHub/token"]);
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("the records of the creating run");
    assert_eq!(
        secret_fetch_records(&records),
        [[
            "ok".to_string(),
            "[egress.c] secret.ref".to_string(),
            format!(
                "source `op`, program {}, reference op://[REDACTED]",
                program.path()
            ),
            String::new(),
        ]]
    );

    // The stored record holds the declaration and the route, at the version of the feature.
    let record = std::fs::read_to_string(box_.root().join("private/box.toml"))
        .expect("the box started, so the record is stored");
    let record: toml::Value = toml::from_str(&record).expect("the record is TOML");
    assert_eq!(record["version"].as_integer(), Some(39));
    assert_eq!(
        record["experimental-features"]["secret-sources"].as_bool(),
        Some(true)
    );
    let expected: toml::Value = toml::from_str(&format!(
        "protocol = \"box.secret-source.v1\"\n\
         command = [{:?}, \"read\", \"op://{{ref}}\"]\n\
         pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_SESSION_*\"]\n\
         reads = [\"~/.config/op\"]\n",
        program.path()
    ))
    .expect("the expected table is TOML");
    assert_eq!(record["secret-source"]["op"], expected);
    let expected: toml::Value = toml::from_str(&format!(
        "ref = \"op://Personal/GitHub/token\"\nenv = \"{DECLARED_VARIABLE}\"\n"
    ))
    .expect("the expected table is TOML");
    assert_eq!(record["egress"]["c"]["secret"], expected);

    let output = box_.run(&["/usr/bin/env"]);
    let environment = String::from_utf8_lossy(&output.stdout).into_owned();
    let held = environment
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{DECLARED_VARIABLE}=")))
        .unwrap_or_default();
    assert!(
        held.starts_with("strands_box_"),
        "the workload must hold a minted placeholder, got {held:?}"
    );
    assert!(
        !environment.contains(DECLARED_SECRET),
        "the secret must never enter the workload's environment"
    );

    // The request with the placeholder passes the boundary: a refusal would be `status=403`.
    let output = probe(
        &box_,
        DECLARED_VARIABLE,
        &format!("https://{endpoint}/v1/charge"),
    );
    let seen = format!("{output:?}");
    assert!(!seen.contains("status=403"), "{seen}");
    assert!(!seen.contains("is not set"), "{seen}");
    assert!(!seen.contains(DECLARED_SECRET), "{seen}");

    assert_eq!(
        program.runs().len(),
        3,
        "each of the three runs reads the secret once"
    );
    assert_eq!(
        files_holding(box_.operator_home(), DECLARED_SECRET),
        Vec::<std::path::PathBuf>::new(),
        "no file of the box, the workspace, or the agent's home holds the secret"
    );
}

/// **A write grant over the program of a secret source stops the box before the program
/// starts**, for a route and for a telemetry target, so no workload can replace a program that
/// Box runs.
#[test]
fn a_write_grant_over_a_secret_source_program_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for (name, secret) in [
        (
            "declared-writable",
            declared_route("api.example.test", "op://Personal/GitHub/token"),
        ),
        (
            // The fixture adds `-<pid>`, and a box name holds at most 32 bytes.
            "declared-writable-otlp",
            "[telemetry.vendor]\nkind = \"otlp\"\ndestination = \"http://127.0.0.1:9\"\n\
             secret.ref = \"op://box/keys#TELEMETRY\"\n"
                .to_string(),
        ),
    ] {
        let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
        let folder = program
            .directory
            .path()
            .canonicalize()
            .expect("the program folder resolves");
        let (box_, output) = with_vault(
            name,
            &permit_egress_to("api.example.test", 443),
            &declared_source(true, &program.path(), &secret),
        )
        .agent_read(&[&folder])
        .agent_write(&[&folder])
        .attempt();
        assert_refused(
            &box_,
            &output,
            &[&format!(
                "this write grant can change [secret-source.op] command {} or its path. Keep \
                 the program of each secret source outside every process's write grants",
                folder.join("vault-stand-in").display()
            )],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("reads each op:// secret"), "{stderr}");
        assert_eq!(
            program.runs(),
            Vec::<String>::new(),
            "{name}: the program must not start in a box that lets a workload replace it"
        );
    }
}

/// The body of a configuration whose `op://` source runs `program` for one route and protects
/// `~/.config/op`, and whose `aws-secretsmanager://` source protects `~/.aws` and a path that is
/// not there, with `rest` after them.
fn protecting_sources(program: &str, rest: &str) -> String {
    let route = declared_route("api.example.test", "op://Personal/GitHub/token");
    format!(
        "{}[secret-source.aws-secretsmanager]\nprotocol = \"box.secret-source.v1\"\n\
         command = [{program:?}, \"get\", \"{{ref}}\"]\n\
         pass-secret-env = [\"AWS_SECRET_ACCESS_KEY\"]\nreads = [\"~/.aws\"]\n\
         deny = [\"~/Library/Group Containers/vault\"]\n{rest}",
        declared_source(true, program, &route)
    )
}

/// The refusal of a grant that reaches `path`, which the `list` entry `entry` of the source
/// `scheme` protects.
fn source_path_refusal(path: &std::path::Path, scheme: &str, list: &str, entry: &str) -> String {
    format!(
        "is refused: this grant reaches {}, which the secret source `{scheme}` keeps from each \
         workload (its `{list}` entry {entry:?}). Keep each grant outside the paths that a \
         secret source names in `reads` and `deny`",
        path.display()
    )
}

/// **A grant that reaches a path of a secret source stops the box before a program starts**:
/// a credential store that a tool names exactly, a folder of the agent that holds the path, and
/// a path that is not there under a stdio MCP server.
#[test]
fn a_grant_over_a_path_of_a_secret_source_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let tool = "[tool.aws]\ncommand = [\"/usr/bin/true\"]\n\
                [tool.aws.filesystem]\nread = [\"~/.aws\"]\n";
    let server = "[mcp.files]\ntype = \"stdio\"\ncommand = [\"files-server\"]\n\
                  [mcp.files.filesystem]\nread = [\"~/Library/Group Containers/vault/t\"]\n";
    for (name, rest, agent_reads) in [
        ("protected-store", tool, None),
        ("protected-folder", "", Some(".config")),
        ("protected-absent", server, None),
    ] {
        let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
        let mut request = with_vault(
            name,
            &permit_egress_to("api.example.test", 443),
            &protecting_sources(&program.path(), rest),
        );
        let home = request
            .operator_home()
            .canonicalize()
            .expect("the operator home resolves");
        let expected = match name {
            "protected-store" => format!(
                "`[tool.aws]` filesystem entry \"~/.aws\" {}",
                source_path_refusal(&home.join(".aws"), "aws-secretsmanager", "reads", "~/.aws")
            ),
            "protected-folder" => format!(
                "`[agent]` filesystem entry {:?} {}",
                home.join(".config").display().to_string(),
                source_path_refusal(&home.join(".config/op"), "op", "reads", "~/.config/op")
            ),
            _ => format!(
                "`[mcp.files]` filesystem entry \"~/Library/Group Containers/vault/t\" {}",
                source_path_refusal(
                    &home.join("Library/Group Containers/vault"),
                    "aws-secretsmanager",
                    "deny",
                    "~/Library/Group Containers/vault"
                )
            ),
        };
        if let Some(folder) = agent_reads {
            request = request.agent_read(&[&home.join(folder)]);
        }
        let (box_, output) = request.attempt();
        assert_refused(&box_, &output, &[&expected]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("reads each op:// secret"), "{stderr}");
        assert_eq!(
            program.runs(),
            Vec::<String>::new(),
            "{name}: no program starts in a box that lets a workload reach the vault"
        );
    }
}

/// **A grant that reaches an absent path of a plugin's list stops the box on each operating
/// system**: with `reads = ["~/.config/op", "~/.op"]` and only the first folder there, a tool
/// that reads `~/.op` is refused before a program starts, and the same table with no such grant
/// starts.
#[test]
fn a_grant_over_an_absent_path_of_a_plugin_list_is_refused() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let attempt = |name: &str, tool: &str| {
        let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
        let request = Request::with_config(
            name,
            &permit_egress_to("api.example.test", 443),
            &format!(
                "[experimental-features]\nsecret-sources = true\n\
                 [secret-source.op]\nprotocol = \"box.secret-source.v1\"\n\
                 command = [{:?}, \"read\", \"op://{{ref}}\"]\n\
                 reads = [\"~/.config/op\", \"~/.op\"]\n{}{tool}",
                program.path(),
                declared_route("api.example.test", "op://Personal/GitHub/token")
            ),
        );
        let home = request
            .operator_home()
            .canonicalize()
            .expect("the operator home resolves");
        std::fs::create_dir_all(home.join(".config/op")).expect("the folder of the vault");
        let (box_, output) = request.attempt();
        (program, home, box_, output)
    };

    let (program, home, box_, output) = attempt(
        "plugin-absent-grant",
        "[tool.old]\ncommand = [\"/usr/bin/true\"]\n[tool.old.filesystem]\nread = [\"~/.op\"]\n",
    );
    assert_refused(
        &box_,
        &output,
        &[&format!(
            "`[tool.old]` filesystem entry \"~/.op\" {}",
            source_path_refusal(&home.join(".op"), "op", "reads", "~/.op")
        )],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("reads each op:// secret"), "{stderr}");
    assert_eq!(program.runs(), Vec::<String>::new());

    // The control: the same lists with no grant above them.
    let (program, _, _box, output) = attempt("plugin-absent-start", "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    assert_eq!(program.runs(), ["read op://Personal/GitHub/token"]);
}

/// The value of a vault credential of the operator, which must never appear inside the box.
const VAULT_CREDENTIAL: &str = "ops_vault_credential_of_the_operator_41c7";

/// **The program of a source gets the operator's value of a `pass-secret-env` variable, and a
/// workload does not**: the box starts, and the workload holds its own value under that name.
#[test]
fn a_workload_holds_a_placeholder_under_the_name_of_a_vault_credential() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let program = StandInProgram::new(&format!(
        "printf '%s' \"$OP_SERVICE_ACCOUNT_TOKEN\" > \"$0.credential\"\n\
         printf '%s\\n' {DECLARED_SECRET}"
    ));
    let (box_, output) = with_vault(
        "protected-run",
        &permit_egress_to("api.example.test", 443),
        &protecting_sources(&program.path(), ""),
    )
    .env("OP_SERVICE_ACCOUNT_TOKEN", VAULT_CREDENTIAL)
    .agent_env("OP_SERVICE_ACCOUNT_TOKEN", "a-placeholder-of-the-profile")
    .attempt();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    assert_eq!(program.runs(), ["read op://Personal/GitHub/token"]);
    assert_eq!(
        std::fs::read_to_string(format!("{}.credential", program.path()))
            .expect("the program wrote what it received"),
        VAULT_CREDENTIAL,
        "the program of the source receives the credential of the vault"
    );

    let output = box_.run(&["/usr/bin/env"]);
    let environment = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        environment.contains("OP_SERVICE_ACCOUNT_TOKEN=a-placeholder-of-the-profile\n"),
        "{environment}"
    );
    assert!(!environment.contains(VAULT_CREDENTIAL), "{environment}");
}

/// **A tool cannot see a path of a secret source, and policy alone decides the Shell there**: a
/// tool reads the size of an ordinary file under the home and gets nothing for a file that a
/// source protects. Stated limit: a write that policy permits changes a file of one source
/// through the Shell, and a `forbid` rule keeps the file of the other.
#[test]
fn a_tool_cannot_see_a_path_of_a_secret_source_and_policy_decides_the_shell() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "stat" };
permit(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource);
forbid(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource)
when { context.input.path == "~/.aws" || context.input.path like "~/.aws/*" };
"#;
    const SETTINGS: &str = "the settings of the vault";
    // The size of a file, as the `stat` of each operating system prints it.
    let size = if cfg!(target_os = "macos") {
        "-f plain=%z"
    } else {
        "-c plain=%s"
    };
    // On macOS the tool finds the ordinary file with no grant, so the sandbox is what hides the
    // file of the vault. On Linux a tool sees no file under the home without a grant, so it has
    // one for the ordinary file, and the tool half shows only that no grant reaches the vault:
    // `a_tool_reads_an_empty_file_in_place_of_a_protected_file` pins what the sandbox covers.
    let tool = if cfg!(target_os = "linux") {
        "[tool.stat]\ncommand = [\"stat\"]\n[tool.stat.filesystem]\nread_file = [\"~/notes.txt\"]\n"
    } else {
        "[tool.stat]\ncommand = [\"stat\"]\n"
    };
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let request = with_vault(
        "protected-tool",
        POLICY,
        &protecting_sources(&program.path(), tool),
    );
    let home = request
        .operator_home()
        .canonicalize()
        .expect("the operator home resolves");
    let (plain, settings, forbidden) = (
        home.join("notes.txt"),
        home.join(".config/op/config"),
        home.join(".aws/config"),
    );
    std::fs::write(&plain, "0123456789").expect("write an ordinary file");
    for file in [&settings, &forbidden] {
        std::fs::write(file, SETTINGS).expect("write the settings");
    }
    let box_ = request.expect();

    let vault = size.replace("plain", "vault");
    let output = box_.bash(&format!(
        "zsh -lc 'stat {size} \"{plain}\"'; echo \"plain_rc=$?\"\n\
         zsh -lc 'stat {vault} \"{settings}\"'; echo \"vault_rc=$?\"\n\
         zsh -lc 'printf changed > \"{plain}\"'; echo \"plain_write_rc=$?\"\n\
         zsh -lc 'printf changed > \"{settings}\"'; echo \"vault_write_rc=$?\"\n\
         zsh -lc 'printf changed > \"{forbidden}\"'; echo \"forbidden_write_rc=$?\"\n",
        plain = plain.display(),
        settings = settings.display(),
        forbidden = forbidden.display()
    ));
    let seen = String::from_utf8_lossy(&output.stdout).into_owned();
    let printed = |line: &str| seen.lines().any(|printed| printed == line);
    assert!(
        printed("plain=10") && printed("plain_rc=0"),
        "the tool must see an ordinary file, so that the next refusal means something: {output:?}"
    );
    assert!(!seen.contains("vault="), "{output:?}");
    assert!(printed("vault_rc=1"), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(&plain).expect("the ordinary file"),
        "changed",
        "the Shell must change an ordinary file, so that the next refusal means something: \
         {output:?}"
    );
    // The stated limit. When a floor beneath policy refuses this change, remove this half and
    // the limit in `docs/user/config.md` and `docs/design/limitations.md` together.
    assert_eq!(
        std::fs::read_to_string(&settings).expect("the settings of the vault"),
        "changed",
        "no floor refuses a change that policy permits: {output:?}"
    );
    // What an operator can do today.
    assert_eq!(
        std::fs::read_to_string(&forbidden).expect("the settings of the other vault"),
        SETTINGS,
        "{output:?}"
    );
    assert!(!printed("forbidden_write_rc=0"), "{output:?}");
}

/// **On Linux, the sandbox of a tool holds an empty file in place of a protected file** that
/// lies in a folder that Box adds to that sandbox itself.
#[cfg(target_os = "linux")]
#[test]
fn a_tool_reads_an_empty_file_in_place_of_a_protected_file() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    // A file under `/usr/lib`, which Box adds to the sandbox of each tool, and a file that Box
    // adds by its own name.
    const PROTECTED: &str = "/usr/lib/os-release";
    const CONTROL: &str = "/etc/ld.so.cache";
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "stat" };
"#;
    let size = |path: &str| {
        std::fs::symlink_metadata(path)
            .ok()
            .filter(|metadata| metadata.is_file() && metadata.len() > 0)
            .map(|metadata| metadata.len())
    };
    let (Some(protected), Some(control)) = (size(PROTECTED), size(CONTROL)) else {
        println!("skipping: {PROTECTED} or {CONTROL} is not a file with content on this host");
        return;
    };
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let route = declared_route("api.example.test", "op://Personal/GitHub/token");
    // The `deny` key comes first, so that it is a key of the `[secret-source.op]` table.
    let box_ = with_vault(
        "protected-cell",
        POLICY,
        &declared_source(
            true,
            &program.path(),
            &format!("deny = [{PROTECTED:?}]\n{route}[tool.stat]\ncommand = [\"stat\"]\n"),
        ),
    )
    .expect();

    let output = box_.bash(&format!(
        "zsh -lc 'stat -c control=%s {CONTROL}'; echo \"control_rc=$?\"\n\
         zsh -lc 'stat -c vault=%s {PROTECTED}'; echo \"vault_rc=$?\"\n"
    ));
    let seen = String::from_utf8_lossy(&output.stdout).into_owned();
    let printed = |line: &str| seen.lines().any(|printed| printed == line);
    assert!(
        printed(&format!("control={control}")) && printed("control_rc=0"),
        "the tool must read the size of a file that Box adds, so that the next line means \
         something: {output:?}"
    );
    assert!(
        printed("vault=0") && printed("vault_rc=0"),
        "the tool must find an empty file in place of the {protected} bytes of {PROTECTED}: \
         {output:?}"
    );
}

/// **A tool that the run leaves out brings no table to the check of the secret sources**: its
/// write grant over the program of a source stops no box, and the same table stops the box when
/// its program is installed.
#[test]
fn a_left_out_tool_with_a_write_grant_over_a_secret_source_program_stops_no_box() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let attempt = |name: &str, tool_program: &dyn Fn(&std::path::Path) -> String| {
        let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
        let folder = program
            .directory
            .path()
            .canonicalize()
            .expect("the program folder resolves");
        let tool_program = tool_program(&folder);
        let grant = folder.display().to_string();
        let tool = format!(
            "[tool.spare]\ncommand = [{tool_program:?}]\n[tool.spare.filesystem]\n\
             read = [{grant:?}]\nwrite = [{grant:?}]\n"
        );
        let (box_, output) = with_vault(
            name,
            &permit_egress_to("api.example.test", 443),
            &declared_source(
                true,
                &program.path(),
                &format!(
                    "{}{tool}",
                    declared_route("api.example.test", "op://Personal/GitHub/token")
                ),
            ),
        )
        .attempt();
        (program, folder, tool_program, box_, output)
    };

    let (program, folder, _, box_, output) =
        attempt("declared-tool-kept", &|_| "/usr/bin/true".to_string());
    assert_refused(
        &box_,
        &output,
        &[
            "`[tool.spare]` filesystem entry",
            &format!(
                "this write grant can change [secret-source.op] command {} or its path",
                folder.join("vault-stand-in").display()
            ),
        ],
    );
    assert_eq!(program.runs(), Vec::<String>::new());

    let (program, _, absent, _box, output) = attempt("declared-tool-left-out", &|folder| {
        folder.join("absent-tool").display().to_string()
    });
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    assert!(
        stderr.contains(&format!(
            "strands-box: [tool.spare] left out: {absent} not found\n"
        )),
        "{stderr}"
    );
    assert_eq!(program.runs(), ["read op://Personal/GitHub/token"]);
}

/// The stderr of the first run of a new box directory, which must stop, each entry that the
/// run left in that directory, and the next run in it after `fix` removes the cause.
fn first_run_then_fixed(
    name: &str,
    body: &str,
    request: impl FnOnce(Request) -> Request,
    fix: impl FnOnce(),
) -> (String, Vec<String>, Output) {
    let (box_, output) = request(with_vault(
        name,
        &permit_egress_to("api.example.test", 443),
        body,
    ))
    .attempt();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "{name}: the first run must stop: {stderr}"
    );
    let mut stored: Vec<String> = std::fs::read_dir(box_.root())
        .expect("the box directory lists")
        .map(|entry| {
            entry
                .expect("an entry of the box directory")
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    stored.sort();
    fix();
    let next = box_.run(&["/bin/bash", "-c", "printf 'READY\\n'"]);
    (stderr, stored, next)
}

/// **A run that the check of the secret sources refuses stores nothing in a new box
/// directory**: the operator removes the cause, and the next run starts in the same directory.
#[test]
fn a_new_box_directory_starts_after_the_cause_of_a_secret_source_refusal_is_gone() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let route = declared_route("api.example.test", "op://Personal/GitHub/token");

    // The program file is absent, and then the operator installs it.
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let installed = std::path::PathBuf::from(program.path());
    let later = installed.with_extension("later");
    std::fs::rename(&installed, &later).expect("the program is not installed yet");
    let (stderr, stored, next) = first_run_then_fixed(
        "first-run-absent",
        &declared_source(true, &program.path(), &route),
        |request| request,
        || std::fs::rename(&later, &installed).expect("the operator installs the program"),
    );
    assert!(stderr.contains("its program cannot run"), "{stderr}");
    assert_eq!(
        stored,
        Vec::<String>::new(),
        "the refused run stores nothing"
    );
    assert_ran(&next);

    // A write grant covers the file that the program path resolves to, and then the operator
    // points the path at a copy outside the grant.
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let outside = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let links = fixture::short_temporary_home();
    let link = links.path().join("op");
    std::os::unix::fs::symlink(program.path(), &link).expect("the program path is a link");
    let folder = program
        .directory
        .path()
        .canonicalize()
        .expect("the program folder resolves");
    let (stderr, stored, next) = first_run_then_fixed(
        "first-run-writable",
        &declared_source(true, &link.display().to_string(), &route),
        |request| request.agent_read(&[&folder]).agent_write(&[&folder]),
        || {
            std::fs::remove_file(&link).expect("the link is removed");
            std::os::unix::fs::symlink(outside.path(), &link).expect("the link names the copy");
        },
    );
    assert!(
        stderr.contains("this write grant can change [secret-source.op] command"),
        "{stderr}"
    );
    assert_eq!(
        stored,
        Vec::<String>::new(),
        "the refused run stores nothing"
    );
    assert_ran(&next);
    assert_eq!(program.runs(), Vec::<String>::new());

    // The control: a route secret that the source does not return, and then returns.
    let program = StandInProgram::new(&format!(
        "test -e \"$(dirname \"$0\")/signed-in\" || {{ echo 'not signed in' >&2; exit 3; }}\n\
         printf '%s\\n' {DECLARED_SECRET}"
    ));
    let marker = program.directory.path().join("signed-in");
    let (stderr, stored, next) = first_run_then_fixed(
        "first-run-route",
        &declared_source(true, &program.path(), &route),
        |request| request,
        || std::fs::write(&marker, "").expect("the operator signs in"),
    );
    assert!(
        stderr.contains("did not return, so the box does not start"),
        "{stderr}"
    );
    assert!(stored.contains(&"private".to_string()), "{stored:?}");
    assert_ran(&next);
}

/// **The limit: a telemetry secret that the program does not return on the first run of a new
/// box directory leaves a record with no history**, so the next run stops until the operator
/// empties the directory, because the read runs a program and so comes after Box stores the
/// record.
#[test]
fn a_telemetry_secret_that_is_not_returned_on_a_first_run_still_strands_the_box_directory() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let program = StandInProgram::new(&format!(
        "test -e \"$(dirname \"$0\")/signed-in\" || {{ echo 'not signed in' >&2; exit 3; }}\n\
         printf '{{\"TELEMETRY\":\"%s\"}}\\n' {DECLARED_SECRET}"
    ));
    let marker = program.directory.path().join("signed-in");
    let (stderr, stored, next) = first_run_then_fixed(
        "first-run-otlp",
        &declared_source(
            true,
            &program.path(),
            "[telemetry.vendor]\nkind = \"otlp\"\ndestination = \"http://127.0.0.1:9\"\n\
             secret.ref = \"op://box/keys#TELEMETRY\"\n",
        ),
        |request| request,
        || std::fs::write(&marker, "").expect("the operator signs in"),
    );
    assert!(
        stderr.contains("`[telemetry.vendor] secret.ref` names a secret that the secret source"),
        "{stderr}"
    );
    assert!(stored.contains(&"private".to_string()), "{stored:?}");
    let refusal = String::from_utf8_lossy(&next.stderr);
    assert!(!next.status.success(), "{refusal}");
    assert!(
        refusal.contains("the box record is committed, but the history")
            && refusal.contains("is absent. Wipe the box directory to start again."),
        "{refusal}"
    );
    assert_eq!(program.runs().len(), 1, "the next run stops before a read");
}

/// **A telemetry target and a route that name one secret run the program once**, the target
/// receives its field of that secret, and both reads are recorded after the collector opens.
#[test]
fn a_telemetry_target_and_a_route_with_one_secret_run_the_program_once() {
    use std::io::{BufRead as _, BufReader};
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("a stand-in telemetry endpoint");
    let port = listener.local_addr().expect("its port").port();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut head = String::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).ok();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            let _ = sender.send(head);
        }
    });

    let program = StandInProgram::new(
        r#"printf '{"TELEMETRY":"vendor-key-declared","ROUTE":"route-key-declared"}\n'"#,
    );
    let records = program.directory.path().join("records.jsonl");
    let (_box, output) = with_vault(
        "declared-shared",
        &permit_egress_to("api.example.test", 443),
        &declared_source(
            true,
            &program.path(),
            &format!(
                "{}[telemetry.vendor]\nkind = \"otlp\"\n\
                 destination = \"http://127.0.0.1:{port}\"\n\
                 secret.ref = \"op://box/keys#TELEMETRY\"\nsecret.header = \"x-vendor-team\"\n\
                 [telemetry.file]\nkind = \"file\"\ndestination = {:?}\n",
                declared_route("api.example.test", "op://box/keys#ROUTE"),
                records.display().to_string()
            ),
        ),
    )
    .attempt();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    assert_eq!(
        program.runs(),
        ["read op://box/keys"],
        "one secret is one run of the program, with no field in its argument"
    );
    let head = receiver
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the target receives a batch")
        .to_ascii_lowercase();
    assert!(
        head.contains("x-vendor-team: vendor-key-declared"),
        "the target receives its field of the secret: {head}"
    );
    assert!(!head.contains("route-key-declared"), "{head}");
    let records = std::fs::read_to_string(&records).expect("the file target holds the records");
    let detail = format!(
        "source `op`, program {}, reference op://[REDACTED]",
        program.path()
    );
    assert_eq!(
        secret_fetch_records(&records),
        ["[telemetry.vendor] secret.ref", "[egress.c] secret.ref"].map(|entry| [
            "ok".to_string(),
            entry.to_string(),
            detail.clone(),
            String::new()
        ])
    );
    assert!(
        records.find("box_started") < records.find("secret_fetched"),
        "the record of the start comes first"
    );
}

/// **A secret source that returns no secret stops the box before the workload starts**: stderr
/// holds the words of the program and names the entry, and no record holds those words.
#[test]
fn a_secret_source_that_fails_stops_the_box_before_the_workload() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let program = StandInProgram::new("echo 'no item BoxTest in the vault Personal' >&2\nexit 3");
    let said = format!(
        "credential error: the secret source \"op\" ({:?}) for op://[REDACTED] exited \
         unsuccessfully (exit status: 3): no item BoxTest in the vault Personal\n",
        program.path()
    );
    let refusal = |entry: &str| {
        format!(
            "strands-box: error: `{entry}` names a secret that the secret source `op` ({}) did \
             not return, so the box does not start\n",
            program.path()
        )
    };

    // A route: the collector is open, so the read is recorded, without the program's words.
    let (box_, output) = with_vault(
        "declared-fails",
        &permit_egress_to("api.example.test", 443),
        &declared_source(
            true,
            &program.path(),
            &declared_route("api.example.test", "op://Personal/GitHub/token"),
        ),
    )
    .attempt();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the box must not start: {stderr}");
    assert!(
        stderr.ends_with(&format!(
            "strands-box: [egress.c] secret.ref: {said}{}",
            refusal("[egress.c] secret.ref")
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("strands-box: starting workload"),
        "{stderr}"
    );
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("the records of the refused run");
    assert_eq!(
        secret_fetch_records(&records),
        [[
            "refused".to_string(),
            "[egress.c] secret.ref".to_string(),
            format!(
                "source `op`, program {}, reference op://[REDACTED]",
                program.path()
            ),
            "the secret source returned no secret; the standard error of the box holds the \
             reason"
                .to_string(),
        ]]
    );
    assert!(!records.contains("BoxTest"), "{records}");

    // A telemetry target: no collector exists yet, so stderr alone states the failed read.
    let (box_, output) = with_vault(
        "declared-telemetry-fails",
        &permit_egress_to("api.example.test", 443),
        &declared_source(
            true,
            &program.path(),
            "[telemetry.vendor]\nkind = \"otlp\"\ndestination = \"http://127.0.0.1:9\"\n\
             secret.ref = \"op://box/keys#TELEMETRY\"\n",
        ),
    )
    .attempt();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the box must not start: {stderr}");
    assert!(
        stderr.ends_with(&format!(
            "strands-box: [telemetry.vendor] secret.ref: {said}{}",
            refusal("[telemetry.vendor] secret.ref")
        )),
        "{stderr}"
    );
    assert_eq!(
        files_holding(&box_.root(), "secret_fetched"),
        Vec::<std::path::PathBuf>::new(),
        "no collector opened, so no file holds a record of the read"
    );
    assert_eq!(
        program.runs().len(),
        2,
        "each refused run starts the program once"
    );
}

/// **Each unsafe secret source configuration is refused through the shipped binary**, before a
/// box exists.
#[test]
fn an_unsafe_secret_source_configuration_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let env_route = |name: &str| {
        format!(
            "[egress.c]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"env://{name}\"\n"
        )
    };
    for (name, body, expected) in [
        (
            "src-no-switch",
            declared_source(false, "/usr/bin/true", DECLARED_ROUTE),
            "invalid `[secret-source.op]` table: a secret source is experimental: set \
             `secret-sources = true` in `[experimental-features]` to load it",
        ),
        (
            "src-bare-program",
            declared_source(true, "op", DECLARED_ROUTE),
            "invalid `[secret-source.op]` table: credential error: the secret source \"op\" \
             names the program \"op\", which is not an absolute path",
        ),
        (
            "src-no-variable",
            declared_source(
                true,
                "/usr/bin/true",
                "[egress.c]\ndestinations = [\"api.example.test\"]\n\
                 secret.ref = \"op://Personal/GitHub/token\"\n",
            ),
            "a reference in the op:// scheme needs secret.env",
        ),
        (
            "src-own-credential",
            declared_source(
                true,
                "/usr/bin/true",
                &env_route("OP_SERVICE_ACCOUNT_TOKEN"),
            ),
            "the variable OP_SERVICE_ACCOUNT_TOKEN is a credential of the secret source `op`",
        ),
        (
            "src-own-prefix",
            declared_source(true, "/usr/bin/true", &env_route("OP_SESSION_abc")),
            "the variable OP_SESSION_abc is a credential of the secret source `op`",
        ),
        (
            "src-not-declared",
            DECLARED_ROUTE.to_string(),
            "secret scheme \"op\" has no `[secret-source.op]` table",
        ),
    ] {
        let (box_, output) =
            Request::with_config(name, &permit_egress_to("api.example.test", 443), &body)
                .env("OP_SERVICE_ACCOUNT_TOKEN", "ops_real_service_account_token")
                .env("OP_SESSION_abc", "real_session_token")
                .attempt();
        assert_refused(&box_, &output, &[expected]);
        assert!(
            !box_.root().join("private/box.toml").exists(),
            "{name}: a refused configuration stores no record"
        );
    }
}

/// **`secret.env` is refused while `secret-sources` is off**, through the shipped binary, on each
/// operating system.
#[test]
fn a_placeholder_variable_key_is_refused_while_the_switch_is_off() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "env-key-no-switch",
        &permit_egress_to("api.example.test", 443),
        &format!(
            "[egress.c]\ndestinations = [\"api.example.test\"]\n\
             secret.ref = \"env://{SECRET_VARIABLE}\"\nsecret.env = \"{SECRET_VARIABLE}\"\n"
        ),
    );
    assert_refused(
        &box_,
        &output,
        &[
            "secret.env is experimental: set `secret-sources = true` in \
           `[experimental-features]` to load it, or remove secret.env, because an env:// \
           reference already names its variable",
        ],
    );
    assert!(
        !box_.root().join("private/box.toml").exists(),
        "a refused configuration stores no record"
    );
}

/// **On Linux, a `reads` or `deny` entry whose path does not exist is skipped**: the box starts,
/// one line names each skipped entry, a tool whose program is a script starts, and the entry
/// whose path is there is protected.
#[cfg(target_os = "linux")]
#[test]
fn an_entry_whose_path_is_absent_is_skipped_and_named_and_the_box_starts() {
    use std::os::unix::fs::PermissionsExt as _;
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource);
"#;
    // The folder of an application of macOS, which a Linux host never has.
    const APP: &str = "~/Library/Group Containers/2BUA8C4S2C.com.1password";
    let Ok(bash) = std::fs::canonicalize("/bin/bash") else {
        println!("skipping: /bin/bash does not resolve on this host");
        return;
    };
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let tools = fixture::short_temporary_home();
    let script = tools.path().join("scripted");
    std::fs::write(&script, "#!/bin/bash\nprintf 'SCRIPT_TOOL_RAN\\n'\n").expect("write the tool");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("make the tool executable");
    let (script, bash) = (script.display().to_string(), bash.display().to_string());
    // The lists of a plugin that names each place that a vault can have: one folder is there.
    let request = Request::with_config(
        "skipped-entries",
        POLICY,
        &format!(
            "[experimental-features]\nsecret-sources = true\n\
             [secret-source.op]\nprotocol = \"box.secret-source.v1\"\n\
             command = [{:?}, \"read\", \"op://{{ref}}\"]\n\
             reads = [\"~/.config/op\", \"~/.op\"]\ndeny = [{APP:?}]\n{}\
             [tool.scripted]\ncommand = [{script:?}]\n\
             [tool.scripted.filesystem]\nread_file = [{script:?}, {bash:?}]\n",
            program.path(),
            declared_route("api.example.test", "op://Personal/GitHub/token")
        ),
    );
    let home = request
        .operator_home()
        .canonicalize()
        .expect("the operator home resolves");
    std::fs::create_dir_all(home.join(".config/op")).expect("the folder of the vault");
    std::fs::write(home.join(".config/op/config"), "the settings").expect("the settings");
    let (box_, output) = request.attempt();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the box must start: {stderr}");
    let skipped = |list: &str, entry: &str| {
        format!(
            "strands-box: [secret-source.op]: `{list}` entry {entry:?} names {}, which does not \
             exist when the box starts, so no sandbox denies it in this run\n",
            home.join(entry.trim_start_matches("~/")).display()
        )
    };
    let lines = format!(
        "strands-box: [secret-source.op]: reads each op:// secret with {}, which runs outside \
         every sandbox\n{}{}",
        program.path(),
        skipped("reads", "~/.op"),
        skipped("deny", APP)
    );
    assert!(stderr.contains(&lines), "{stderr}");
    assert_eq!(program.runs(), ["read op://Personal/GitHub/token"]);

    let output = box_.bash(&format!(
        "zsh -lc 'scripted'; echo \"script_rc=$?\"\n\
         if [ -d '{vault}' ]; then echo vault=folder; fi\n\
         if [ -e '{vault}/config' ]; then echo config=there; fi\n\
         if [ -e '{home}/.op' ]; then echo skipped=there; fi\n",
        vault = home.join(".config/op").display(),
        home = home.display()
    ));
    let seen = String::from_utf8_lossy(&output.stdout).into_owned();
    let printed = |line: &str| seen.lines().any(|printed| printed == line);
    assert!(
        printed("SCRIPT_TOOL_RAN") && printed("script_rc=0"),
        "a tool whose program is a script must start beside a skipped entry: {output:?}"
    );
    assert!(
        printed("vault=folder") && !printed("config=there"),
        "the agent must find an empty folder in place of the folder that is there: {output:?}"
    );
    assert!(!printed("skipped=there"), "{output:?}");
}

/// **On Linux, a `reads` or `deny` entry that names a socket stops the box before a program
/// starts and before Box stores a record**, and the refusal says to name the folder.
#[cfg(target_os = "linux")]
#[test]
fn an_entry_that_names_a_socket_stops_the_box_before_a_program_starts() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let program = StandInProgram::new(&format!("printf '%s\\n' {DECLARED_SECRET}"));
    let route = declared_route("api.example.test", "op://Personal/GitHub/token");
    // The socket is outside each folder that the table names. The `deny` key comes first, so
    // that it is a key of the `[secret-source.op]` table.
    let request = with_vault(
        "socket-entry",
        &permit_egress_to("api.example.test", 443),
        &declared_source(
            true,
            &program.path(),
            &format!("deny = [\"~/.op/agent.sock\"]\n{route}"),
        ),
    );
    let folder = request
        .operator_home()
        .canonicalize()
        .expect("the operator home resolves")
        .join(".op");
    std::fs::create_dir(&folder).expect("the folder of the socket");
    let socket = folder.join("agent.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("a socket of the vault");
    let (box_, output) = request.attempt();
    assert_refused(
        &box_,
        &output,
        &[&format!(
            "invalid `[secret-source.op]` table: `deny` entry \"~/.op/agent.sock\" names \
             {}, which is not a folder or a regular file. On Linux, Box protects only a folder \
             or a regular file: name the folder that holds it, or remove the entry",
            socket.display()
        )],
    );
    assert_eq!(program.runs(), Vec::<String>::new());
    assert_eq!(
        std::fs::read_dir(box_.root())
            .expect("the box directory lists")
            .count(),
        0,
        "the refused run stores nothing"
    );
}

/// One table over the refusals an operator is most likely to trip, through the shipped binary.
///
/// **The 80/20 of this surface, deliberately as one test rather than eleven.** Each row is a
/// spelling a real `strands-box.toml` can contain; the per-row unit tests in `config.rs` cover the
/// reasoning, and this covers that the *binary* refuses them before a box tree exists. `*:443` is the
/// row that matters most: it exited 0 before this work, with the stored record round-tripping it.
///
/// Accept rows are here too, and are not filler — a validator that refused everything would pass a
/// refuse-only table just as happily.
#[test]
fn the_operator_reachable_credential_refusals_hold_end_to_end() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let policy = permit_egress_to("api.example.test", 443);

    // (name, credential-toml, expected substring of the refusal — None means "must be accepted")
    let cases: &[(&str, String, Option<&str>)] = &[
        // Endpoint breadth: a suffix wildcard is deliberate, an all-hosts pattern is not, and the
        // `*:<port>` family is what a text comparison missed.
        ("ep-exact", target("api.example.test"), None),
        ("ep-suffix", target("*.example.test"), None),
        ("ep-star", target("*"), Some("every permitted request")),
        (
            "ep-star-443",
            target("*:443"),
            Some("every permitted request"),
        ),
        (
            "ep-star-8443",
            target("*:8443"),
            Some("every permitted request"),
        ),
        // Credential schemes the box cannot deliver.
        (
            "scheme-file",
            with_credential("file:///etc/hosts"),
            Some("env://"),
        ),
        ("scheme-cmd", with_credential("cmd://mint"), Some("env://")),
        // Placement surface: the two available modes, and the one withheld by name.
        ("placement-basic", with_placement("basic_auth", None), None),
        (
            "placement-query",
            with_placement("query_param", Some("key")),
            None,
        ),
        (
            "placement-url-path",
            with_placement("url_path", None),
            Some("not available"),
        ),
        (
            "placement-query-no-param",
            with_placement("query_param", None),
            Some("needs credential_param"),
        ),
    ];

    for (name, toml, expected) in cases {
        match expected {
            None => {
                let box_ = box_with_credentials(name, &policy, toml);
                assert_ran(&workload(&box_, "printf 'done\\n'"));
            }
            Some(fragment) => {
                let (box_, output) = attempt_configure(name, &policy, toml);
                assert_refused(&box_, &output, &[fragment]);
            }
        }
    }
}

/// An `[[credential]]` naming `endpoint` with the given credential locator.
fn with_credential(locator: &str) -> String {
    format!("[egress.d]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"{locator}\"\n")
}

/// An `[[credential]]` with a placement and its optional argument.
fn with_placement(placement: &str, param: Option<&str>) -> String {
    let param = param
        .map(|p| format!("secret.param = \"{p}\"\n"))
        .unwrap_or_default();
    format!(
        "[egress.e]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"env://{SECRET_VARIABLE}\"\nsecret.placement = \"{placement}\"\n{param}"
    )
}

/// A target with no credential is refused: it would declare only a destination.
#[test]
fn an_entry_without_a_secret_is_refused_at_create() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "no-credential",
        &permit_egress_to("api.example.test", 443),
        "[egress.f]\ndestinations = [\"api.example.test\"]\nsecret.ref = \"\"\n",
    );
    assert_refused(&box_, &output, &["secret is required"]);
}

/// A typo is a load error, not a silently-dropped field.
#[test]
fn an_unknown_config_field_is_refused_at_configure() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let (box_, output) = attempt_configure(
        "typo",
        &permit_egress_to("api.example.test", 443),
        &format!(
            "{}credentail_header = \"x-api-key\"\n",
            target("api.example.test")
        ),
    );
    assert_refused(&box_, &output, &["cannot parse config"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// The swap, end to end against a real upstream.
// ═══════════════════════════════════════════════════════════════════════════════

/// A configured destination is reachable through the boundary, and the boundary — not
/// the workload — decides what is attached.
///
/// The wire-level swap (phantom out, `Real_Secret` upstream) is proven at the proxy layer
/// in `egress-proxy`'s `interception_e2e.rs::opaque_swap_reaches_upstream_with_real_secret`,
/// which can supply `upstream_ca_pems` for a fixture upstream. `strands-box` deliberately
/// does **not** expose that knob — an operator cannot make the box trust an arbitrary
/// upstream CA — so this layer asserts what only it can: the config-declared destination
/// is admitted, the request is governed end to end, and the secret never enters the box.
#[test]
fn a_configured_destination_is_admitted_through_the_boundary() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = RecordingUpstream::start();
    let host = "localhost";
    let box_ = box_with_credentials(
        "admitted",
        &permit_egress_to(host, upstream.port),
        &target(&format!("{host}:{}", upstream.port)),
    );

    let output = probe(
        &box_,
        SECRET_VARIABLE,
        &format!("https://{host}:{}/v1/charge", upstream.port),
    );
    let out = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // The CONNECT was admitted: the probe got past the floor, the pin, and `net:connect`,
    // and completed a TLS handshake against the box's own ephemeral CA. A denial would
    // have surfaced as `status=403` from the proxy instead.
    assert!(
        !out.contains("status=403"),
        "the configured destination must be admitted: stdout={out:?} stderr={stderr:?}"
    );
    // The upstream leg fails closed because the box will not trust a fixture CA, which is
    // itself the property worth pinning: there is no operator knob to weaken it.
    assert!(
        !stderr.contains("HTTPS_PROXY is not set"),
        "the daemon's proxy must be seeded into the workload: {stderr:?}"
    );
    assert!(
        !stderr.contains("NODE_EXTRA_CA_CERTS is not set"),
        "the daemon's intercept CA must be seeded into the workload: {stderr:?}"
    );

    // Whatever happened on the wire, the real secret never entered the box.
    assert!(
        !out.contains(REAL_SECRET) && !stderr.contains(REAL_SECRET),
        "the real secret must never appear inside the box: {out:?} / {stderr:?}"
    );
}

/// The workload's own environment holds a phantom of the minted form, never the secret.
///
/// The companion to the swap test: that one proves the upstream got the real secret,
/// this one proves the box never had it. `env` is the workload, so no shell is needed.
#[test]
fn the_workload_environment_holds_only_a_phantom() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = RecordingUpstream::start();
    let box_ = box_with_credentials(
        "phantom-env",
        &permit_egress_to("localhost", upstream.port),
        &target(&format!("localhost:{}", upstream.port)),
    );

    let output = box_.run(&["/usr/bin/env"]);
    let environment = String::from_utf8_lossy(&output.stdout).into_owned();

    let held = environment
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{SECRET_VARIABLE}=")))
        .unwrap_or_default();
    assert!(
        held.starts_with("strands_box_"),
        "the workload must hold a minted phantom, got {held:?}"
    );
    assert!(
        !environment.contains(REAL_SECRET),
        "the real secret must never enter the workload's environment"
    );
}

/// The hosted Shell holds the phantom the workload holds, never the secret.
#[test]
fn the_shell_holds_the_workloads_phantom_and_never_the_secret() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_with_credentials(
        "shell-phantom",
        &permit_egress_to("localhost", 9),
        &target("localhost:9"),
    );

    // Single quotes leave the variable for the Shell to expand, not the workload's `bash`.
    let output = workload(
        &box_,
        &format!(
            r#"printf 'workload=%s\n' "${SECRET_VARIABLE}"
               zsh -lc 'printf "shell=%s\n" "${SECRET_VARIABLE}"'"#
        ),
    );
    assert_ran(&output);

    let seen = stdout(&output);
    let phantom = seen
        .lines()
        .find_map(|line| line.strip_prefix("workload="))
        .unwrap_or_default()
        .to_string();
    assert!(
        phantom.starts_with("strands_box_"),
        "the workload must hold a minted phantom: {output:?}"
    );
    assert_eq!(
        seen,
        format!("workload={phantom}\nshell={phantom}"),
        "the Shell must expand the variable to the workload's phantom: {output:?}"
    );
    assert!(
        !format!("{output:?}").contains(REAL_SECRET),
        "the real secret must never reach the workload or the Shell: {output:?}"
    );
}

/// A phantom is a RUN-lifetime value, and it is stable for that run.
///
/// The phantom used to be minted once per daemon load and shared by every run of the box. Each
/// run now opens its own trusted half, so each mints its own — and that is sound because the
/// gateway which swaps the phantom for the real secret is the same process that minted it.
/// Nothing outside a run ever sees the pairing.
///
/// The authority path is unchanged, and this is the part worth pinning: the locator comes from the
/// stored record and the value from the operator's own environment, so the workload influences
/// neither. What each run must never hold is the real secret.
#[test]
fn a_phantom_is_stable_within_a_run_and_never_the_real_secret() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = RecordingUpstream::start();
    let box_ = box_with_credentials(
        "phantom-shared",
        &permit_egress_to("localhost", upstream.port),
        &target(&format!("localhost:{}", upstream.port)),
    );

    let phantoms_of = |output: &Output| -> Vec<String> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{SECRET_VARIABLE}=")))
            .map(str::to_string)
            .collect()
    };

    // Twice in ONE run, because one run owns a box. The gateway matches the value it
    // minted, so a phantom that changed between two reads inside a run would break every swap.
    // Bash builtins only: the profile grants exec on the workload and the aliases, so `printenv`
    // and `grep` are not in the cage and a pipeline through them measures nothing.
    let within = box_.bash(&format!(
        r#"printf "{SECRET_VARIABLE}=%s\n" "${SECRET_VARIABLE}"; \
           printf "{SECRET_VARIABLE}=%s\n" "${SECRET_VARIABLE}""#
    ));
    let seen = phantoms_of(&within);
    assert_eq!(
        seen.len(),
        2,
        "the run must report its phantom twice: {within:?}"
    );
    assert!(
        seen[0].starts_with("strands_box_"),
        "the run must hold a phantom, got {:?}",
        seen[0]
    );
    assert_eq!(
        seen[0], seen[1],
        "a phantom is stable for its run, because the gateway matches the value it minted"
    );

    // A second run holds a phantom of its own. It need not be the same one, and it must never be
    // the real secret.
    let next = phantoms_of(&box_.run(&["/usr/bin/env"]));
    let next = next.first().cloned().unwrap_or_default();
    assert!(
        next.starts_with("strands_box_"),
        "the next run must hold a phantom too, got {next:?}"
    );
    assert_ne!(
        next, REAL_SECRET,
        "no run may hold the real secret in its environment"
    );
}

/// A `net:connect` deny stops the request before any socket, credential or not.
///
/// A credential binding must not become a way to reach a host policy refuses: the
/// config says *what to attach*, never *where you may go*.
#[test]
fn a_credential_binding_does_not_grant_reachability() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = RecordingUpstream::start();
    let host = "localhost";
    // Policy permits a DIFFERENT port than the one the credential (and the request)
    // names, so the connect gate refuses.
    let box_ = box_with_credentials(
        "no-reach",
        &permit_egress_to(host, upstream.port.wrapping_add(1)),
        &target(&format!("{host}:{}", upstream.port)),
    );

    let output = probe(
        &box_,
        SECRET_VARIABLE,
        &format!("https://{host}:{}/v1/charge", upstream.port),
    );
    let out = String::from_utf8_lossy(&output.stdout).into_owned();

    // The upstream was never reached, so it recorded nothing.
    assert!(
        upstream.authorizations().is_empty(),
        "policy denied the connect, so no request may reach the upstream: {:?}",
        upstream.authorizations()
    );
    // The proxy answered the denial itself rather than the upstream answering.
    assert!(
        out.contains("status=403") || !out.contains("status=200"),
        "a denied destination must not report success: {out:?}"
    );
    // And the secret did not leak on the way.
    assert!(!out.contains(REAL_SECRET));
}

#[test]
fn policy_explanations_reach_the_contained_http_and_remote_mcp_workload() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let id = "request-\"\\\n";
    let frame = serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/list"
    })
    .to_string();
    for remote in [false, true] {
        for (annotations, expected) in [
            (
                Some(r#"@id("restricted") @description("Use the approved endpoint.")"#),
                "[policy: restricted]: Use the approved endpoint.",
            ),
            (Some(r#"@id("restricted")"#), "[policy: restricted]."),
            (
                None,
                "[default-deny]: No permit policy matched this request.",
            ),
        ] {
            let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
            upstream.set_nonblocking(true).unwrap();
            let authority = upstream.local_addr().unwrap().to_string();
            let transport = r#"permit(principal, action == Box::Action::"net:connect", resource);"#;
            let (action, permit, config) = if remote {
                (
                    "mcp:call",
                    r#"permit(principal, action == Box::Action::"http:request", resource);"#,
                    format!("[mcp.demo]\ntype = \"http\"\ndestinations = [\"{authority}\"]\n"),
                )
            } else {
                ("http:request", "", String::new())
            };
            let denial = annotations.map_or_else(String::new, |annotations| {
                format!(
                    r#"{annotations} forbid(principal, action == Box::Action::"{action}", resource);"#
                )
            });
            let box_ = Request::with_config(
                "denial-message",
                &format!("{transport}\n{permit}\n{denial}"),
                &config,
            )
            .expect();
            let output = box_.run(&[
                env!("CARGO_BIN_EXE_box-egress-probe"),
                "http-response",
                &authority,
                &frame,
            ]);
            assert!(output.status.success(), "{output:?}");
            let response = String::from_utf8(output.stdout).unwrap();
            assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
            let (_, body) = response.split_once("\r\n\r\n").unwrap();
            if remote {
                let reply: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(reply["id"], id);
                assert_eq!(reply["error"]["code"], -32001);
                assert!(
                    reply["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains(expected)
                );
            } else {
                assert!(body.contains(expected), "{body}");
            }
            let (mut connection, _) = upstream.accept().unwrap();
            connection
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            assert_eq!(connection.read(&mut [0; 1]).unwrap(), 0);
        }
    }
}

fn trace_probe(box_: &Configured, requests: &Value) -> Vec<Value> {
    let output = box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        "trace-requests",
        &requests.to_string(),
    ]);
    if !output.status.success() {
        eprintln!(
            "policy records after probe failure: {}",
            std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
                .unwrap_or_default()
        );
    }
    assert!(
        output.status.success(),
        "contained probe failed: {output:?}"
    );
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("probe response JSON"))
        .collect();
    assert_eq!(replies.len(), requests.as_array().unwrap().len());
    replies
}

fn optional_span_attribute<'a>(span: &'a Value, name: &str) -> Option<&'a str> {
    span["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|attribute| attribute["key"] == name)
        .and_then(|attribute| attribute["value"]["stringValue"].as_str())
}

fn span_attribute<'a>(span: &'a Value, name: &str) -> &'a str {
    optional_span_attribute(span, name)
        .unwrap_or_else(|| panic!("missing {name} in policy span: {span}"))
}

fn recorded_policy_spans(box_: &Configured) -> Vec<Value> {
    let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
        .expect("the real collector's records");
    // The default file reveals no tool-call value anywhere, and no decision or span carries one.
    assert!(!records.contains("unrelated-private-payload"));
    let mut decision_text = String::new();
    for line in records.lines() {
        let mut batch: Value = serde_json::from_str(line).expect("OTLP batch");
        for resource in batch["resourceLogs"].as_array_mut().into_iter().flatten() {
            if let Some(scopes) = resource["scopeLogs"].as_array_mut() {
                scopes.retain(|scope| scope["scope"]["name"] != "strands-box.mcp");
            }
        }
        decision_text.push_str(&batch.to_string());
    }
    assert!(
        !decision_text.contains("unrelated-private-payload"),
        "a decision or span must not carry a tool call's arguments"
    );
    let mut spans = Vec::new();
    let mut logs = Vec::new();
    for line in records.lines() {
        let batch: Value = serde_json::from_str(line).expect("OTLP batch");
        for (resources, scopes, items, output) in [
            ("resourceSpans", "scopeSpans", "spans", &mut spans),
            ("resourceLogs", "scopeLogs", "logRecords", &mut logs),
        ] {
            for resource in batch[resources].as_array().into_iter().flatten() {
                for scope in resource[scopes].as_array().into_iter().flatten() {
                    if scope["scope"]["name"] == "strands-box.policy" {
                        output.extend(scope[items].as_array().unwrap().iter().cloned());
                    }
                }
            }
        }
    }
    assert!(!spans.is_empty(), "no exported policy spans: {records}");
    assert_eq!(spans.len(), logs.len(), "each policy log exports one span");
    let mut ids = std::collections::HashSet::new();
    for span in &spans {
        assert_eq!(span["kind"], 1, "policy spans must be INTERNAL: {span}");
        let id = span["spanId"].as_str().expect("span ID");
        assert_eq!(id.len(), 16);
        assert_ne!(id, "0000000000000000");
        assert!(ids.insert(id), "duplicate policy span ID: {span}");
        let matching: Vec<_> = logs
            .iter()
            .filter(|log| log["traceId"] == span["traceId"] && log["spanId"] == span["spanId"])
            .collect();
        assert_eq!(matching.len(), 1, "span needs its matching log: {span}");
        // The span omits only what one of its own fields already states — `parentSpanId`, which
        // `assert_span_parent` asserts. Everything else must agree exactly.
        let omitted = ["strands.box.trace.parent_span_id"];
        let kept = |record: &Value| {
            record["attributes"]
                .as_array()
                .expect("attributes")
                .iter()
                .filter(|attribute| {
                    !omitted.contains(&attribute["key"].as_str().unwrap_or_default())
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(kept(matching[0]), kept(span));
        for key in omitted {
            assert!(
                !span["attributes"]
                    .as_array()
                    .expect("attributes")
                    .iter()
                    .any(|attribute| attribute["key"] == key),
                "a span field already states {key}: {span}"
            );
        }
    }
    spans
}

fn assert_span_parent(span: &Value, traceparent: &str, sent_tracestate: &str) {
    let parts: Vec<_> = traceparent.split('-').collect();
    assert_eq!(span["traceId"], parts[1], "{span}");
    assert_eq!(span["parentSpanId"], parts[2], "{span}");
    assert_eq!(
        span["traceState"].as_str().unwrap_or_default(),
        "",
        "the caller sent {sent_tracestate} and the box records no tracestate: {span}"
    );
    assert_ne!(span["spanId"], span["parentSpanId"], "{span}");
    // A non-zero parent span id IS the parented fact, which is why
    // `strands.box.trace.correlation` was removed rather than replaced.
    assert_ne!(
        span["parentSpanId"].as_str().unwrap_or_default(),
        "",
        "{span}"
    );
}

/// Every key the attribute contract removed, checked on a real box's span.
fn assert_removed_keys_are_absent(span: &Value) {
    for removed in [
        "gen_ai.conversation.id",
        "gen_ai.tool.call.id",
        "gen_ai.tool.name",
        "mcp.method.name",
        "security_rule.uuid",
        "strands.box.policy.determining.tokens",
        "strands.box.trace.correlation",
        "strands.box.trace.link_traceparent",
    ] {
        assert!(
            optional_span_attribute(span, removed).is_none(),
            "{removed} was removed: {span}"
        );
    }
}

fn assert_no_span_links(span: &Value) {
    assert!(
        span["links"].as_array().is_none_or(Vec::is_empty),
        "unexpected trace link: {span}"
    );
}

#[test]
fn tls_http_policy_spans_use_inner_parent_and_share_connect_request_id() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = RecordingUpstream::start();
    let box_ = Request::with_policy(
        "trace-tls",
        &format!(
            r#"permit(principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "localhost" && context.input.port == {} }};
@id("deny-inner-http")
forbid(principal, action == Box::Action::"http:request", resource);"#,
            upstream.port
        ),
    )
    .expect();
    let cases = [
        (
            "00-11111111111111111111111111111111-aaaaaaaaaaaaaaaa-01",
            "vendor=thread",
            json!({"thread-id": "tls-thread", "session-id": "ignored-session"}),
            "tls-thread",
        ),
        (
            "00-22222222222222222222222222222222-bbbbbbbbbbbbbbbb-00",
            "vendor=session",
            json!({"session-id": "tls-session"}),
            "tls-session",
        ),
    ];
    let requests: Vec<_> = cases
        .iter()
        .map(|(parent, state, headers, _)| {
            let mut headers = headers.clone();
            headers["traceparent"] = json!(parent);
            headers["tracestate"] = json!(state);
            json!({
                "url": format!("https://localhost:{}/denied", upstream.port),
                "headers": headers
            })
        })
        .collect();
    let replies = trace_probe(&box_, &json!(requests));
    for reply in &replies {
        assert_eq!(reply["status"], 403, "{reply}");
        assert!(
            reply["body"].as_str().unwrap().contains("deny-inner-http"),
            "{reply}"
        );
    }
    assert!(
        upstream.authorizations().is_empty(),
        "denied TLS requests reached origin"
    );
    let spans = recorded_policy_spans(&box_);
    // Each pinned address is its own `net:connect` authorization, so the CONNECT count follows how
    // `localhost` resolves on this host. Each exchange records exactly one `http:request`.
    let http_spans = spans
        .iter()
        .filter(|span| span_attribute(span, "strands.box.policy.action") == "http:request")
        .count();
    assert_eq!(http_spans, cases.len(), "{spans:#?}");
    assert!(
        spans.len() > http_spans,
        "each exchange also records its CONNECT: {spans:#?}"
    );
    let mut request_ids = std::collections::HashSet::new();
    for (parent, state, _, _) in &cases {
        let caller_trace = parent.split('-').nth(1).unwrap();
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| {
                span_attribute(span, "strands.box.policy.action") == "http:request"
                    && span["traceId"].as_str() == Some(caller_trace)
            })
            .collect();
        assert_eq!(matching.len(), 1, "{spans:#?}");
        let http = matching[0];
        assert_eq!(
            span_attribute(http, "strands.box.policy.action"),
            "http:request"
        );
        assert_eq!(span_attribute(http, "strands.box.policy.verdict"), "deny");
        assert_span_parent(http, parent, state);
        assert_no_span_links(http);
        let request_id = span_attribute(http, "strands.box.request.id");
        assert!(!request_id.is_empty());
        assert!(
            request_ids.insert(request_id),
            "distinct TLS requests share an ID"
        );
        let related: Vec<_> = spans
            .iter()
            .filter(|span| span_attribute(span, "strands.box.request.id") == request_id)
            .collect();
        // Each pinned address is its own `net:connect` authorization, and every one rides this
        // exchange's request ID beside the one `http:request`.
        let connects: Vec<_> = related
            .iter()
            .filter(|span| span_attribute(span, "strands.box.policy.action") == "net:connect")
            .collect();
        assert!(!connects.is_empty(), "{spans:#?}");
        assert_eq!(related.len(), connects.len() + 1, "{spans:#?}");
        for connect in connects {
            assert_eq!(
                span_attribute(connect, "strands.box.policy.verdict"),
                "permit"
            );
            assert_eq!(connect["parentSpanId"].as_str().unwrap_or_default(), "");
            let root_trace = connect["traceId"].as_str().unwrap();
            assert_eq!(root_trace.len(), 32);
            assert_ne!(root_trace, "00000000000000000000000000000000");
            for (other_parent, _, _, _) in &cases {
                assert_ne!(root_trace, other_parent.split('-').nth(1).unwrap());
            }
            assert_removed_keys_are_absent(connect);
            assert_no_span_links(connect);
        }
    }
}

#[test]
#[ignore = "live HTTPS echo fixture; set STRANDS_BOX_TLS_ECHO_URL and run with --ignored"]
fn tls_http_policy_spans_reach_a_trusted_origin_and_preserve_parent() {
    assert!(
        fixture::namespace_launcher_is_usable(),
        "this live test requires actual containment"
    );
    let endpoint = std::env::var("STRANDS_BOX_TLS_ECHO_URL")
        .expect("set STRANDS_BOX_TLS_ECHO_URL to an HTTPS /anything echo fixture");
    let endpoint = reqwest::Url::parse(&endpoint).expect("HTTPS echo URL");
    assert_eq!(endpoint.scheme(), "https");
    assert!(endpoint.username().is_empty() && endpoint.password().is_none());
    assert!(endpoint.query().is_none() && endpoint.fragment().is_none());
    let host = endpoint.host_str().expect("echo host");
    let port = endpoint.port_or_known_default().unwrap();
    let nonce = format!(
        "{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let allowed_path = format!("{}/permit-{nonce}", endpoint.path().trim_end_matches('/'));
    let denied_path = format!("{}/deny-{nonce}", endpoint.path().trim_end_matches('/'));
    let parent = format!("00-{nonce}-aaaaaaaaaaaaaaaa-01");
    let denied_parent = format!("00-{nonce}-bbbbbbbbbbbbbbbb-00");
    let box_ = Request::with_policy(
        "trace-tls-origin",
        &format!(
            r#"permit(principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == {host:?} && context.input.port == {port} }};
@id("permit-live-tls")
permit(principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == {host:?} && context.input.port == {port} &&
        context.input.path == {allowed_path:?} }};
@id("deny-live-tls")
forbid(principal, action == Box::Action::"http:request", resource)
when {{ context.input.path == {denied_path:?} }};"#
        ),
    )
    .expect();
    let body = json!({"probe": "strands-box-tls-e2e", "run": nonce});
    let requests = json!([
        {
            "url": format!("https://{host}:{port}{allowed_path}"),
            "headers": {
                "traceparent": parent, "tracestate": "fixture=permit",
                "thread-id": "tls-origin-permit", "session-id": "ignored-session",
                "cache-control": "no-store"
            },
            "body": body
        },
        {
            "url": format!("https://{host}:{port}{denied_path}"),
            "headers": {
                "traceparent": denied_parent, "tracestate": "fixture=deny",
                "session-id": "tls-origin-deny"
            },
            "body": body
        }
    ]);
    let replies = trace_probe(&box_, &requests);
    let capture = std::env::var_os("STRANDS_BOX_TRACE_CAPTURE_DIR").map(|directory| {
        let directory = std::path::PathBuf::from(directory).join(format!("tls-origin-{nonce}"));
        std::fs::create_dir_all(&directory).expect("create TLS capture directory");
        for (name, value) in [
            ("requests.json", &requests),
            ("replies.json", &json!(replies)),
        ] {
            std::fs::write(
                directory.join(name),
                serde_json::to_vec_pretty(value).unwrap(),
            )
            .expect("write request or response capture");
        }
        for (source, name) in [
            (
                box_.root().join("private/telemetry/records.jsonl"),
                "records.jsonl",
            ),
            (box_.config().to_path_buf(), "box.toml"),
            (box_.config().with_file_name("policy.dw"), "policy.dw"),
        ] {
            std::fs::copy(source, directory.join(name)).expect("capture original run bytes");
        }
        eprintln!("TLS_ORIGIN_CAPTURE={}", directory.display());
        directory
    });
    assert_eq!(replies[0]["status"], 200, "{replies:#?}");
    let origin: Value = serde_json::from_str(replies[0]["body"].as_str().unwrap())
        .expect("the origin echoes the actual request");
    assert_eq!(origin["method"], "POST", "{origin}");
    assert_eq!(origin["json"], body, "{origin}");
    let origin_url = reqwest::Url::parse(origin["url"].as_str().unwrap()).unwrap();
    assert_eq!(origin_url.scheme(), "https");
    assert_eq!(origin_url.host_str(), Some(host));
    assert_eq!(origin_url.port_or_known_default(), Some(port));
    assert_eq!(origin_url.path(), allowed_path);
    let origin_header = |name: &str| {
        let value = origin["headers"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("origin did not receive {name}: {origin}"))
            .1;
        value
            .as_str()
            .or_else(|| {
                let values = value.as_array()?;
                assert_eq!(values.len(), 1, "repeated origin header {name}");
                values[0].as_str()
            })
            .unwrap()
    };
    assert_eq!(origin_header("traceparent"), parent);
    assert_eq!(origin_header("tracestate"), "fixture=permit");
    assert_eq!(origin_header("thread-id"), "tls-origin-permit");
    assert_eq!(replies[1]["status"], 403, "{replies:#?}");
    assert!(
        replies[1]["body"]
            .as_str()
            .unwrap()
            .contains("deny-live-tls"),
        "{replies:#?}"
    );
    for reply in &replies {
        assert!(
            matches!(
                reply["tls"]["protocol"].as_str(),
                Some("TLSv1_2" | "TLSv1_3")
            ),
            "the contained probe must negotiate TLS: {reply}"
        );
        assert!(!reply["tls"]["cipher_suite"].as_str().unwrap().is_empty());
    }
    let spans = recorded_policy_spans(&box_);
    assert_eq!(spans.len(), 4, "{spans:#?}");
    let mut request_ids = std::collections::HashSet::new();
    for (_conversation, expected_parent, state, verdict, rule) in [
        (
            "tls-origin-permit",
            parent.as_str(),
            "fixture=permit",
            "permit",
            "permit-live-tls",
        ),
        (
            "tls-origin-deny",
            denied_parent.as_str(),
            "fixture=deny",
            "deny",
            "deny-live-tls",
        ),
    ] {
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| {
                span_attribute(span, "strands.box.policy.action") == "http:request"
                    && span_attribute(span, "strands.box.policy.verdict") == verdict
            })
            .collect();
        assert_eq!(matching.len(), 1, "{spans:#?}");
        let http = matching[0];
        assert_eq!(
            span_attribute(http, "strands.box.policy.action"),
            "http:request"
        );
        assert_eq!(span_attribute(http, "strands.box.policy.verdict"), verdict);
        let determining_ids = http["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|attribute| attribute["key"] == "strands.box.policy.determining.ids")
            .expect("authored determining rule IDs");
        assert_eq!(
            determining_ids["value"]["arrayValue"]["values"],
            json!([{"stringValue": rule}])
        );
        assert_span_parent(http, expected_parent, state);
        assert_no_span_links(http);
        let request_id = span_attribute(http, "strands.box.request.id");
        assert!(
            request_ids.insert(request_id),
            "distinct exchanges share an ID"
        );
        let connections: Vec<_> = spans
            .iter()
            .filter(|span| {
                span_attribute(span, "strands.box.request.id") == request_id
                    && span_attribute(span, "strands.box.policy.action") == "net:connect"
            })
            .collect();
        assert_eq!(connections.len(), 1, "{spans:#?}");
        let connect = connections[0];
        assert_eq!(
            span_attribute(connect, "strands.box.policy.verdict"),
            "permit"
        );
        assert_eq!(connect["parentSpanId"].as_str().unwrap_or_default(), "");
        assert_ne!(connect["traceId"], http["traceId"]);
        assert_removed_keys_are_absent(connect);
        assert_no_span_links(connect);
    }
    let result = json!({
        "passed": true,
        "run": nonce,
        "origin": origin_url.to_string(),
        "origin_traceparent": origin_header("traceparent"),
        "origin_tracestate": origin_header("tracestate"),
        "statuses": [replies[0]["status"], replies[1]["status"]],
        "probe_tls": [replies[0]["tls"], replies[1]["tls"]],
        "policy_spans": spans,
        "verification": "normal Box upstream roots; no fixture CA or verification bypass"
    });
    if let Some(directory) = capture {
        std::fs::write(
            directory.join("result.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .expect("write passing assertion summary");
    }
    eprintln!("TLS_ORIGIN_RESULT={result}");
}

/// A budget on a remote MCP tool holds across two runs of a box whose only MCP server is http:
/// the second run still sees the first run's calls, as every other rule does.
#[test]
fn a_remote_mcp_tool_budget_holds_across_two_runs_of_an_http_only_box() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-budget",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
permit(principal, action == demo::Action::"echo", resource);
@id("one-echo")
forbid(principal, action == demo::Action::"echo", resource)
when temporal {
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h ( demo::Action::"echo"::request{ input.text: "once" } && tp(t) )
    )) == total && total >= 2
  )
};"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let requests = |frames: &[Value]| {
        json!(
            frames
                .iter()
                .map(|frame| json!({
                    "url": format!("http://{}/mcp", upstream.authority),
                    "headers": {},
                    "body": frame
                }))
                .collect::<Vec<_>>()
        )
    };
    let list = json!({"jsonrpc": "2.0", "id": "catalog", "method": "tools/list"});
    let echo = |id: &str| {
        json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "once"}}
        })
    };
    let statuses = |replies: Vec<Value>| -> Vec<Value> {
        replies
            .into_iter()
            .map(|reply| reply["status"].clone())
            .collect()
    };

    let first = trace_probe(
        &box_,
        &requests(&[list.clone(), echo("first"), echo("second")]),
    );
    assert_eq!(
        statuses(first),
        [json!(200), json!(200), json!(403)],
        "the first echo is within budget and the second is not"
    );
    let second = trace_probe(&box_, &requests(&[list, echo("third")]));
    assert_eq!(
        statuses(second),
        [json!(200), json!(403)],
        "the second run still counts the first run's echo"
    );
}

#[test]
fn remote_mcp_policy_spans_prefer_message_parent_and_link_transport() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "trace-remote-mcp",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
@id("blocked-tool")
forbid(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" && context.input has tool && context.input.tool == "blocked" };
permit(principal, action == demo::Action::"echo", resource);
@id("denied-argument")
forbid(principal, action == demo::Action::"echo", resource)
when { context.input.text == "denied" };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let transport = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";
    let frames = [
        json!({
            "jsonrpc": "2.0", "id": "catalog", "method": "tools/list",
            "params": {"_meta": {
                "traceparent": "00-11111111111111111111111111111111-1111111111111111-01",
                "tracestate": "message=catalog", "sessionId": "catalog-session"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "unrelated-private-payload"}, "_meta": {
                "traceparent": "00-22222222222222222222222222222222-2222222222222222-01",
                "tracestate": "message=allowed", "threadId": "message-thread",
                "sessionId": "ignored-session", "callId": "allowed-call"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": "typed-denied", "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "denied"}, "_meta": {
                "traceparent": "00-33333333333333333333333333333333-3333333333333333-01",
                "tracestate": "message=denied", "sessionId": "message-session",
                "callId": "denied-call"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": "gate-denied", "method": "tools/call",
            "params": {"name": "blocked", "arguments": {"text": "unrelated-private-payload"}, "_meta": {
                "traceparent": "00-44444444444444444444444444444444-4444444444444444-01",
                "tracestate": "message=gate", "threadId": "gate-thread", "callId": "gate-call"
            }}
        }),
    ];
    let requests: Vec<_> = frames
        .iter()
        .map(|frame| {
            json!({
                "url": format!("http://{}/mcp", upstream.authority),
                "headers": {
                    "traceparent": transport, "tracestate": "transport=outer",
                    "thread-id": "transport-thread", "session-id": "transport-session"
                },
                "body": frame
            })
        })
        .collect();
    let replies = trace_probe(&box_, &json!(requests));
    for (index, reply) in replies.iter().enumerate() {
        assert_eq!(
            reply["status"],
            if index < 2 { 200 } else { 403 },
            "{reply}"
        );
        let body: Value = serde_json::from_str(reply["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["id"], frames[index]["id"]);
        if index >= 2 {
            assert_eq!(body["error"]["code"], -32001);
            let rule = if index == 2 {
                "denied-argument"
            } else {
                "blocked-tool"
            };
            assert!(
                body["error"]["message"].as_str().unwrap().contains(rule),
                "{body}"
            );
        } else {
            assert!(body.get("result").is_some(), "{body}");
        }
    }
    let received = upstream.finish();
    assert_eq!(
        received.len(),
        2,
        "only the catalog and allowed call reach origin: {received:#?}"
    );
    for (index, request) in received.iter().enumerate() {
        assert_eq!(
            request.body, frames[index],
            "origin must receive the original metadata"
        );
        assert_eq!(request.headers["traceparent"], transport);
        assert_eq!(request.headers["tracestate"], "transport=outer");
    }
    let spans = recorded_policy_spans(&box_);
    assert_eq!(spans.len(), 8, "{spans:#?}");
    // The default file names no signal, so it takes no tool call, whose values are in clear text.
    let tools = tool_records(&box_.root().join("private/telemetry/records.jsonl"));
    assert!(
        tools.is_empty(),
        "the default file holds no tool-call record: {tools:#?}"
    );
    let mut request_ids = std::collections::HashSet::new();
    for (index, frame) in frames.iter().enumerate() {
        let id = frame["id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| frame["id"].to_string());
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| optional_span_attribute(span, "jsonrpc.request.id") == Some(id.as_str()))
            .collect();
        assert_eq!(matching.len(), 1, "{spans:#?}");
        let decision = matching[0];
        let meta = &frame["params"]["_meta"];
        assert_span_parent(
            decision,
            meta["traceparent"].as_str().unwrap(),
            meta["tracestate"].as_str().unwrap(),
        );
        // A distinct transport parent no longer becomes a Link, because
        // `strands.box.trace.link_traceparent` was removed as never emitted.
        assert_no_span_links(decision);
        assert_removed_keys_are_absent(decision);
        let action = if index == 1 || index == 2 {
            "echo"
        } else {
            "mcp:call"
        };
        assert_eq!(
            span_attribute(decision, "strands.box.policy.action"),
            action
        );
        assert_eq!(
            span_attribute(decision, "strands.box.policy.verdict"),
            if index < 2 { "permit" } else { "deny" }
        );
        let request_id = span_attribute(decision, "strands.box.request.id");
        assert!(!request_id.is_empty());
        assert!(request_ids.insert(request_id), "MCP exchanges share an ID");
        let connections: Vec<_> = spans
            .iter()
            .filter(|span| {
                span_attribute(span, "strands.box.request.id") == request_id
                    && span_attribute(span, "strands.box.policy.action") == "net:connect"
            })
            .collect();
        assert_eq!(connections.len(), 1, "{spans:#?}");
        let connect = connections[0];
        assert_span_parent(connect, transport, "transport=outer");
        assert_eq!(
            span_attribute(connect, "strands.box.policy.verdict"),
            "permit"
        );
        assert_removed_keys_are_absent(connect);
        assert!(optional_span_attribute(connect, "jsonrpc.request.id").is_none());
        assert_no_span_links(connect);
    }
}

#[test]
fn remote_mcp_policy_spans_fall_back_to_transport_without_valid_message_context() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "trace-remote-fallback",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let transport = "00-55555555555555555555555555555555-6666666666666666-01";
    let frames = [
        json!({"jsonrpc": "2.0", "id": "no-meta", "method": "tools/list"}),
        json!({
            "jsonrpc": "2.0", "id": "invalid-meta", "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "allowed"}, "_meta": {
                "traceparent": "00-00000000000000000000000000000000-1111111111111111-01",
                "tracestate": "invalid=message", "callId": "fallback-call"
            }}
        }),
    ];
    let requests: Vec<_> = frames
        .iter()
        .map(|frame| {
            json!({
                "url": format!("http://{}/mcp", upstream.authority),
                "headers": {
                    "traceparent": transport, "tracestate": "transport=fallback",
                    "session-id": "transport-session"
                },
                "body": frame
            })
        })
        .collect();
    let replies = trace_probe(&box_, &json!(requests));
    for (reply, frame) in replies.iter().zip(&frames) {
        assert_eq!(reply["status"], 200, "{reply}");
        let body: Value = serde_json::from_str(reply["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["id"], frame["id"]);
    }
    let received = upstream.finish();
    assert_eq!(received.len(), 2, "{received:#?}");
    for (request, frame) in received.iter().zip(&frames) {
        assert_eq!(&request.body, frame);
    }
    let spans = recorded_policy_spans(&box_);
    assert_eq!(spans.len(), 4, "{spans:#?}");
    for span in &spans {
        assert_span_parent(span, transport, "transport=fallback");
        assert_removed_keys_are_absent(span);
        assert_eq!(span_attribute(span, "strands.box.policy.verdict"), "permit");
        assert_no_span_links(span);
    }
    for frame in &frames {
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| {
                optional_span_attribute(span, "jsonrpc.request.id") == frame["id"].as_str()
            })
            .collect();
        assert_eq!(matching.len(), 1, "{spans:#?}");
        let decision = matching[0];
        assert_removed_keys_are_absent(decision);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// The authority surface itself.
// ═══════════════════════════════════════════════════════════════════════════════

/// The `--policy` shorthand configures a box: a config with no bindings.
#[test]
fn the_policy_shorthand_configures_a_box() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ =
        Request::with_policy("shorthand", &permit_egress_to("api.example.test", 443)).expect();
    let output = workload(&box_, "printf 'done\\n'");
    assert_ran(&output);
    assert_eq!(stdout(&output), "done");
}
// **The config-plus-policy composition test was removed with the `create` verb (2026-08-18).**
//
// It asserted that `create --config X --policy Y` let `--policy` override the file's `policy` key
// while every other key survived. That was a property of the two `create` flags. A box is created
// by `run` in a workspace now, from one `.strands-box/box.toml` plus a `policy.dw` beside it, so
// there are no two flags to compose. The properties that outlive it — the box stores the policy it
// was given, and its `box.toml` keys round-trip — are covered by the record round-trip tests.

/// Workload arguments cannot replace the configuration's policy.
#[test]
fn run_refuses_to_accept_authority() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource)
when { context.input.command == "printf AUTHORITY_CONTROL" };
"#;
    let box_ = Request::with_policy("no-run-authority", POLICY).expect();
    let elsewhere = box_.operator_home().join("attacker.dw");
    std::fs::write(&elsewhere, "permit(principal, action, resource);\n")
        .expect("write the attacker policy");
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(box_.config()).expect("read configuration"))
            .expect("parse configuration");
    config["agent"]["command"] = toml::Value::Array(
        [
            "/bin/bash",
            "-c",
            "printf 'argument=%s\\n' \"$@\"; \
             zsh -lc 'printf AUTHORITY_CONTROL' || exit 1; \
             zsh -lc 'printf AUTHORITY_REPLACED'",
            "authority-probe",
        ]
        .into_iter()
        .map(toml::Value::from)
        .collect(),
    );
    std::fs::write(
        box_.config(),
        toml::to_string(&config).expect("serialize configuration"),
    )
    .expect("write the fixed workload");
    let before = std::fs::read(box_.config()).expect("the selected configuration");

    for flag in ["--policy", "--name"] {
        let output = Command::new(fixture::box_binary())
            .arg("run")
            .arg("--config")
            .arg(box_.config())
            .arg(flag)
            .arg(&elsewhere)
            .env("HOME", box_.operator_home())
            .output()
            .expect("spawn strands-box run");

        let printed = String::from_utf8_lossy(&output.stdout);
        assert!(printed.contains(&format!("argument={flag}")), "{output:?}");
        assert!(printed.contains("AUTHORITY_CONTROL"), "{output:?}");
        assert_eq!(output.status.code(), Some(126), "{output:?}");
        assert!(
            !printed.contains("AUTHORITY_REPLACED"),
            "no workload may run under authority passed to {flag}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("effect denied"),
            "{output:?}"
        );
        assert_eq!(
            std::fs::read(box_.config()).expect("the configuration survives"),
            before,
            "{flag} must not change the selected authority"
        );
    }
}

/// The daemon's resolved secrets stay out of the Shell, including out of Lua.
///
/// **This is the security test for hosting the Shell in the daemon**
/// (docs/design/decisions.md#one-policy-engine-per-box). The daemon resolves `env://` locators,
/// so its *process* environment holds the operator's real secret — and moving the Shell
/// in-process removed the `env_clear()` that the sibling shim was spawned with. What replaces
/// it is not a process boundary but the Shell's construction: its `Process` carries a
/// synthesized environment (`HOME`/`PATH`/`PWD`/`USER` and each route's phantom) rather than the
/// host's, and every filesystem and environment read is serviced by the VFS instead of
/// `std::env`/`std::fs`.
///
/// Lua is probed deliberately and is the sharpest case. `mlua` is a **non-optional**
/// dependency of Strands Shell with `features = ["lua54", "async", "vendored"]`, so
/// a Lua 5.4 **C** interpreter is compiled into whichever process hosts the Shell, and
/// `builtins/mod.rs` exposes it as a reachable `lua` builtin that runs
/// workload-supplied source. `os.getenv` and `io.popen("env")` see the synthesized
/// environment, where the secret's variable holds the workload's phantom, and
/// `io.open("/etc/passwd")` is refused by the VFS, so the interpreter reaches the same
/// mediated surface as the Shell itself, not the host's.
///
/// If this test ever fails, the daemon is handing the operator's secrets to attacker-
/// supplied script text, and hosting the Shell in-process must be reverted rather than
/// patched.
#[test]
fn the_shell_cannot_read_the_daemons_resolved_secrets() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ = box_with_credentials(
        "measure-env-leak",
        &permit_egress_to("localhost", 9),
        &target("localhost:9"),
    );
    let output = box_.bash(&format!(
        r#"printf 'workload=%s\n' "${SECRET_VARIABLE}"
           zsh -lc 'env | grep -c {SECRET_VARIABLE} || true'
           zsh -lc 'echo "expand=${SECRET_VARIABLE}"'
           zsh -lc 'lua -e "print([[getenv=]] .. os.getenv([[{SECRET_VARIABLE}]]))"'
           zsh -lc 'lua -e "local f=io.popen([[env]]); print(f:read([[a]]))"'
           zsh -lc 'lua -e "print(io.open([[/etc/passwd]]))"'"#
    ));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains(REAL_SECRET),
        "the Shell must not read the daemon's resolved secrets: {all}"
    );
    // The environment the Shell *does* see is the synthesized one, which is what proves
    // the absence above is mediation rather than the variable happening to be unset.
    assert!(
        all.contains("USER=strands-box"),
        "the Shell must see its own synthesized environment: {all}"
    );
    // The secret's variable holds the workload's phantom, for the Shell and for Lua alike.
    let phantom = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("workload="))
        .unwrap_or_default()
        .to_string();
    assert!(
        phantom.starts_with("strands_box_"),
        "the workload must hold a minted phantom: {all}"
    );
    assert!(
        all.contains(&format!("expand={phantom}\n")),
        "the Shell must expand the variable to the workload's phantom: {all}"
    );
    // Lua's own escape hatches reach the same mediated surface.
    assert!(
        all.contains(&format!("getenv={phantom}\n")),
        "lua os.getenv must read the Shell's environment, not the host's: {all}"
    );
    assert!(
        all.contains("/etc/passwd: no such file or directory"),
        "lua io.open must be refused by the VFS, not reach the host: {all}"
    );
}

#[test]
fn a_remote_tool_precondition_met_in_one_run_holds_in_the_next() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-history",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
@id("after_first")
forbid(principal, action == demo::Action::"echo", resource)
when { context.input.text == "second" }
when temporal { formerly within 1h ( demo::Action::"echo"::request{ input.text: "first" } ) };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let frame = |id: &str, method: &str, text: Option<&str>| {
        let params = match text {
            Some(text) => json!({"name": "echo", "arguments": {"text": text}}),
            None => json!({}),
        };
        json!({
            "url": format!("http://{}/mcp", upstream.authority),
            "headers": {},
            "body": {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        })
    };
    let statuses = |requests: Vec<Value>| {
        trace_probe(&box_, &json!(requests))
            .iter()
            .map(|reply| reply["status"].as_u64().expect("a status"))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        statuses(vec![
            frame("list", "tools/list", None),
            frame("first", "tools/call", Some("first")),
            frame("second", "tools/call", Some("second")),
        ]),
        [200, 200, 403],
        "the precondition is met in the first run"
    );
    assert_eq!(
        statuses(vec![
            frame("list", "tools/list", None),
            frame("second", "tools/call", Some("second")),
        ]),
        [200, 403],
        "the precondition met in the first run still holds"
    );
    assert_eq!(upstream.finish().len(), 3, "no denied call reaches origin");
}

#[test]
fn a_limit_over_a_remote_tools_own_response_refuses_the_next_call() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-response",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
@id("one_echo")
forbid(principal, action == demo::Action::"echo", resource)
when temporal { formerly within 1h ( demo::Action::"echo"::response{ input.text: "first" } ) };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let frame = |id: &str, method: &str, text: Option<&str>| {
        let params = match text {
            Some(text) => json!({"name": "echo", "arguments": {"text": text}}),
            None => json!({}),
        };
        json!({
            "url": format!("http://{}/mcp", upstream.authority),
            "headers": {},
            "body": {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        })
    };
    let statuses: Vec<u64> = trace_probe(
        &box_,
        &json!([
            frame("list", "tools/list", None),
            frame("first", "tools/call", Some("first")),
            frame("second", "tools/call", Some("second")),
        ]),
    )
    .iter()
    .map(|reply| reply["status"].as_u64().expect("a status"))
    .collect();
    assert_eq!(
        statuses,
        [200, 200, 403],
        "the finished first echo is recorded under the tool's own action"
    );
    assert_eq!(
        upstream.finish().len(),
        2,
        "the refused echo never reached origin"
    );
}

#[test]
fn a_remote_tool_result_satisfies_a_result_precondition() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-result",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
@id("guarded_after_result")
forbid(principal, action == demo::Action::"echo", resource)
when { context.input.text == "guarded" }
unless temporal { formerly within 1h ( demo::Action::"echo"::response{ output.reply: "result" } ) };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let frame = |id: &str, method: &str, text: Option<&str>| {
        let params = match text {
            Some(text) => json!({"name": "echo", "arguments": {"text": text}}),
            None => json!({}),
        };
        json!({
            "url": format!("http://{}/mcp", upstream.authority),
            "headers": {},
            "body": {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        })
    };
    let statuses: Vec<u64> = trace_probe(
        &box_,
        &json!([
            frame("list", "tools/list", None),
            frame("early", "tools/call", Some("guarded")),
            frame("first", "tools/call", Some("first")),
            frame("after", "tools/call", Some("guarded")),
        ]),
    )
    .iter()
    .map(|reply| reply["status"].as_u64().expect("a status"))
    .collect();
    assert_eq!(
        statuses,
        [200, 403, 200, 200],
        "the guarded call is refused until an earlier call's reply was a result"
    );
}

/// Over http the gateway reads the `tools/call` reply, so a precondition on the
/// tool's declared output (`output.structured.verified`) is met only by a verification that
/// answered true — from a plain JSON reply or a streamed SSE reply.
#[test]
fn a_remote_precondition_on_structured_output_needs_the_answer_it_names() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-output",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };
@id("verified_first")
forbid(principal, action == demo::Action::"echo", resource)
unless temporal { formerly within 1h ( demo::Action::"verify"::response{
  output.reply: "result", output.structured.verified: true } ) };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n",
            upstream.authority
        ),
    )
    .expect();
    let frame = |id: &str, method: &str, tool: &str, text: Option<&str>| {
        let params = match text {
            Some(text) => json!({"name": tool, "arguments": {"text": text}}),
            None => json!({}),
        };
        json!({
            "url": format!("http://{}/mcp", upstream.authority),
            "headers": {},
            "body": {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        })
    };
    let statuses: Vec<u64> = trace_probe(
        &box_,
        &json!([
            frame("list", "tools/list", "", None),
            frame("v1", "tools/call", "verify", Some("no")),
            frame("e1", "tools/call", "echo", Some("a")),
            frame("v2", "tools/call", "verify", Some("sse-yes")),
            frame("e2", "tools/call", "echo", Some("b")),
        ]),
    )
    .iter()
    .map(|reply| reply["status"].as_u64().expect("a status"))
    .collect();
    assert_eq!(
        statuses,
        [200, 200, 403, 200, 200],
        "only a verification that answered verified=true admits the echo"
    );
    assert_eq!(
        upstream.finish().len(),
        4,
        "the refused echo never reached origin"
    );

    // No target names mcp_tool_calls, so the default file holds no tool-call record at all.
    let tools = tool_records(&box_.root().join("private/telemetry/records.jsonl"));
    assert!(tools.is_empty(), "{tools:#?}");
}

/// A target that names `mcp_tool_calls` in `box.toml` receives each call's arguments and output in
/// clear text over http, joined to the call by its JSON-RPC id, with how each call that ran ended.
#[test]
fn a_target_naming_tool_calls_receives_each_remote_call_in_clear_text() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let upstream = TraceUpstream::start();
    let box_ = Request::with_config(
        "remote-tool-calls",
        r#"permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource);
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "demo" };"#,
        &format!(
            "[mcp.demo]\ntype = \"http\"\ndestinations = [\"{}\"]\n\n\
             [telemetry.local]\nkind = \"file\"\n\
             destination = \"{}/private/telemetry/tools.jsonl\"\n\
             include = [\"deny\", \"permit\", \"mcp_tool_calls\"]\n",
            upstream.authority,
            fixture::BOX_DIR
        ),
    )
    .expect();
    let frame = |id: &str, method: &str, tool: &str, text: Option<&str>| {
        let params = match text {
            Some(text) => json!({"name": tool, "arguments": {"text": text}}),
            None => json!({}),
        };
        json!({
            "url": format!("http://{}/mcp", upstream.authority),
            "headers": {},
            "body": {"jsonrpc": "2.0", "id": id, "method": method, "params": params}
        })
    };
    let statuses: Vec<u64> = trace_probe(
        &box_,
        &json!([
            frame("list", "tools/list", "", None),
            frame("v1", "tools/call", "verify", Some("sse-yes")),
            frame("e1", "tools/call", "echo", Some("echo-private-text")),
            // An argument the tool's schema does not declare, so policy refuses the call.
            json!({
                "url": format!("http://{}/mcp", upstream.authority),
                "headers": {},
                "body": {"jsonrpc": "2.0", "id": "e2", "method": "tools/call", "params": {
                    "name": "echo",
                    "arguments": {"text": "refused-text", "extra": 1}
                }}
            }),
        ]),
    )
    .iter()
    .map(|reply| reply["status"].as_u64().expect("a status"))
    .collect();
    assert_eq!(statuses, [200, 200, 200, 403]);
    upstream.finish();

    let tools = tool_records(&box_.root().join("private/telemetry/tools.jsonl"));
    let record = |event: &str, id: &str| {
        tools.iter().find(|(name, attributes)| {
            name == event
                && attributes
                    .iter()
                    .any(|(key, value)| key == "jsonrpc.request.id" && value == id)
        })
    };
    let value = |event: &str, id: &str, key: &str| {
        record(event, id).and_then(|(_, attributes)| {
            attributes
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        })
    };
    for (id, text) in [
        ("v1", "sse-yes"),
        ("e1", "echo-private-text"),
        ("e2", "refused-text"),
    ] {
        assert_eq!(
            value(
                "strands.box.mcp.tool.call",
                id,
                "strands.box.mcp.tool.arguments.text"
            )
            .as_deref(),
            Some(text),
            "call {id} states its argument in clear text: {tools:#?}"
        );
    }
    assert_eq!(
        value(
            "strands.box.mcp.tool.completion",
            "v1",
            "strands.box.mcp.tool.output.verified"
        )
        .as_deref(),
        Some("true"),
        "a streamed reply's own answer arrives: {tools:#?}"
    );
    for id in ["v1", "e1"] {
        assert_eq!(
            value(
                "strands.box.mcp.tool.completion",
                id,
                "strands.box.mcp.tool.reply"
            )
            .as_deref(),
            Some("result"),
            "call {id} states how it ended: {tools:#?}"
        );
    }
    assert!(
        record("strands.box.mcp.tool.completion", "e2").is_none(),
        "the refused call never ran, so it has no completion: {tools:#?}"
    );
}

/// Every `strands-box.mcp` log record in a records file, as its event name and string attributes.
fn tool_records(path: &std::path::Path) -> Vec<(String, Vec<(String, String)>)> {
    let text = std::fs::read_to_string(path).expect("read the drained telemetry");
    let mut records = Vec::new();
    for line in text.lines() {
        let request: serde_json::Value =
            serde_json::from_str(line).expect("a telemetry line is one OTLP request");
        for resource in request["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] != "strands-box.mcp" {
                    continue;
                }
                for record in scope["logRecords"].as_array().into_iter().flatten() {
                    records.push((
                        record["eventName"].as_str().unwrap_or_default().to_string(),
                        record["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|attribute| {
                                let Some(key) = attribute["key"].as_str() else {
                                    return Vec::new();
                                };
                                if let Some(text) = attribute["value"]["stringValue"].as_str() {
                                    return vec![(key.to_string(), text.to_string())];
                                }
                                attribute["value"]["kvlistValue"]["values"]
                                    .as_array()
                                    .into_iter()
                                    .flatten()
                                    .filter_map(|field| {
                                        let value = &field["value"];
                                        let text = value["stringValue"]
                                            .as_str()
                                            .map(str::to_string)
                                            .or_else(|| {
                                                value["boolValue"]
                                                    .as_bool()
                                                    .map(|flag| flag.to_string())
                                            })
                                            .or_else(|| {
                                                value["intValue"].as_str().map(str::to_string)
                                            })
                                            .or_else(|| {
                                                value["doubleValue"].as_f64().map(|n| n.to_string())
                                            })?;
                                        Some((format!("{key}.{}", field["key"].as_str()?), text))
                                    })
                                    .collect()
                            })
                            .collect(),
                    ));
                }
            }
        }
    }
    records
}
