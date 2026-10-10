//! Telemetry end to end, against a real box and a real kernel boundary.
//!
//! | Promise | Test |
//! |---|---|
//! | A box that declares nothing records every effective decision | `a_box_that_declares_no_target_records_every_effective_decision` |
//! | A declared target replaces the default | `a_declared_file_target_is_where_the_records_go` |
//! | A target naming only `deny` keeps only refusals | `a_policy_denied_target_keeps_only_the_refusals` |
//! | The workload can neither read nor remove the record | `the_workload_can_neither_read_nor_remove_the_record` |
//! | Two boxes share no record | `two_boxes_share_no_record` |
//! | A misspelled signal refuses before the box exists | `a_misspelled_signal_refuses_before_the_box_exists` |
//! | A target naming no signal refuses too | `an_empty_signal_list_refuses_before_the_box_exists` |
//! | An unbuilt exporter refuses, naming what works | `an_unbuilt_exporter_refuses_and_names_what_works` |
//! | An OTLP target receives protobuf with the secret attached | `an_otlp_target_receives_the_records_with_the_secret_attached` |
//! | The agent holds the endpoint and never the secret | `the_agent_holds_the_endpoint_and_never_the_vendor_secret` |
//! | With `trace`, a span is kept and cannot forge a record | `at_trace_an_agent_span_is_kept_and_cannot_claim_the_boxs_namespace` |
//! | Without `trace`, a span is answered and discarded | `below_trace_an_agent_span_is_answered_and_discarded` |
//!
//! **A probe of the workload's own environment must not go through the `zsh` alias.** That alias
//! reaches the hosted Shell, which has its own synthesized environment, so `zsh -c 'env'` reports
//! the Shell's and not the workload's.
//!
//! **Every test that starts a box goes through `needs_a_box!`, which names itself when it skips.**
//! A build container that refuses `mount("proc")` inside a fresh PID namespace stops the Linux
//! launcher from constructing its view. A bare `return` reports `ok`, which read as ten passing tests
//! that asserted nothing. The seven that assert a refusal *before* the box exists run everywhere,
//! because a `configure` refusal reaches no kernel.

#[path = "support/fixture.rs"]
mod fixture;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::sync::mpsc;

use fixture::Request;

/// A policy that permits one read and every command, so a run produces both verdict kinds.
///
/// **Annotated so that an annotated policy is loaded and installed through a real box**, which both
/// shipped examples now are. It does **not** prove the annotations reach a record: the read rule
/// matches nothing here, because `$BOX_HOME` is the harness's variable and the hosted Shell has its
/// own environment, so the path resolves to `/allowed.txt` and the read is a `no_match` deny. That
/// deny is what the standard rule keys are asserted against below. `record.rs`'s unit tests pin the
/// authored `@id` and `@description` reaching the record.
const READ_ONE_FILE: &str = r#"
@id("allow_one_read")
@description("Permit the one file this example reads.")
permit(
    principal,
    action == Box::Action::"fs:read",
    resource
) when { context.input.path like "{box_home}/allowed.txt" };
permit(principal, action == Box::Action::"shell:exec", resource);
"#;

/// Return from a test that needs a real box, naming itself where none can be built.
macro_rules! needs_a_box {
    ($test:literal) => {
        if !fixture::namespace_launcher_is_usable() {
            eprintln!(
                "SKIPPED: {}: this host cannot build a box, so it asserted nothing",
                $test
            );
            return;
        }
    };
}

/// The default destination, under the box's own private tree.
fn default_records(root: &std::path::Path) -> std::path::PathBuf {
    root.join("private").join("telemetry").join("records.jsonl")
}

fn policy_spans(text: &str) -> Vec<serde_json::Value> {
    let mut spans = Vec::new();
    for line in text.lines() {
        let batch: serde_json::Value = serde_json::from_str(line).unwrap();
        for resource in batch["resourceSpans"].as_array().into_iter().flatten() {
            for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] == "strands-box.policy" {
                    spans.extend(scope["spans"].as_array().unwrap().iter().cloned());
                }
            }
        }
    }
    spans
}

#[test]
fn a_shell_decision_states_its_arguments_and_its_directory() {
    needs_a_box!("a_shell_decision_states_its_arguments_and_its_directory");
    let configured = Request::with_policy("shell-args", READ_ONE_FILE).expect();
    std::fs::write(configured.box_home().join("allowed.txt"), "public").unwrap();
    // The outer bash expands `BOX_HOME`, because the hosted Shell has its own environment.
    let output = configured.bash(r#"zsh -c "cat $BOX_HOME/allowed.txt""#);
    assert!(output.status.success(), "{output:?}");

    let text = std::fs::read_to_string(default_records(&configured.root())).unwrap();
    let spans = policy_spans(&text);
    let mut seen = None;
    for span in &spans {
        let attributes = span["attributes"].as_array().unwrap();
        let value = |key: &str| {
            attributes
                .iter()
                .find(|attribute| attribute["key"] == key)
                .map(|attribute| attribute["value"].clone())
        };
        if value("strands.box.policy.action").and_then(|value| {
            value["stringValue"]
                .as_str()
                .map(|text| text == "shell:exec")
        }) != Some(true)
        {
            continue;
        }
        // `cat` alone is what the resource says, so the arguments have to arrive beside it.
        if value("process.command")
            .and_then(|value| value["stringValue"].as_str().map(|text| text == "cat"))
            == Some(true)
        {
            let args = value("process.command_args").expect("the argument vector");
            let reported: Vec<String> = args["arrayValue"]["values"]
                .as_array()
                .expect("an array value")
                .iter()
                .map(|entry| {
                    entry["stringValue"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect();
            seen = Some((reported, value("process.working_directory")));
            break;
        }
    }
    let (args, cwd) = seen.unwrap_or_else(|| {
        panic!("no `shell:exec` decision named `cat` with its arguments: {text}")
    });
    assert_eq!(args.first().map(String::as_str), Some("cat"), "{args:?}");
    assert_eq!(args.len(), 2, "the program and one path: {args:?}");
    assert!(
        args[1].ends_with("allowed.txt"),
        "the expanded path, not the spelling: {args:?}"
    );
    assert!(cwd.is_some(), "the directory the line ran in: {spans:?}");
}

#[test]
fn shell_and_monty_policy_spans_use_the_callers_parent() {
    needs_a_box!("shell_and_monty_policy_spans_use_the_callers_parent");
    for (name, command) in [
        (
            "shell",
            r#"zsh -c 'cat "$BOX_HOME/allowed.txt"; cat "$BOX_HOME/secret.txt" || true'"#,
        ),
        (
            "monty",
            r#"python3 -c "from pathlib import Path; print(Path('$BOX_HOME/allowed.txt').read_text()); print(Path('$BOX_HOME/secret.txt').read_text())" || true"#,
        ),
    ] {
        let configured = Request::with_policy(&format!("trace-{name}"), READ_ONE_FILE).expect();
        std::fs::write(configured.box_home().join("allowed.txt"), "public").unwrap();
        std::fs::write(configured.box_home().join("secret.txt"), "private").unwrap();
        // The box knows only `TRACEPARENT` and `TRACESTATE` by name. The two other variables are set
        // deliberately: the alias must read neither, so the absence assertion below can fail.
        let output = configured.bash(&format!(
            "export TRACEPARENT=00-1234567890abcdef1234567890abcdef-0123456789abcdef-01 \
             STRANDS_BOX_CONVERSATION_ENV=HARNESS_THREAD HARNESS_THREAD=conversation-test; \
             {command}"
        ));
        assert!(output.status.success(), "{output:?}");
        let text = std::fs::read_to_string(default_records(&configured.root())).unwrap();
        let spans = policy_spans(&text);
        assert!(!spans.is_empty(), "{name}: no policy spans: {text}");
        let mut verdicts = std::collections::BTreeSet::new();
        for span in &spans {
            assert_eq!(
                span["traceId"], "1234567890abcdef1234567890abcdef",
                "{name}: {span}"
            );
            assert_eq!(span["parentSpanId"], "0123456789abcdef", "{name}: {span}");
            assert_ne!(span["spanId"], span["parentSpanId"]);
            for attribute in span["attributes"].as_array().unwrap() {
                if attribute["key"] == "strands.box.policy.verdict" {
                    verdicts.insert(
                        attribute["value"]["stringValue"]
                            .as_str()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
            // Every key the attribute contract removed stays removed, on a real box.
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
                    !span["attributes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|attribute| attribute["key"] == removed),
                    "{name}: {removed} was removed: {span}"
                );
            }
        }
        assert!(
            verdicts.contains("permit") && verdicts.contains("deny"),
            "{name}: {verdicts:?}"
        );

        // **A refusal names no authored policy.** The engine reaches `<default-deny>` here, so the
        // standard rule keys must name that and carry neither a durable token nor a description.
        let refused = spans
            .iter()
            .find(|span| {
                let held =
                    |key: &str, want: &str| {
                        span["attributes"].as_array().unwrap().iter().any(|entry| {
                            entry["key"] == key && entry["value"]["stringValue"] == want
                        })
                    };
                held("strands.box.policy.action", "fs:read")
                    && held("strands.box.policy.verdict", "deny")
            })
            .unwrap_or_else(|| panic!("{name}: a refused fs:read must be recorded: {text}"));
        let value = |key: &str| {
            refused["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["key"] == key)
                .map(|entry| entry["value"].clone())
        };
        let text_of =
            |key: &str| value(key).and_then(|held| held["stringValue"].as_str().map(String::from));
        assert_eq!(
            text_of("strands.box.policy.rule").as_deref(),
            Some("<default-deny>"),
            "{name}: a refusal names the rule reached: {refused}"
        );
        assert!(
            value("strands.box.policy.description").is_none(),
            "{name}: a refusal must not carry a description: {refused}"
        );
        assert_eq!(
            text_of("strands.box.policy.category").as_deref(),
            Some("fs")
        );
        // An `fs:*` subject restates the decided path under the standard name.
        assert_eq!(
            value("file.path"),
            value("strands.box.policy.resource"),
            "{name}: file.path restates the decided path: {refused}"
        );
    }
}

#[test]
fn concurrent_http_requests_keep_distinct_policy_parents_and_refusals() {
    needs_a_box!("concurrent_http_requests_keep_distinct_policy_parents_and_refusals");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = std::thread::spawn(move || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(45);
        let mut readers = Vec::new();
        let mut connections = 0;
        while connections < 2 && std::time::Instant::now() < until {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            connections += 1;
            readers.push(std::thread::spawn(move || {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                if !head.is_empty() {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                    Some(String::from_utf8(head).unwrap())
                } else {
                    None
                }
            }));
        }
        readers
            .into_iter()
            .filter_map(|reader| reader.join().unwrap())
            .collect::<Vec<_>>()
    });
    let configured = Request::with_policy(
        "trace-http",
        r#"
permit(principal, action == Box::Action::"net:connect", resource);
permit(principal, action == Box::Action::"http:request", resource)
when { context.input.path == "/allowed" };
"#,
    )
    .expect();
    let output = configured.bash(&format!(r#"
request() {{
  exec 3<>/dev/tcp/127.0.0.1/${{HTTPS_PROXY##*:}}
  printf 'GET http://127.0.0.1:{port}/%s HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\ntraceparent: 00-%s-0123456789abcdef-01\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' "$1" "$2" >&3
  read -r status <&3
  printf '%s:%s\n' "$1" "$status"
  exec 3<&-
}}
request allowed 11111111111111111111111111111111 &
request denied 22222222222222222222222222222222 &
wait
"#));
    assert!(output.status.success(), "{output:?}");
    let forwarded = upstream.join().unwrap();
    let records = std::fs::read_to_string(default_records(&configured.root())).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("allowed:HTTP/1.1 200"),
        "{output:?}; origin: {forwarded:?}; records: {records}"
    );
    assert!(stdout.contains("denied:HTTP/1.1 403"), "{output:?}");
    assert_eq!(
        forwarded.len(),
        1,
        "a refused HTTP request must not reach the origin: {forwarded:?}"
    );
    assert!(forwarded[0].starts_with("GET /allowed "));
    let spans = policy_spans(&records);
    assert_eq!(spans.len(), 4, "{spans:?}");
    for trace in [
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
    ] {
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| span["traceId"] == trace)
            .collect();
        assert_eq!(matching.len(), 2, "{spans:?}");
        for span in matching {
            assert_eq!(span["parentSpanId"], "0123456789abcdef");
        }
    }
}

#[test]
#[ignore = "public HTTPS echo dependency; set STRANDS_BOX_TLS_ECHO_URL and run with --ignored"]
fn hosted_shell_and_monty_http_forward_call_trace_context() {
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
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let allowed_path = format!("{}/permit-{nonce:x}", endpoint.path().trim_end_matches('/'));
    let denied_path = format!("{}/deny-{nonce:x}", endpoint.path().trim_end_matches('/'));
    let configured = Request::with_policy(
        "trace-hosted-http",
        &format!(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == {host:?} && context.input.port == {port} }};
@id("permit-hosted-http")
permit(principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == {host:?} && context.input.port == {port} &&
        context.input.path == {allowed_path:?} }};
@id("deny-hosted-http")
forbid(principal, action == Box::Action::"http:request", resource)
when {{ context.input.path == {denied_path:?} }};"#
        ),
    )
    .expect();
    let parents: Vec<_> = (1_u128..=6)
        .map(|id| format!("00-{:032x}-{id:016x}-01", nonce + id))
        .collect();
    let cases = [
        ("shell-allow", false, true, "caller=shell-allow"),
        ("shell-deny", false, false, "caller=shell-deny"),
        ("monty-allow", true, true, "caller=monty-allow"),
        ("monty-deny", true, false, "caller=monty-deny"),
        ("shell-override", false, true, "caller=shell-default"),
    ];
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let mut script = String::new();
    for (index, (name, monty, allowed, state)) in cases.iter().enumerate() {
        let mut url = endpoint.clone();
        url.set_path(if *allowed {
            &allowed_path
        } else {
            &denied_path
        });
        url.set_query(Some(&format!("call={name}")));
        let code = if *monty {
            format!(
                "response = fetch({:?}); print(response['status']); print(response['body'])",
                url.as_str()
            )
        } else {
            let explicit = if index == 4 {
                format!(
                    "-H {} -H {} ",
                    quote(&format!("TraceParent: {}", parents[5])),
                    quote("TraceState: explicit=header")
                )
            } else {
                String::new()
            };
            format!(
                "curl --silent --show-error --include {explicit}{}",
                quote(url.as_str())
            )
        };
        let interpreter = if *monty { "python3" } else { "zsh" };
        script.push_str(&format!(
            "printf '\\nCASE_{name}_BEGIN\\n'\nTRACEPARENT={} TRACESTATE={} {interpreter} -c {}\nprintf '\\nCASE_{name}_END=%s\\n' \"$?\"\n",
            quote(&parents[index]),
            quote(state),
            quote(&code),
        ));
    }
    let output = configured.bash(&script);
    let records_path = default_records(&configured.root());
    let records = std::fs::read_to_string(&records_path).unwrap();
    let capture = std::env::var_os("STRANDS_BOX_TRACE_CAPTURE_DIR").map(|directory| {
        let directory = std::path::PathBuf::from(directory).join(format!("hosted-http-{nonce:x}"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::copy(&records_path, directory.join("records.jsonl")).unwrap();
        std::fs::write(directory.join("stdout.txt"), &output.stdout).unwrap();
        std::fs::write(directory.join("stderr.txt"), &output.stderr).unwrap();
        eprintln!("HOSTED_HTTP_ORIGIN_CAPTURE={}", directory.display());
        directory
    });
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let spans: Vec<_> = policy_spans(&records)
        .into_iter()
        .filter(|span| {
            span["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attribute| {
                    attribute["key"] == "strands.box.policy.action"
                        && attribute["value"]["stringValue"] == "http:request"
                })
        })
        .collect();
    assert_eq!(
        spans.len(),
        cases.len(),
        "{output:?}; HTTP spans: {spans:?}"
    );
    let mut results = Vec::new();
    for (index, (name, monty, allowed, state)) in cases.iter().enumerate() {
        let begin = format!("\nCASE_{name}_BEGIN\n");
        let end = format!("\nCASE_{name}_END=");
        let block = stdout.split_once(&begin).expect("case begins").1;
        let (reply, tail) = block.split_once(&end).expect("case ends");
        assert_eq!(tail.lines().next(), Some("0"), "{name}: {output:?}");
        let reply = reply.trim_start_matches('\n').replace("\r\n", "\n");
        let (status, body) = if *monty {
            let (status, body) = reply.split_once('\n').expect("Monty status and body");
            (status.trim().parse::<u16>().unwrap(), body.trim())
        } else {
            let (head, body) = reply
                .split_once("\n\n")
                .expect("curl includes response headers");
            let status = head
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u16>()
                .unwrap();
            (status, body.trim())
        };
        assert_eq!(status, if *allowed { 200 } else { 403 }, "{name}: {reply}");
        let (parent, state) = if index == 4 {
            (&parents[5], "explicit=header")
        } else {
            (&parents[index], *state)
        };
        if *allowed {
            let origin: serde_json::Value = serde_json::from_str(body).expect("origin echo JSON");
            assert_eq!(origin["method"], "GET", "{origin}");
            let url = reqwest::Url::parse(origin["url"].as_str().unwrap()).unwrap();
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some(host));
            assert_eq!(url.port_or_known_default(), Some(port));
            assert_eq!(url.path(), allowed_path);
            for (name, expected) in [("traceparent", parent.as_str()), ("tracestate", state)] {
                let value = &origin["headers"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .unwrap_or_else(|| panic!("origin did not receive {name}: {origin}"))
                    .1;
                let value = value
                    .as_str()
                    .or_else(|| {
                        let values = value.as_array()?;
                        assert_eq!(values.len(), 1, "duplicate {name}: {origin}");
                        values[0].as_str()
                    })
                    .unwrap();
                assert_eq!(value, expected, "{origin}");
            }
        } else {
            assert!(body.contains("deny-hosted-http"), "{name}: {body}");
        }
        let fields: Vec<_> = parent.split('-').collect();
        let matching: Vec<_> = spans
            .iter()
            .filter(|span| span["traceId"] == fields[1])
            .collect();
        assert_eq!(matching.len(), 1, "{parent}: {spans:?}");
        let span = matching[0];
        assert_eq!(span["parentSpanId"], fields[2], "{span}");
        assert_eq!(
            span["traceState"].as_str().unwrap_or_default(),
            "",
            "the caller sent {state} and the box records no tracestate: {span}"
        );
        assert_ne!(span["spanId"], span["parentSpanId"], "{span}");
        let verdict = if *allowed { "permit" } else { "deny" };
        assert!(
            span["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attribute| {
                    attribute["key"] == "strands.box.policy.verdict"
                        && attribute["value"]["stringValue"] == verdict
                }),
            "{span}"
        );
        results.push(serde_json::json!({
            "case": name, "status": status, "parent": parent, "tracestate": state,
            "policy_span_id": span["spanId"], "verdict": verdict,
            "origin_echo_verified": allowed,
        }));
    }
    if let Some(directory) = capture {
        std::fs::write(
            directory.join("results.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"cases": results, "denied_origin_absence_verified": false}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    eprintln!(
        "HOSTED_HTTP_VERIFIED: three origin echoes and five policy parents; denied origin absence is unobserved"
    );
}

/// The identity that Box generated for one caller-owned directory.
fn box_identity(root: &std::path::Path) -> String {
    let path = root.join("private").join("box.toml");
    let text = std::fs::read_to_string(&path).expect("the box record");
    let record: toml::Value = toml::from_str(&text).expect("the box record parses");
    record["box_id"]
        .as_str()
        .expect("the box record has an identity")
        .to_string()
}

/// Every attribute on the first DECISION record in `text`.
///
/// The scope is named rather than indexed, because control-plane records share the destination and
/// arrive first — a box records that it started before it takes a decision.
fn first_decision_attributes(text: &str) -> Vec<String> {
    for line in text.lines() {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("one OTLP request per line");
        let Some(resources) = value["resourceLogs"].as_array() else {
            continue;
        };
        for resource in resources {
            let Some(scopes) = resource["scopeLogs"].as_array() else {
                continue;
            };
            for scope in scopes {
                if scope["scope"]["name"].as_str() != Some("strands-box.policy") {
                    continue;
                }
                let Some(records) = scope["logRecords"].as_array() else {
                    continue;
                };
                if let Some(first) = records.first() {
                    return first["attributes"]
                        .as_array()
                        .expect("the record's attributes")
                        .iter()
                        .map(|item| item["key"].as_str().unwrap_or_default().to_string())
                        .collect();
                }
            }
        }
    }
    panic!("no decision record under the policy scope: {text}");
}

/// Every control-plane record in `text`, in file order, as `(operation, outcome, subject)`.
fn control_records(text: &str) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for line in text.lines() {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("one OTLP request per line");
        for resource in parsed["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] != "strands-box.control" {
                    continue;
                }
                for entry in scope["logRecords"].as_array().into_iter().flatten() {
                    let read = |key: &str| {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .unwrap_or_default()
                            .to_string()
                    };
                    found.push((
                        read("strands.box.control.operation"),
                        read("strands.box.control.outcome"),
                        read("strands.box.control.subject"),
                    ));
                }
            }
        }
    }
    found
}

/// **A box that declares no target still records, and the record names the whole decision.**
#[test]
fn a_box_that_declares_no_target_records_every_effective_decision() {
    needs_a_box!("a_box_that_declares_no_target_records_every_effective_decision");
    let configured = Request::with_policy("telemetry-default", READ_ONE_FILE).expect();
    std::fs::write(configured.box_home().join("allowed.txt"), "public").expect("the allowed file");
    std::fs::write(configured.box_home().join("secret.txt"), "private").expect("the other file");

    // The second read is refused, which is the point, so the shell's own status is not the check.
    assert!(
        configured
            .bash("zsh -c 'cat $HOME/allowed.txt; cat $HOME/secret.txt || true'")
            .status
            .success()
    );

    let path = default_records(&configured.root());
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must hold the records: {error}", path.display()));

    let attributes = first_decision_attributes(&text);
    for key in [
        "strands.box.policy.principal",
        "strands.box.policy.action",
        "strands.box.policy.resource",
        "strands.box.policy.verdict",
        "strands.box.policy.rule",
        "strands.box.policy.category",
    ] {
        assert!(
            attributes.iter().any(|found| found == key),
            "{key} missing from {attributes:?}"
        );
    }
    // Every key the attribute contract removed stays absent from a real decision.
    for removed in [
        "security_rule.uuid",
        "strands.box.policy.determining.tokens",
        "strands.box.trace.correlation",
    ] {
        assert!(
            !attributes.iter().any(|found| found == removed),
            "{removed} was removed: {attributes:?}"
        );
    }
    assert!(
        text.contains("\"deny\""),
        "the refused read must be recorded: {text}"
    );
}

/// **The control plane is recorded beside the decisions, on its own scope.**
///
/// A reader has to be able to tell why a request early in the run was denied, which needs the
/// authority's own changes in the same order as the decisions taken under it.
#[test]
fn the_control_plane_is_recorded_beside_the_decisions() {
    needs_a_box!("the_control_plane_is_recorded_beside_the_decisions");
    let configured = Request::with_policy("telemetry-control", READ_ONE_FILE).expect();
    assert!(configured.bash("zsh -c 'true'").status.success());

    let path = default_records(&configured.root());
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must hold the records: {error}", path.display()));

    for operation in ["box_started", "policy_installed", "box_stopped"] {
        assert!(
            text.contains(operation),
            "{operation} missing from the records: {text}"
        );
    }
    assert!(
        text.contains("strands-box.control"),
        "a control record carries its own scope: {text}"
    );
    assert!(
        text.contains("strands.box.control.operation"),
        "and its own attribute namespace: {text}"
    );
    // The two planes share one destination and stay tellable apart, which is the whole point.
    assert!(
        text.contains("strands-box.policy"),
        "the decisions are still there: {text}"
    );
}

/// **A run that fails before its workload starts records its stop, and records it as refused.**
///
/// `execute` is the one teardown point, and this is what pins it: an unresolvable workload fails in
/// `Boundary::assemble`, which is past `box_started` and short of `Contained::wait`. Before the fix
/// that path reached no drain, so a reader could not tell a failed run from one still running.
///
/// The creating run writes its own pair into this same file, so a `contains` check passes on that
/// run alone and measures nothing. Both runs are counted, and the failed one is read by position.
#[test]
fn a_run_that_fails_before_its_workload_still_records_its_stop() {
    needs_a_box!("a_run_that_fails_before_its_workload_still_records_its_stop");
    let configured = Request::with_policy("telemetry-halted", READ_ONE_FILE).expect();

    let refused = configured.run(&["/nonexistent/program-no-box-may-run"]);
    assert!(
        !refused.status.success(),
        "an unresolvable workload must refuse: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let path = default_records(&configured.root());
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must hold the records: {error}", path.display()));
    let control = control_records(&text);

    let started: Vec<_> = control
        .iter()
        .filter(|(operation, ..)| operation == "box_started")
        .collect();
    let stopped: Vec<_> = control
        .iter()
        .filter(|(operation, ..)| operation == "box_stopped")
        .collect();
    assert_eq!(
        started.len(),
        2,
        "the creating run and the refused run each record a start: {control:?}"
    );
    assert_eq!(
        stopped.len(),
        2,
        "the refused run reaches the teardown point too: {control:?}"
    );
    assert_eq!(
        stopped[0].1, "ok",
        "the creating run succeeded: {control:?}"
    );
    // The whole point of the record: a reader must be able to tell this run died.
    assert_eq!(
        stopped[1].1, "refused",
        "a run that failed must not record its stop as ok: {control:?}"
    );
    assert!(
        !stopped[1].2.is_empty(),
        "and the refusal must name the box: {control:?}"
    );
}

/// **A declared file target replaces the default, and `~/` means the operator's home.**
#[test]
fn a_declared_file_target_is_where_the_records_go() {
    needs_a_box!("a_declared_file_target_is_where_the_records_go");
    let configured = Request::with_config(
        "telemetry-declared",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/declared.jsonl\"\ninclude = [\"deny\", \"permit\"]\n",
    )
    .expect();
    assert!(configured.bash("zsh -c 'true'").status.success());

    let declared = configured.operator_home().join("declared.jsonl");
    let text = std::fs::read_to_string(&declared)
        .unwrap_or_else(|error| panic!("the declared target must hold the records: {error}"));
    assert!(!text.is_empty());
    assert!(
        !default_records(&configured.root()).exists(),
        "a declared target replaces the default rather than adding to it"
    );
}

/// **A target narrowed to refusals never fills with permits.**
#[test]
fn a_policy_denied_target_keeps_only_the_refusals() {
    needs_a_box!("a_policy_denied_target_keeps_only_the_refusals");
    let configured = Request::with_config(
        "telemetry-denied",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/denied.jsonl\"\ninclude = [\"deny\"]\n",
    )
    .expect();
    std::fs::write(configured.box_home().join("secret.txt"), "private").expect("the other file");
    assert!(
        configured
            .bash("zsh -c 'cat $HOME/secret.txt || true'")
            .status
            .success()
    );

    let text = std::fs::read_to_string(configured.operator_home().join("denied.jsonl"))
        .expect("the narrowed target");
    assert!(text.contains("\"deny\""), "the refusal is kept: {text}");
    assert!(
        !text.contains("\"permit\""),
        "a permit must not reach a refusals-only target: {text}"
    );
}

/// **A target narrowed to refusals still receives the agent's own log records and metrics.**
///
/// The two are unconditional, so `include` narrows the box's permits and the agent's spans and
/// never these. All three payloads go through the same route, and the span is the control: it is
/// answered and kept nowhere, which is what proves the list still narrows something.
#[test]
fn a_narrowed_target_still_receives_the_agents_own_logs_and_metrics() {
    needs_a_box!("a_narrowed_target_still_receives_the_agents_own_logs_and_metrics");
    let configured = Request::with_config(
        "telemetry-unconditional",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/unconditional.jsonl\"\ninclude = [\"deny\"]\n",
    )
    .expect();
    std::fs::write(configured.box_home().join("secret.txt"), "private").expect("the other file");

    let log = concat!(
        r#"{"resourceLogs":[{"scopeLogs":[{"scope":{"name":"agent.sdk"},"#,
        r#""logRecords":[{"body":{"stringValue":"agent-log-line"}}]}]}]}"#
    );
    let metric = concat!(
        r#"{"resourceMetrics":[{"scopeMetrics":[{"scope":{"name":"agent.sdk"},"#,
        r#""metrics":[{"name":"agent.turns","gauge":{"dataPoints":[{"asInt":"1"}]}}]}]}]}"#
    );
    let span = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"agent-work"}]}]}]}"#;

    // Posted by the WORKLOAD itself, so the real Seatbelt rule is in the path. `/dev/tcp` is a
    // bash feature and the workload is bash, so this must not go through the `zsh` alias. The
    // denied read comes first, so the file also holds one record of the box's own.
    let post = |route: &str, body: &str| {
        format!(
            "exec 3<>/dev/tcp/127.0.0.1/${{OTEL_EXPORTER_OTLP_ENDPOINT##*:}}; \
             printf 'POST {route} HTTP/1.1\\r\\nHost: x\\r\\n\
             Content-Type: application/json\\r\\nContent-Length: {}\\r\\n\\r\\n{body}' >&3; \
             read -r answer <&3; printf '%s ' \"$answer\"; exec 3<&-; ",
            body.len()
        )
    };
    let script = format!(
        "zsh -c 'cat $HOME/secret.txt || true'; {}{}{}",
        post("/v1/logs", log),
        post("/v1/metrics", metric),
        post("/v1/traces", span)
    );
    let output = configured.bash(&script);
    let answered = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        answered.matches("200").count(),
        3,
        "each route answers the workload: {answered} {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = std::fs::read_to_string(configured.operator_home().join("unconditional.jsonl"))
        .expect("the narrowed target");
    assert!(
        text.contains("agent-log-line"),
        "the agent's log record is unconditional: {text}"
    );
    assert!(
        text.contains("agent.turns"),
        "the agent's metric is unconditional: {text}"
    );
    assert!(
        text.contains("\"deny\""),
        "the box's own refusal is still there: {text}"
    );
    assert!(
        !text.contains("agent-work"),
        "a span is not unconditional, so this list still narrows: {text}"
    );
}

/// **The record is the box's, not the workload's: unreadable and undeletable from inside.**
#[test]
fn the_workload_can_neither_read_nor_remove_the_record() {
    needs_a_box!("the_workload_can_neither_read_nor_remove_the_record");
    let configured = Request::with_policy("telemetry-guarded", READ_ONE_FILE).expect();
    assert!(configured.bash("zsh -c 'true'").status.success());

    let path = default_records(&configured.root());
    assert!(path.is_file(), "the box recorded its verdicts");

    let reported = path.display().to_string();
    let attempt = configured.bash(&format!(
        "zsh -c 'cat {reported} 2>&1; rm -f {reported} 2>&1; true'"
    ));
    let output = String::from_utf8_lossy(&attempt.stdout).to_string()
        + &String::from_utf8_lossy(&attempt.stderr);
    assert!(
        !output.contains("strands.box.policy.verdict"),
        "the workload read its own audit trail: {output}"
    );
    assert!(
        path.is_file(),
        "the workload removed the record; a trail it can erase is no trail"
    );
}

/// **Two boxes share no record file, so neither can read or corrupt the other's.**
#[test]
fn two_boxes_share_no_record() {
    needs_a_box!("two_boxes_share_no_record");
    let first = Request::with_policy("telemetry-first", READ_ONE_FILE).expect();
    let second = Request::with_policy("telemetry-second", READ_ONE_FILE).expect();
    assert!(first.bash("zsh -c 'true'").status.success());
    assert!(second.bash("zsh -c 'true'").status.success());

    let one = default_records(&first.root());
    let two = default_records(&second.root());
    assert_ne!(one, two, "two boxes must not share one destination");
    assert!(one.is_file() && two.is_file());

    let text = std::fs::read_to_string(&one).expect("the first box's records");
    let first_identity = box_identity(&first.root());
    let second_identity = box_identity(&second.root());
    assert!(text.contains(&first_identity), "{text}");
    assert!(
        !text.contains(&second_identity),
        "one box's file holds no other box's records: {text}"
    );
}

/// **A misspelled signal is refused when the config loads, so no box starts believing it records.**
#[test]
fn a_misspelled_signal_refuses_before_the_box_exists() {
    let (_configured, output) = Request::with_config(
        "telemetry-bad-signal",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/x.jsonl\"\ninclude = [\"verbose\"]\n",
    )
    .attempt();
    assert!(!output.status.success(), "a bad signal must refuse the run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("verbose"), "{stderr}");
    for spelling in ["deny", "permit", "trace"] {
        assert!(
            stderr.contains(spelling),
            "the refusal must list {spelling}, which an operator may write: {stderr}"
        );
    }
}

/// **A target naming no signal is refused, because nothing would ever reach it.**
#[test]
fn an_empty_signal_list_refuses_before_the_box_exists() {
    let (_configured, output) = Request::with_config(
        "telemetry-no-signal",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/x.jsonl\"\ninclude = []\n",
    )
    .attempt();
    assert!(
        !output.status.success(),
        "an empty list must refuse the run"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no signal"), "{stderr}");
    for word in ["deny", "permit", "trace"] {
        assert!(
            stderr.contains(word),
            "the refusal must list {word}, which an operator may write: {stderr}"
        );
    }
}

/// **An unknown exporter type is refused, naming the two that exist.**
#[test]
fn an_unknown_exporter_type_refuses_and_names_the_two_that_exist() {
    let (_configured, output) = Request::with_config(
        "telemetry-kafka",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"kafka\"\ndestination = \"broker:9092\"\n",
    )
    .attempt();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("kafka"), "{stderr}");
    assert!(stderr.contains("file"), "{stderr}");
}

/// **A destination inside the box directory but outside `private/` is refused**, because a process
/// the spec grants reach there could truncate it.
///
/// A record the workload deletes suppresses every refusal it provoked. The box's own default sits
/// under `private/`, which the rule must keep accepting: it is the default destination, so a rule
/// widened to the whole box directory would refuse every box that declares no target.
///
/// **The test is this box's own directory, not a namespace.** A caller supplies `box_dir`, so Box
/// cannot know where any other box lives, and the refusal narrowed accordingly. The destination
/// below therefore uses the `{box_dir}` token rather than a spelled path: the fixture's box name
/// carries its pid, so a hand-spelled path names a sibling directory and proves nothing.
#[test]
fn a_destination_inside_the_box_directory_outside_private_refuses_before_the_box_exists() {
    let (_configured, output) = Request::with_config(
        "telemetry-in-box",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"{box_dir}/trust/audit.jsonl\"\n",
    )
    .attempt();
    assert!(
        !output.status.success(),
        "a destination inside the box directory, outside `private/`, must refuse the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("outside its private tree"),
        "the refusal must name why: {stderr}"
    );

    // `Path::components` keeps `..`, so a spelling that walks out of `private/` read its second
    // component as `private` and passed an earlier form of this check.
    let (_second, walked) = Request::with_config(
        "telemetry-walks-back",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \
         \"{box_dir}/private/../trust/audit.jsonl\"\n",
    )
    .attempt();
    assert!(
        !walked.status.success(),
        "a `..` out of `private/` must refuse the run"
    );
    let walked_stderr = String::from_utf8_lossy(&walked.stderr);
    assert!(walked_stderr.contains(".."), "{walked_stderr}");
}

/// **The default destination under `private/` stays acceptable.**
///
/// The paired positive for the refusal above. Without it, a rule that refused the whole box
/// directory would pass that test and break every box that declares a target at all.
#[test]
fn a_destination_under_the_boxs_private_tree_is_accepted() {
    // This is the one telemetry case that needs the box to START. Its sibling refusals are decided
    // when the configuration loads, so they assert on a host that can build no box; this one opens
    // the declared file, which only a running box does.
    needs_a_box!("a_destination_under_the_boxs_private_tree_is_accepted");
    let (configured, output) = Request::with_config(
        "telemetry-in-private",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \
         \"{box_dir}/private/telemetry/declared.jsonl\"\n",
    )
    .attempt();
    assert!(
        output.status.success(),
        "a destination under `private/` is the one place inside the box that is allowed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        configured
            .root()
            .join("private/telemetry/declared.jsonl")
            .is_file(),
        "the declared destination must be the file the box opened"
    );
}

/// **A relative file destination is refused, because it would open against the box's own cwd.**
///
/// Two boxes started from different directories with the same declaration would otherwise write to
/// two different files, and neither where the operator looked.
#[test]
fn a_relative_file_destination_refuses_before_the_box_exists() {
    let (_configured, output) = Request::with_config(
        "telemetry-relative",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"records.jsonl\"\n",
    )
    .attempt();

    assert!(
        !output.status.success(),
        "a relative destination must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("absolute"), "{stderr}");
}

/// **The agent holds no name in the OTLP exporter family beyond the three the box sets.**
#[test]
fn an_env_key_cannot_claim_a_signal_specific_otlp_name() {
    let (_configured, output) = Request::with_policy("telemetry-claimed", READ_ONE_FILE)
        .agent_env(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "http://attacker.example",
        )
        .attempt();

    assert!(
        !output.status.success(),
        "an `env` key must not claim a box-owned OTLP name"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
        "the refusal must name the key: {stderr}"
    );
}

/// **A tilde form the box cannot expand is refused, not opened against the working directory.**
///
/// `expanded_home_path` rewrites `~` and `~/…` only, so `~foo` and `~user/…` were returned verbatim
/// and opened relative to wherever the operator invoked `run`.
#[test]
fn an_unexpandable_tilde_destination_refuses_before_the_box_exists() {
    for destination in ["~foo", "~user/records.jsonl"] {
        let (_configured, output) = Request::with_config(
            "telemetry-tilde",
            READ_ONE_FILE,
            &format!("[telemetry.decisions]\nkind = \"file\"\ndestination = \"{destination}\"\n"),
        )
        .attempt();
        assert!(
            !output.status.success(),
            "{destination} must refuse: the box cannot expand it"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("absolute"), "{destination}: {stderr}");
    }
}

/// **Every record names who produced it, and an agent cannot claim to be the box.**
#[test]
fn the_records_carry_their_provenance() {
    needs_a_box!("the_records_carry_their_provenance");
    let configured = Request::with_policy("telemetry-source", READ_ONE_FILE).expect();
    assert!(configured.bash("zsh -c 'true'").status.success());

    let text =
        std::fs::read_to_string(default_records(&configured.root())).expect("the default target");
    assert!(
        text.contains("strands.box.source") && text.contains("\"box\""),
        "the box's own records must be stamped as the box's: {text}"
    );
}

/// **A secret over plaintext is refused at `configure`, not at the first run.**
///
/// The collector enforces the same rule, so without the check in `checked_telemetry` an operator
/// passed `configure` and then failed every `run` — which is the failure `configure` exists to
/// prevent. Loopback is exempt, and `an_otlp_target_receives_the_records_with_the_secret_attached`
/// is what keeps that exemption honest.
#[test]
fn a_secret_over_plaintext_refuses_before_the_box_exists() {
    let (_configured, output) = Request::with_config(
        "telemetry-plaintext",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"otlp\"\ndestination = \"http://vendor.example\"\n\
         secret.ref = \"env://BOX_TELEMETRY_KEY\"\n",
    )
    .env("BOX_TELEMETRY_KEY", "vendor-key")
    .attempt();

    assert!(
        !output.status.success(),
        "a secret over plaintext must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("https"), "{stderr}");
    assert!(
        !stderr.contains("vendor-key"),
        "the refusal must not echo the secret: {stderr}"
    );
}

/// **An OTLP target receives protobuf, and the box attaches the secret on the way out.**
///
/// The endpoint is a stand-in rather than a vendor, and loopback is why the secret may cross it in
/// the clear. What matters is that the box holds the credential and the workload never sees it.
#[test]
fn an_otlp_target_receives_the_records_with_the_secret_attached() {
    needs_a_box!("an_otlp_target_receives_the_records_with_the_secret_attached");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a stand-in endpoint");
    let port = listener.local_addr().expect("its port").port();
    let (sender, receiver) = mpsc::channel();

    // Several connections, not one: a box exports its control-plane records and its decisions in
    // separate batches, so serving one would answer whichever raced first and drop the other.
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
            let _ = sender.send((head, body));
        }
    });

    let configured = Request::with_config(
        "telemetry-otlp",
        READ_ONE_FILE,
        &format!(
            "[telemetry.decisions]\nkind = \"otlp\"\ndestination = \"http://127.0.0.1:{port}\"\n\
             secret.ref = \"env://BOX_TELEMETRY_KEY\"\nsecret.header = \"x-vendor-team\"\n"
        ),
    )
    .env("BOX_TELEMETRY_KEY", "vendor-key")
    .expect();
    assert!(configured.bash("zsh -c 'true'").status.success());

    // Received until a verdict crosses, rather than asserting on the first batch: control-plane
    // records share the destination and a box records that it started before it decides anything.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut verdict_crossed = false;
    let mut seen = 0usize;
    while std::time::Instant::now() < deadline {
        let Ok((head, body)) = receiver.recv_timeout(std::time::Duration::from_secs(20)) else {
            break;
        };
        seen += 1;
        let head = head.to_ascii_lowercase();
        assert!(
            head.contains("content-type: application/x-protobuf"),
            "OTLP over HTTP defaults to protobuf: {head}"
        );
        assert!(
            head.contains("x-vendor-team: vendor-key"),
            "the box attaches the secret on the way out: {head}"
        );
        assert!(
            !body.is_empty(),
            "the endpoint received an empty body, so no record crossed"
        );
        if String::from_utf8_lossy(&body).contains("strands.box.policy.verdict") {
            verdict_crossed = true;
            break;
        }
    }
    assert!(
        verdict_crossed,
        "no batch carried a verdict, across {seen} received"
    );
}

/// **The agent holds this box's endpoint and never a vendor credential.**
#[test]
fn the_agent_holds_the_endpoint_and_never_the_vendor_secret() {
    needs_a_box!("the_agent_holds_the_endpoint_and_never_the_vendor_secret");
    let configured = Request::with_config(
        "telemetry-env",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/env.jsonl\"\n",
    )
    .env("BOX_TELEMETRY_KEY", "vendor-key")
    .expect();

    // Printed by the WORKLOAD with a bash builtin. Two reasons: the `zsh` alias would report the
    // hosted Shell's own synthesized environment instead, and `env` is not a granted exec literal,
    // so the workload cannot run it at all.
    let output = configured.bash(
        "printf 'endpoint=%s\n' \"$OTEL_EXPORTER_OTLP_ENDPOINT\";          printf 'protocol=%s\n' \"$OTEL_EXPORTER_OTLP_PROTOCOL\";          printf 'headers=%s\n' \"$OTEL_EXPORTER_OTLP_HEADERS\"",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let environment = String::from_utf8_lossy(&output.stdout);
    assert!(
        environment.contains("endpoint=http://127.0.0.1:"),
        "the agent needs a loopback endpoint to export to: {environment}"
    );
    assert!(
        environment.contains("protocol=http/protobuf"),
        "the receiver serves HTTP and not gRPC: {environment}"
    );
    // The line is always printed, so the assertion has to be on an EMPTY value. An earlier
    // version also accepted `headers=`, which the `printf` always produces — so it passed whatever
    // the variable held.
    assert!(
        environment.contains("headers=\n"),
        "a credential header must be absent: {environment}"
    );
    assert!(
        !environment.contains("vendor-key"),
        "no vendor credential reaches the workload: {environment}"
    );
}

/// **At `trace`, an agent's own span is kept beside the box's records.**
///
/// The workload posts to its own endpoint with `/dev/tcp`, which is the real Seatbelt rule in the
/// path rather than a stand-in. The strip is asserted too: the span claims the box's namespace and
/// must not keep it.
#[test]
fn at_trace_an_agent_span_is_kept_and_cannot_claim_the_boxs_namespace() {
    needs_a_box!("at_trace_an_agent_span_is_kept_and_cannot_claim_the_boxs_namespace");
    let configured = Request::with_config(
        "telemetry-trace",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/traced.jsonl\"\ninclude = [\"deny\", \"permit\", \"trace\"]\n",
    )
    .expect();

    // One OTLP-JSON trace, claiming the box's reserved namespace at the span level.
    let span = concat!(
        r#"{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","#,
        r#""value":{"stringValue":"the-agent"}}]},"scopeSpans":[{"scope":{"name":"agent.sdk"},"#,
        r#""spans":[{"name":"agent-work","attributes":[{"key":"strands.box.policy.verdict","#,
        r#""value":{"stringValue":"permit"}}]}]}]}]}"#
    );
    // Posted by the WORKLOAD itself, so the real Seatbelt rule is in the path. `/dev/tcp` is a
    // bash feature and the workload is bash, so this must not go through the `zsh` alias.
    // `zsh -c true` first, so the run also produces a box record and the file holds both.
    let script = format!(
        "zsh -c true; \
         exec 3<>/dev/tcp/127.0.0.1/${{OTEL_EXPORTER_OTLP_ENDPOINT##*:}}; \
         printf 'POST /v1/traces HTTP/1.1\\r\\nHost: x\\r\\n\
         Content-Type: application/json\\r\\nContent-Length: {}\\r\\n\\r\\n{}' >&3; \
         read -r answer <&3; printf '%s' \"$answer\"; exec 3<&-",
        span.len(),
        span
    );
    let output = configured.bash(&script);
    let answered = String::from_utf8_lossy(&output.stdout);
    assert!(
        answered.contains("200"),
        "the contained workload must reach its own endpoint: {answered} {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = std::fs::read_to_string(configured.operator_home().join("traced.jsonl"))
        .expect("the traced target");
    assert!(
        text.contains("agent-work"),
        "the agent's own span must be kept at trace: {text}"
    );
    assert!(
        text.contains("resourceSpans"),
        "the span is kept as a trace, not rewritten into a log: {text}"
    );
    assert!(
        text.contains("resourceLogs"),
        "the box's own records are still there beside it: {text}"
    );
    let mut agent_batches = 0;
    for line in text.lines().filter(|line| line.contains("resourceSpans")) {
        let batch: serde_json::Value = serde_json::from_str(line).unwrap();
        let source_is_agent = batch["resourceSpans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource| {
                resource["resource"]["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|attribute| {
                        attribute["key"] == "strands.box.source"
                            && attribute["value"]["stringValue"] == "agent"
                    })
            });
        if !source_is_agent {
            continue;
        }
        agent_batches += 1;
        assert!(
            !line.contains("strands.box.policy."),
            "an agent span kept a policy attribute it claimed: {line}"
        );
        assert!(
            line.contains("strands.box.source") && line.contains("\"agent\""),
            "an agent span must be stamped as the agent's: {line}"
        );
    }
    assert!(agent_batches > 0, "the actual agent batch must be checked");
}

/// **Below `trace`, an agent's span is answered and kept nowhere.**
#[test]
fn below_trace_an_agent_span_is_answered_and_discarded() {
    needs_a_box!("below_trace_an_agent_span_is_answered_and_discarded");
    let configured = Request::with_config(
        "telemetry-untraced",
        READ_ONE_FILE,
        "[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/untraced.jsonl\"\ninclude = [\"deny\", \"permit\"]\n",
    )
    .expect();

    let span = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"agent-work"}]}]}]}"#;
    // Posted by the WORKLOAD itself, so the real Seatbelt rule is in the path. `/dev/tcp` is a
    // bash feature and the workload is bash, so this must not go through the `zsh` alias.
    // `zsh -c true` first, so the run also produces a box record and the file holds both.
    let script = format!(
        "zsh -c true; \
         exec 3<>/dev/tcp/127.0.0.1/${{OTEL_EXPORTER_OTLP_ENDPOINT##*:}}; \
         printf 'POST /v1/traces HTTP/1.1\\r\\nHost: x\\r\\n\
         Content-Type: application/json\\r\\nContent-Length: {}\\r\\n\\r\\n{}' >&3; \
         read -r answer <&3; printf '%s' \"$answer\"; exec 3<&-",
        span.len(),
        span
    );
    let output = configured.bash(&script);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("200"),
        "the endpoint answers whatever the level says, so the agent learns nothing from it"
    );

    let text = std::fs::read_to_string(configured.operator_home().join("untraced.jsonl"))
        .expect("the target");
    assert!(
        !text.contains("agent-work"),
        "a debug target must keep no agent span: {text}"
    );
}

/// A policy that permits every command and spawning `hostname`, so the agent can start one tool.
#[cfg(target_os = "linux")]
const SPAWN_HOSTNAME: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "hostname" };
"#;

/// The `strands.box.policy.resource` of every decision record whose action is `action`.
#[cfg(target_os = "linux")]
fn resources_recorded_for(text: &str, action: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines().filter(|line| line.contains(action)) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let records = value["resourceLogs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|resource| resource["scopeLogs"].as_array().into_iter().flatten())
            .flat_map(|scope| scope["logRecords"].as_array().into_iter().flatten());
        for record in records {
            let attribute = |key: &str| {
                record["attributes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|item| item["key"] == key)
                    .and_then(|item| item["value"]["stringValue"].as_str())
                    .map(str::to_string)
            };
            if attribute("strands.box.policy.action").as_deref() == Some(action)
                && let Some(resource) = attribute("strands.box.policy.resource")
            {
                found.push(resource);
            }
        }
    }
    found
}

/// **Every leaf that shares the container's `/proc` says so in the record**: the agent and each tool
/// it starts, so an operator can reconstruct which processes could list the container's processes.
#[cfg(target_os = "linux")]
#[test]
fn a_shared_proc_box_records_proc_shared_for_the_agent_and_its_tools() {
    needs_a_box!("a_shared_proc_box_records_proc_shared_for_the_agent_and_its_tools");
    let configured = Request::with_config(
        "telemetry-proc-shared",
        SPAWN_HOSTNAME,
        "[containment]\nprivate_proc = false\n\n[tool.hostname]\ncommand = [\"hostname\"]\n",
    )
    .expect();
    let output = configured.bash(r#"zsh -lc "hostname""#);
    assert!(output.status.success(), "{output:?}");

    let text = std::fs::read_to_string(default_records(&configured.root())).expect("the records");
    let resources = resources_recorded_for(&text, "proc:shared");
    assert!(
        resources.iter().any(|resource| resource == "agent"),
        "the agent shares /proc and must say so: {resources:?}\n{text}"
    );
    assert!(
        resources.iter().any(|resource| resource == "hostname"),
        "the tool shares /proc and must say so: {resources:?}\n{text}"
    );
}

/// **A box that keeps its private `/proc` records no `proc:shared`.**
#[cfg(target_os = "linux")]
#[test]
fn a_private_proc_box_records_no_proc_shared() {
    needs_a_box!("a_private_proc_box_records_no_proc_shared");
    let configured = Request::with_config(
        "telemetry-proc-private",
        SPAWN_HOSTNAME,
        "[tool.hostname]\ncommand = [\"hostname\"]\n",
    )
    .expect();
    assert!(configured.bash(r#"zsh -lc "hostname""#).status.success());

    let text = std::fs::read_to_string(default_records(&configured.root())).expect("the records");
    assert!(
        resources_recorded_for(&text, "proc:shared").is_empty(),
        "{text}"
    );
}
