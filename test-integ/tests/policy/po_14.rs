use strands_det_harness::egress::{
    FloorAnswer, HostRecorder, HostResolution, PROBE_SOURCE, ProbeMode, Transcript,
    absolute_request, judge_floor_probe, probe_command, probe_reached_recorder,
};
use strands_det_harness::{Platform, det_case};

// The spelling set comes from the "inet_aton spellings" cases in SRT's canonical-host-routing
// suite (6fa73136).
//
// Every spelling of the metadata address, sent by the compiled native probe (run under the agent's
// `exec` grant on `out/`) to the gateway through `$HTTP_PROXY`, under a permit-everything policy
// plus the metadata forbid on `context.input.ip`. The literal forms need no resolver: the dotted
// quad and its trailing-dot form are addresses, and the bracketed IPv6 encodings (mapped,
// compatible, 6to4, Teredo) are parsed as addresses that policy reads as `169.254.169.254`. The
// `inet_aton` forms (decimal, hex, octal, two-part) are not addresses to Rust's parser, so the
// gateway resolves them as names, and `getaddrinfo` reads them as `169.254.169.254`.
//
// A refusal counts only as the gateway's policy refusal naming `metadata_addresses`. A `502` is
// read as `Unresolvable` only when the HOST's own resolver, asked independently by the case,
// refuses the same spelling; a bare `502` for a spelling the host resolves is a transport or
// interceptor failure and fails the case, control included.
//
// The allowed control fixes the resolver's behaviour: the decimal form of a loopback recorder
// (`2130706433:<port>`), permitted by policy, must reach the recorder whole. Where the host
// resolver reads that spelling the control must answer 200; where it refuses it (not glibc), the
// control must be the bare `502` and the resolver spellings are Declared, never counted. On Linux
// the resolver is glibc and the control is required to pass.
det_case! {
    name: po_14,
    id:   "PO-14",
    desc: "Address spellings from the native route: every literal and inet_aton spelling of 169.254.169.254 is refused by a policy forbid on context.input.ip or independently declared unresolvable, while the decimal spelling of a permitted loopback recorder reaches it",
    run: |b| {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let port = recorder.port();
        let probe = b.compile_probe("egress-probe", PROBE_SOURCE);

        b.apply_policy(
            r#"@id("net_all")  permit (principal, action == Box::Action::"net:connect",  resource);
@id("http_all") permit (principal, action == Box::Action::"http:request", resource);
@id("metadata_addresses") forbid (principal, action == Box::Action::"net:connect", resource)
    when { context.input has ip && context.input.ip like "169.254.*" };"#,
        );

        let literals = [
            ("LIT_DOTTED", "169.254.169.254"),
            ("LIT_TRAILING_DOT", "169.254.169.254."),
            ("LIT_V6_MAPPED", "[::ffff:169.254.169.254]"),
            ("LIT_V6_MAPPED_HEX", "[::ffff:a9fe:a9fe]"),
            ("LIT_V6_COMPAT", "[::169.254.169.254]"),
            ("LIT_6TO4", "[2002:a9fe:a9fe::]"),
            ("LIT_TEREDO", "[2001:0:0:0:0:0:5601:5601]"),
        ];
        let resolver_forms = [
            ("RES_DECIMAL", "2852039166"),
            ("RES_HEX", "0xa9fea9fe"),
            ("RES_OCTAL", "0251.0376.0251.0376"),
            ("RES_TWO_PART", "169.254.43518"),
            ("RES_HEX_DOTTED", "0xa9.0xfe.0xa9.0xfe"),
        ];
        let control_spelling = "2130706433";

        let mut script = String::new();
        for (tag, spelling) in literals.iter().chain(resolver_forms.iter()) {
            script.push_str(&probe_command(
                &probe,
                tag,
                &absolute_request("GET", spelling, "/latest/meta-data/"),
                15,
                ProbeMode::Read,
            ));
            script.push('\n');
        }
        script.push_str(&probe_command(
            &probe,
            "CONTROL",
            &absolute_request("GET", &format!("{control_spelling}:{port}"), "/po14-control"),
            15,
            ProbeMode::Read,
        ));
        script.push('\n');
        let r = b.run_sh_with_config(b.with_exec_tree(), &script);
        r.assert_entered();

        // Literal spellings: the policy refusal, whatever the resolver does.
        for (tag, spelling) in literals {
            if let Err(reason) = metadata_refusal(&r.out, tag, spelling) {
                panic!("{spelling}: {reason}; out=[{}]", r.snippet());
            }
        }

        // The control, judged by the same evidence rules: a whole 200 from the recorder when the
        // host resolver reads the decimal spelling; the bare 502 only when it independently refuses
        // it, and never on Linux.
        let control_resolution = HostResolution::of(control_spelling);
        let control_transcript = Transcript::of(&r.out, "CONTROL");
        let control_resolved = match control_resolution {
            HostResolution::Resolves => {
                assert!(
                    probe_reached_recorder(&r.out, "CONTROL"),
                    "the host resolver reads {control_spelling}, so the permitted decimal spelling must reach the recorder whole; transcript: {control_transcript:?}; out=[{}]",
                    r.snippet()
                );
                let seen = recorder.snapshot();
                assert!(seen.accept_errors.is_empty(), "{seen:?}");
                assert_eq!(
                    seen.request_lines(),
                    vec!["GET /po14-control HTTP/1.1".to_string()],
                    "the permitted decimal spelling reached the recorder, and nothing else did: {seen:?}"
                );
                true
            }
            HostResolution::Refuses => {
                assert_ne!(
                    Platform::current(),
                    Platform::Linux,
                    "glibc reads {control_spelling}; a refusal on Linux is a resolver fault, not a declared difference"
                );
                match judge_floor_probe(&r.out, "CONTROL", control_resolution) {
                    Ok(FloorAnswer::Unresolvable) => {}
                    other => panic!(
                        "the host resolver refuses {control_spelling}, so the control must be the gateway's bare 502, got {other:?}; transcript: {control_transcript:?}; out=[{}]",
                        r.snippet()
                    ),
                }
                eprintln!("PO-14: this host's resolver does not read {control_spelling}; inet_aton spellings are reported, not required");
                false
            }
        };

        // Resolver spellings: refused where the resolver reads them; Declared only with the host
        // resolver's independent refusal; never anything else.
        let mut unresolvable = Vec::new();
        for (tag, spelling) in resolver_forms {
            let refused = metadata_refusal(&r.out, tag, spelling);
            match (refused, judge_floor_probe(&r.out, tag, HostResolution::of(spelling))) {
                (Ok(()), _) => {}
                (Err(_), Ok(FloorAnswer::Unresolvable)) => unresolvable.push(spelling),
                (Err(reason), _) => panic!("{spelling}: {reason}; out=[{}]", r.snippet()),
            }
        }
        if control_resolved {
            assert!(
                unresolvable.is_empty(),
                "the resolver read the decimal control, so every inet_aton spelling of the metadata address reaches the policy decision; unresolvable: {unresolvable:?}; out=[{}]",
                r.snippet()
            );
        } else {
            eprintln!("PO-14: unresolvable on this host (not counted as a refusal): {unresolvable:?}");
        }

        // Nothing metadata-shaped reached the workload, and the recorder saw only the control.
        r.assert_absent("ami-id");
        r.assert_absent("instance-id");
        r.assert_absent("iam/");
        let seen = recorder.snapshot();
        assert!(seen.accept_errors.is_empty(), "{seen:?}");
        assert!(
            seen.request_lines().iter().all(|line| line == "GET /po14-control HTTP/1.1"),
            "only the control may reach the recorder: {seen:?}"
        );
        assert!(
            seen.incomplete().is_empty(),
            "every connection the recorder saw delivered a complete request: {seen:?}"
        );
    }
}

/// Whether probe `tag` was refused by the `metadata_addresses` forbid, for `spelling` at port 80.
fn metadata_refusal(out: &str, tag: &str, spelling: &str) -> Result<(), String> {
    let host = spelling.trim_end_matches('.').trim_start_matches('[').trim_end_matches(']');
    let target = format!("{host}:80");
    let transcript = Transcript::of(out, tag);
    if transcript.status_line.as_deref() != Some("HTTP/1.1 403 Forbidden") {
        return Err(format!("expected the policy's 403 Forbidden: {transcript:?}"));
    }
    let expected = format!("policy denied this operation on '{target}' [policy: metadata_addresses].");
    if transcript.body_text() != expected {
        return Err(format!("expected {expected:?}, got {:?}", transcript.body_text()));
    }
    Ok(())
}
