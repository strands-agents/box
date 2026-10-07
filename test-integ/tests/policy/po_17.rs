use strands_det_harness::det_case;
use strands_det_harness::egress::{
    HostRecorder, PROBE_SOURCE, ProbeMode, Transcript, absolute_request, probe_command,
    probe_reached_recorder,
};

// `net:connect` is decided on the pinned address.
//
// `localhost` resolves to two addresses, `127.0.0.1` and `::1`. The compiled native probe sends a
// request for `localhost:<port>` through `$HTTP_PROXY` to a host recorder on loopback, twice. The
// first run permits the host at `net:connect` and `http:request`, and the request reaches the
// recorder. The second run keeps those permits and adds one `forbid` on `context.input.ip` for both
// addresses. The gateway decides that forbid on each resolved, pinned address after DNS, so the
// permitted host is refused by the authority's `403 Forbidden` naming the rule, and the recorder
// records no connection. The forbid does not load where `ip` is not a string.
det_case! {
    name: po_17,
    id:   "PO-17",
    desc: "Pinned address: a permitted host that resolves to 127.0.0.1 and ::1 is reached, and the same host is refused by a forbid on context.input.ip for those addresses; the recorder sees only the first request",
    run: |b| {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let port = recorder.port();
        let probe = b.compile_probe("egress-probe", PROBE_SOURCE);
        let target = format!("localhost:{port}");
        let permits = format!(
            r#"@id("localhost_connect") permit (principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "localhost" && context.input.port == {port} }};
@id("localhost_request") permit (principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "localhost" && context.input.port == {port} }};"#
        );
        let script = |tag: &str, path: &str| {
            format!(
                "{}\n",
                probe_command(&probe, tag, &absolute_request("GET", &target, path), 15, ProbeMode::Read)
            )
        };

        // The host permitted, no address rule: the request reaches the recorder.
        b.apply_policy(&permits);
        let r = b.run_sh_with_config(b.with_exec_tree(), &script("ALLOWED", "/po17-allowed"));
        r.assert_entered();
        assert!(
            probe_reached_recorder(&r.out, "ALLOWED"),
            "the permitted host answers a whole 200 through the gateway; transcript: {:?}; decisions: {:?}; out=[{}]",
            Transcript::of(&r.out, "ALLOWED"),
            r.decisions,
            r.snippet()
        );
        r.assert_mediated_permitted("net:connect", &target);

        // The same permits and a forbid on the pinned address: the host is refused after DNS.
        b.apply_policy(&format!(
            r#"{permits}
@id("block_loopback") forbid (principal, action == Box::Action::"net:connect", resource)
when {{ context.input has ip && (context.input.ip == "127.0.0.1" || context.input.ip == "::1") }};"#
        ));
        let r = b.run_sh_with_config(b.with_exec_tree(), &script("BLOCKED", "/po17-blocked"));
        r.assert_entered();
        let transcript = Transcript::of(&r.out, "BLOCKED");
        assert_eq!(
            transcript.status_line.as_deref(),
            Some("HTTP/1.1 403 Forbidden"),
            "the authority refuses the pinned address; transcript: {transcript:?}; out=[{}]",
            r.snippet()
        );
        assert_eq!(
            transcript.body_text(),
            format!("policy denied this operation on '{target}' [policy: block_loopback]."),
            "the refusal names the forbid on the address; transcript: {transcript:?}"
        );
        r.assert_forbidden_by("net:connect", &target, "block_loopback");

        // Only the permitted request reached the recorder.
        let seen = recorder.snapshot();
        assert!(seen.accept_errors.is_empty(), "{seen:?}");
        assert_eq!(
            seen.request_lines(),
            vec!["GET /po17-allowed HTTP/1.1".to_string()],
            "the refused request never reached the recorder: {seen:?}"
        );
        assert!(seen.incomplete().is_empty(), "{seen:?}");
    }
}
