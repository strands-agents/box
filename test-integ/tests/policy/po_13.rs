use strands_det_harness::det_case;
use strands_det_harness::egress::{
    HostRecorder, PROBE_SOURCE, ProbeMode, Transcript, absolute_request, default_deny_pair,
    judge_policy_refusal, probe_command, probe_reached_recorder,
};

// A small TCP probe the case compiles into the fixture's `out/` tree runs from the native contained
// bash under the agent's own `exec` grant on that tree (the CN-X-02 / CN-N-03 route). Its socket
// is the agent's own syscall; nothing passes the broker. It connects to the port in `$HTTP_PROXY`,
// writes the request bytes, and prints the response bytes as hex records with an explicit end
// (EOF, timeout, error). Two host-owned recorders stand on loopback where a forwarded request
// lands. Policy permits `net:connect` and `http:request` to the first recorder's port only. The
// gateway forwards the permitted request to the first recorder and refuses the second as a
// policy refusal: `403 Forbidden`, the `x-strands-box-egress: refused` marker, and a body naming
// the refused `host:port` and the rule (`write_interceptor_error`). That is the authority's answer
// and not the floor's bare `403 forbidden`, which names no target; `judge_policy_refusal` requires
// the exact refusal shape and the target, and would refuse a floor answer. The second recorder —
// proven live by a direct host connection before the run — records no connection, complete or not.
// The journal holds the `net:connect` permit for the first destination and the deny for the second.
// The deny and the body are two representations of one default deny, each spelled by its own Core
// producer: the journal's rule `<default-deny>` with reason `no permit matched` and no determining
// id, the body's `[default-deny]: No permit policy matched this request.`; `default_deny_pair`
// asserts both exactly for this target.
//
// This measures the gateway path from inside the cage. It does not measure the kernel: a direct
// (non-proxied) connect from the workload is CN-N-03's subject.
det_case! {
    name: po_13,
    id:   "PO-13",
    desc: "Gateway from the native route: a permitted loopback destination is reached through $HTTP_PROXY and a policy-denied one is refused by the authority's 403 Forbidden naming the target; a live host recorder at the denied destination records nothing",
    run: |b| {
        let allowed = HostRecorder::start();
        let denied = HostRecorder::start();
        allowed.self_test();
        denied.self_test();
        let (allowed_port, denied_port) = (allowed.port(), denied.port());
        let probe = b.compile_probe("egress-probe", PROBE_SOURCE);

        b.apply_policy(&format!(
            r#"@id("recorder_connect") permit (principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {allowed_port} }};
@id("recorder_request") permit (principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {allowed_port} }};"#
        ));

        let script = format!(
            "{}\n{}\n",
            probe_command(
                &probe,
                "ALLOWED",
                &absolute_request("GET", &format!("127.0.0.1:{allowed_port}"), "/po13-allowed"),
                15,
                ProbeMode::Read,
            ),
            probe_command(
                &probe,
                "DENIED",
                &absolute_request("GET", &format!("127.0.0.1:{denied_port}"), "/po13-denied"),
                15,
                ProbeMode::Read,
            ),
        );
        let r = b.run_sh_with_config(b.with_exec_tree(), &script);
        r.assert_entered();

        // Allowed control: a complete 200 carrying exactly the recorder's marker, then EOF. On a
        // failure the message carries every leg's evidence: the probe transcript, what the
        // recorder saw, and the journaled decisions, so the failing leg is named.
        let allowed_transcript = Transcript::of(&r.out, "ALLOWED");
        let allowed_seen = allowed.snapshot();
        assert!(
            probe_reached_recorder(&r.out, "ALLOWED"),
            "the permitted destination answers a whole 200 with the recorder's body through the gateway; transcript: {allowed_transcript:?}; recorder: {allowed_seen:?}; decisions: {:?}; out=[{}]",
            r.decisions,
            r.snippet()
        );
        assert!(allowed_seen.accept_errors.is_empty(), "{allowed_seen:?}");
        assert_eq!(
            allowed_seen.request_lines(),
            vec!["GET /po13-allowed HTTP/1.1".to_string()],
            "the permitted recorder received exactly the permitted request: {allowed_seen:?}"
        );
        assert!(
            allowed_seen.incomplete().is_empty(),
            "the permitted recorder read its one request whole: {allowed_seen:?}"
        );
        r.assert_mediated_permitted("net:connect", &format!("127.0.0.1:{allowed_port}"));

        // The denied destination: the authority's refusal, in its exact shape, naming this target.
        let denied_target = format!("127.0.0.1:{denied_port}");
        let body = match judge_policy_refusal(&r.out, "DENIED", &denied_target) {
            Ok(body) => body,
            Err(reason) => panic!(
                "the denied destination must be refused by the authority's 403 Forbidden naming {denied_target}: {reason}; transcript: {:?}; out=[{}]",
                Transcript::of(&r.out, "DENIED"),
                r.snippet()
            ),
        };
        r.assert_mediated_denied("net:connect", &denied_target);
        let decision = r
            .decisions
            .iter()
            .find(|d| d.is_action("net:connect") && d.resource == denied_target && d.denied())
            .expect("the deny the assertion above found");
        if let Err(reason) = default_deny_pair(decision, &body, &denied_target) {
            panic!(
                "the journal deny and the refusal body are one default deny of {denied_target}: {reason}; decisions: {:?}",
                r.decisions
            );
        }

        // The boundary observation: the denied recorder saw no connection, complete or not.
        let denied_seen = denied.snapshot();
        assert!(denied_seen.accept_errors.is_empty(), "{denied_seen:?}");
        assert!(
            denied_seen.observations.is_empty(),
            "the denied destination was never contacted; observations: {denied_seen:?}"
        );
    }
}
