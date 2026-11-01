use strands_det_harness::det_case;
use strands_det_harness::egress::{
    Ending, HostRecorder, PROBE_SOURCE, ProbeMode, Transcript, bare_shape, probe_command,
    probe_reached_recorder,
};

// The fault shapes come from SRT's client-abort cases (6fa73136): "aborted chunked upload never
// reaches the upstream framed as complete", "denied mid-upload", and "GET with a chunked body
// cannot smuggle a second request upstream".
//
// Proxy robustness measured from inside the cage with the compiled native probe (run under the
// agent's `exec` grant on `out/`), against a host recorder policy permits. The gateway buffers a
// whole request before it opens or writes the upstream, forwards exactly one request per
// connection under its own `Content-Length`, and refuses a frame that carries both a
// `Content-Length` and a `Transfer-Encoding`. So, in one native run:
//
//   1. an upload aborted mid-body (head, part of the body, close) opens no connection to the
//      recorder at all;
//   2. a `Content-Length` + `Transfer-Encoding: chunked` frame carrying a second request is
//      answered `400` and neither request reaches the recorder;
//   3. a second request written after a complete first one, in the same connection, is not
//      forwarded: the recorder receives the first request, re-framed, and nothing else;
//   4. after all three the same gateway serves an ordinary request whole, so no fault crashed
//      or wedged it.
//
// The recorder is proven live before the run and its snapshot lists exactly the two complete
// requests it received, in order, with nothing incomplete. This is proxy robustness, not kernel
// containment: a crash would fail closed for the workload, and the assertions here are about what
// reached the destination.
det_case! {
    name: po_16,
    id:   "PO-16",
    desc: "Proxy robustness from the native route: an aborted upload, a CL+TE frame carrying a second request, and a request riding a complete one deliver nothing extra to a live host recorder, and the gateway keeps serving",
    run: |b| {
        let recorder = HostRecorder::start();
        recorder.self_test();
        let port = recorder.port();
        let authority = format!("127.0.0.1:{port}");
        let probe = b.compile_probe("egress-probe", PROBE_SOURCE);

        b.apply_policy(&format!(
            r#"@id("recorder_connect") permit (principal, action == Box::Action::"net:connect", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};
@id("recorder_request") permit (principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "127.0.0.1" && context.input.port == {port} }};"#
        ));

        let abort = format!(
            "POST http://{authority}/po16-abort HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 100000\r\n\r\npartial-body"
        );
        let cl_te = format!(
            "POST http://{authority}/po16-legit HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET http://{authority}/po16-smuggled HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        );
        let pipelined = format!(
            "POST http://{authority}/po16-first HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 5\r\n\r\nhelloGET http://{authority}/po16-second HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        );
        let alive = format!(
            "GET http://{authority}/po16-alive HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        let script = format!(
            "{}\n{}\n{}\n{}\n",
            probe_command(&probe, "ABORT", abort.as_bytes(), 15, ProbeMode::Abort),
            probe_command(&probe, "CLTE", cl_te.as_bytes(), 15, ProbeMode::Read),
            probe_command(&probe, "PIPE", pipelined.as_bytes(), 15, ProbeMode::Read),
            probe_command(&probe, "ALIVE", alive.as_bytes(), 15, ProbeMode::Read),
        );
        let r = b.run_sh_with_config(b.with_exec_tree(), &script);
        r.assert_entered();
        assert_eq!(
            Transcript::of(&r.out, "ABORT").ending,
            Ending::Aborted,
            "the abort probe wrote and closed; out=[{}]",
            r.snippet()
        );

        // 2. The ambiguous frame is refused by the gateway itself: the complete bare 400, then the
        // connection ends. The gateway refuses the frame before it reads the body, so its close
        // answers unread request bytes with a reset on some kernels and a FIN on others; both are
        // the peer ending the connection after a complete answer, and neither is a probe error, a
        // timeout or an unread answer.
        let clte = Transcript::of(&r.out, "CLTE");
        assert!(
            matches!(clte.ending, Ending::Eof | Ending::Reset),
            "the gateway answered and ended the ambiguous frame's connection; transcript: {clte:?}; out=[{}]",
            r.snippet()
        );
        // The bytes are the gateway's bare `write_status(400)` and nothing else: exactly one
        // `Content-Length: 0` and one `Connection: close`, no other or repeated header, no body.
        if let Err(reason) = bare_shape(&clte, "HTTP/1.1 400 bad request") {
            panic!(
                "a Content-Length plus Transfer-Encoding frame is refused with the gateway's bare 400: {reason}; transcript: {clte:?}"
            );
        }
        assert!(
            !String::from_utf8_lossy(&clte.bytes).contains("DET_RECORDER_OK"),
            "nothing behind the ambiguous frame was answered from the recorder: {clte:?}"
        );

        // 3. The first request is served whole; the one riding it is not. A failure names every
        // leg: the probe transcript, the recorder's snapshot, the journaled decisions.
        let seen_now = recorder.snapshot();
        assert!(
            probe_reached_recorder(&r.out, "PIPE"),
            "the first request is served with the recorder's whole body; transcript: {:?}; recorder: {seen_now:?}; decisions: {:?}; out=[{}]",
            Transcript::of(&r.out, "PIPE"),
            r.decisions,
            r.snippet()
        );

        // 4. The gateway is still serving.
        assert!(
            probe_reached_recorder(&r.out, "ALIVE"),
            "the gateway serves after the faults; transcript: {:?}; recorder: {seen_now:?}; decisions: {:?}; out=[{}]",
            Transcript::of(&r.out, "ALIVE"),
            r.decisions,
            r.snippet()
        );

        // The boundary observation: exactly the two permitted, complete requests reached the
        // recorder, re-framed, in order — no abort bytes, no smuggled or riding request, nothing
        // incomplete, no accept error.
        let seen = recorder.snapshot();
        assert!(seen.accept_errors.is_empty(), "{seen:?}");
        assert_eq!(
            seen.request_lines(),
            vec![
                "POST /po16-first HTTP/1.1".to_string(),
                "GET /po16-alive HTTP/1.1".to_string(),
            ],
            "the recorder received the two complete requests and nothing else: {seen:?}"
        );
        assert_eq!(
            seen.observations.len(),
            2,
            "the aborted upload opened no connection and the refused frame opened none: {seen:?}"
        );
        assert!(
            seen.incomplete().is_empty(),
            "both recorded requests were read whole: {seen:?}"
        );
        let first = &seen.requests()[0];
        assert!(first.ends_with("hello"), "the first request's body arrived whole: {first:?}");
        assert!(
            first.contains("\r\nContent-Length: 5\r\n"),
            "the first request was re-framed under its own Content-Length: {first:?}"
        );
        assert!(!first.contains("po16-second"), "the riding request is not in the forwarded bytes: {first:?}");
        r.assert_mediated_permitted("http:request", &format!("{authority}/po16-first"));
        r.assert_mediated_permitted("http:request", &format!("{authority}/po16-alive"));
        assert!(
            !r.decisions.iter().any(|d| d.resource.contains("po16-second") || d.resource.contains("po16-smuggled") || d.resource.contains("po16-abort")),
            "no request effect was raised for an aborted, smuggled or riding request; decisions: {:?}",
            r.decisions
        );
    }
}
