use strands_det_harness::det_case;

// The fixture permits `net:connect` on port 443 and no `http:request` to example.com, so the
// gateway admits the connection and refuses the Shell's `curl` at the `http:request` gate with its
// 403 and the origin marker. The Shell's kernel turns a marked response into a refusal, never a
// response: `curl` exits 1, prints the gateway's explanation naming the gate, the target, and the
// rule on stderr, and writes no body to stdout. The harness appends the box's stderr after its
// stdout, so the explanation after `CURL_RC` is the proof it was not on stdout. The Shell's own
// floor refuses every loopback and private address before the gateway, so the denied host is a
// public one, and a runner with no route to it records an ERROR, not a FAIL.
det_case! {
    name: sh_neg_curl_403,
    id:   "SH-NEG-CURL-403",
    desc: "Gateway policy 403: the Shell's curl to a connect-permitted, request-denied public host exits 1 with the http:request refusal naming the target on stderr and prints no body",
    run: |b| {
        b.reset_policy();
        let target = "example.com:443/";
        let r = b.run_mediated("curl -sS https://example.com/; echo CURL_RC=$?");
        r.assert_entered();
        assert!(
            !(r.out.contains("CURL_RC=6\n") && !r.decisions.iter().any(|d| d.denied())),
            "DET_ERROR: curl reported a transport failure and the box refused nothing, so the runner has no route to example.com:443; decisions: {:?}; out=[{}]",
            r.decisions,
            r.snippet()
        );
        r.assert_mediated_permitted("net:connect", "example.com:443");
        let rule = r.assert_mediated_denied("http:request", target);
        assert!(
            rule.contains("default-deny"),
            "the request must be refused by default-deny, not a rule of the case's own: {rule}"
        );
        r.assert_contains("CURL_RC=1\n");
        let explanation = format!(
            "curl: http:request gate: policy denied this operation on '{target}' [default-deny]"
        );
        r.assert_contains(&explanation);
        let status_at = r.out.find("CURL_RC=1\n").expect("asserted above");
        let explanation_at = r.out.find(&explanation).expect("asserted above");
        assert!(
            status_at < explanation_at,
            "the explanation must be on stderr: it precedes the status echo, so curl wrote it to stdout; out=[{}]",
            r.snippet()
        );
        r.assert_absent("CURL_RC=0");
        r.assert_absent("<html");
        r.assert_absent("Example Domain");
    }
}
