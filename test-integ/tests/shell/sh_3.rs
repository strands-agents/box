use strands_det_harness::det_case;

// `curl` in the hosted Shell is the Shell's own command, not a host binary: its request is an
// `http:request` effect the policy engine judges before any connection is made. Under the
// pristine policy only `*.api.aws` is permitted, so example.com is refused by default-deny,
// which curl reports as `policy denied this operation`. HTTP effects carry no journal row
// (the broker journals filesystem and spawn subjects only), so the evidence is curl's own report
// plus the absence of any body or 200 status. (The spawn gate is PO-9's subject.)
det_case! {
    name: sh_3,
    id:   "SH-3",
    desc: "Default-deny: the Shell's curl to an unpermitted host is refused by policy before any request is made",
    run: |b| {
        b.reset_policy();
        let r = b.run_mediated("curl -sS -w \"HTTP_%{http_code}\\n\" http://example.com/; echo CURL_RC=$?");
        r.assert_entered();
        r.assert_contains("policy denied this operation");
        r.assert_absent("HTTP_200");
        r.assert_absent("CURL_RC=0");
        r.assert_absent("<html");
        r.assert_absent("Example Domain");
    }
}
