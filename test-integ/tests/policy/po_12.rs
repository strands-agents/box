use strands_det_harness::{SsrfFloor, det_case, judge_ssrf_probe};

// `curl` in the hosted Shell is the Shell's own command. Its request meets the Shell kernel's own
// SSRF floor (`check_url_safe`, before any transport) whatever policy permits: a link-local
// destination is refused as `PermissionDenied("access denied: 169.254.169.254")`, which curl
// prints as `curl: access denied: …` and answers with exit 1 — no HTTP status exists.
//
// What is not the floor: a `policy denied` (the broad permit did not take, so the floor was never
// asked), `blocked by egress control` (the gateway's L7 policy interceptor), a `curl: (6)`
// transport error, any HTTP status (the request passed the floor), or any metadata content.
// `judge_ssrf_probe` names each.
// Only options the Shell's curl implements are used (`-s`, `-S`, `-w`).
det_case! {
    name: po_12,
    id:   "PO-12",
    desc: "SSRF floor: a broad http:request permit still cannot reach 169.254.169.254 (IMDS) from the Shell's curl; the refusal is the Shell kernel floor's words",
    run: |b| {
        b.apply_policy(
            r#"@id("net_all")  permit (principal, action == Box::Action::"net:connect",  resource);
@id("http_all") permit (principal, action == Box::Action::"http:request", resource);"#,
        );
        let r = b.run_mediated(
            "curl -sS -w \"HTTP_%{http_code} BODY_%{size_download}\\n\" http://169.254.169.254/latest/meta-data/; echo CURL_RC=$?",
        );
        r.assert_entered();
        match judge_ssrf_probe(&r.out) {
            Ok(SsrfFloor::ShellKernel) => {
                r.assert_contains("curl: access denied: 169.254.169.254");
                r.assert_contains("CURL_RC=1");
            }
            Err(reason) => panic!("not the SSRF floor: {reason}; out=[{}]", r.snippet()),
        }
        r.assert_absent("HTTP_200");
        r.assert_absent("HTTP_401");
        r.assert_absent("ami-id");
        r.assert_absent("instance-id");
        r.assert_absent("iam/");
    }
}
