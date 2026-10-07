use strands_det_harness::egress::HostRecorder;
use strands_det_harness::{SsrfFloor, det_case, judge_ssrf_probe};

// PO-12 sends the dotted metadata literal from the Shell's `curl`. This case sends the other
// spellings a workload might try — decimal, hex, octal, two-part, trailing dot — down the same
// route. The Shell's curl parses the URL with the WHATWG `url` crate, whose host parser reads
// every `inet_aton` form as an IPv4 address, so the Shell kernel's own floor (`check_url_safe`)
// refuses the request before any transport and names the canonical address in its refusal:
// `curl: access denied: 169.254.169.254`. That line is the proof that the spelling was
// canonicalized. `judge_ssrf_probe` rejects everything else.
//
// The Shell kernel's floor also refuses every loopback destination, spelled any way. A host
// recorder stands at the loopback port the workload names in decimal, so "refused" is a measured
// zero at the destination and not only curl's words. This pins the Shell's current contract; it
// is the reason a Shell-route allowed control against a loopback recorder does not exist, and why
// PO-13/PO-14/PO-16 use the native route for theirs.
det_case! {
    name: po_15,
    id:   "PO-15",
    desc: "Shell curl address spellings: every inet_aton and trailing-dot spelling of 169.254.169.254 is refused by the Shell kernel floor with the canonical address; a decimal loopback spelling is refused and its recorder sees nothing",
    run: |b| {
        b.apply_policy(
            r#"@id("net_all")  permit (principal, action == Box::Action::"net:connect",  resource);
@id("http_all") permit (principal, action == Box::Action::"http:request", resource);"#,
        );

        let spellings = [
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.43518",
            "169.254.169.254.",
        ];
        let mut floors = Vec::new();
        for spelling in spellings {
            let r = b.run_mediated(&format!(
                "curl -sS -w \"HTTP_%{{http_code}} BODY_%{{size_download}}\\n\" http://{spelling}/latest/meta-data/; echo CURL_RC=$?"
            ));
            r.assert_entered();
            match judge_ssrf_probe(&r.out) {
                Ok(SsrfFloor::ShellKernel) => {
                    // The refusal names the canonical address: the spelling was parsed as an IPv4
                    // address before the floor judged it.
                    r.assert_contains("curl: access denied: 169.254.169.254");
                    r.assert_contains("CURL_RC=1");
                    floors.push((spelling, "shell-kernel"));
                }
                Err(reason) => panic!("{spelling}: not the SSRF floor: {reason}; out=[{}]", r.snippet()),
            }
            r.assert_absent("HTTP_200");
            r.assert_absent("HTTP_401");
            r.assert_absent("ami-id");
            r.assert_absent("instance-id");
        }
        eprintln!("PO-15 floors: {floors:?}");

        // Loopback in decimal, against a live recorder: refused by the Shell kernel floor with the
        // canonical address, and the recorder records no connection.
        let recorder = HostRecorder::start();
        recorder.self_test();
        let port = recorder.port();
        let r = b.run_mediated(&format!(
            "curl -sS -w \"HTTP_%{{http_code}} BODY_%{{size_download}}\\n\" http://2130706433:{port}/po15; echo CURL_RC=$?"
        ));
        r.assert_entered();
        r.assert_contains("curl: access denied: 127.0.0.1");
        r.assert_contains("CURL_RC=1");
        r.assert_absent("HTTP_200");
        r.assert_absent("DET_RECORDER_OK");
        assert_eq!(
            recorder.connections(),
            0,
            "the Shell's curl must not reach a loopback recorder however the address is spelled; requests: {:?}",
            recorder.request_lines()
        );
    }
}
