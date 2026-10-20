// A target that does not name `kernel` receives no kernel-refusal record, and the refusal still
// fails with EPERM.
use strands_det_harness::det_case;
use strands_det_harness::telemetry::CONTAINMENT_SCOPE;

det_case! {
    name: cn_k_03,
    id:   "CN-K-03",
    platforms: [Linux],
    desc: "include = [\"deny\"] receives no kernel-refusal record; the refused call still fails",
    run: |b| {
        b.reset_policy();
        let destination = b.workspace().join("deny-only.jsonl");
        let r = b.probe_py_with_config(
            b.with_telemetry_file(&destination, &["deny"]),
            r##"
import socket
t("raw_socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0))
"##,
        );
        r.assert_errno("raw_socket", 1);
        assert!(b.telemetry_at(&destination).logs_under(CONTAINMENT_SCOPE).is_empty());
    }
}
