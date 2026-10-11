// A call the Linux syscall filter refuses still fails with EPERM, and now leaves one kernel-refusal
// record under the box's containment scope: an argument-scoped refusal names its decoded
// arguments, an unlisted one names only the call, and neither is a policy decision.
use strands_det_harness::det_case;
use strands_det_harness::telemetry::CONTAINMENT_SCOPE;

det_case! {
    name: cn_k_01,
    id:   "CN-K-01",
    platforms: [Linux],
    desc: "A refused raw socket and an unlisted bpf call fail with EPERM and each leave a kernel-refusal record",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r##"
import socket
t("raw_socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0))
print("bpf", *raw("syscall", 280, 0, 0, 0))
"##,
        );
        r.assert_errno("raw_socket", 1);
        r.assert_contains("bpf rc -1 errno 1");

        let journal = b.telemetry();
        let refusals = journal.logs_under(CONTAINMENT_SCOPE);
        let named = |syscall: &str| refusals.iter().filter(|record| {
            record.attributes.get("strands.box.containment.syscall").map(String::as_str) == Some(syscall)
        }).collect::<Vec<_>>();
        let socket = named("socket");
        assert_eq!(socket.len(), 1, "one raw-socket refusal record: {refusals:?}");
        assert_eq!(
            socket[0].attributes.get("strands.box.containment.arguments").map(String::as_str),
            Some("family=AF_PACKET type=SOCK_RAW")
        );
        assert_eq!(socket[0].attributes.get("strands.box.containment.errno").map(String::as_str), Some("EPERM"));
        assert!(socket[0].attributes.keys().all(|key| !key.starts_with("strands.box.policy.")));
        let bpf = named("bpf");
        assert_eq!(bpf.len(), 1, "one bpf refusal record: {refusals:?}");
        assert!(bpf[0].attributes.get("strands.box.containment.arguments").is_none());
        // Startup refusals the interpreter itself makes are expected; the note names them.
        let calls: Vec<&str> = refusals
            .iter()
            .filter_map(|record| record.attributes.get("strands.box.containment.syscall").map(String::as_str))
            .collect();
        b.record_note(format!("{} refusal record(s): {calls:?}", refusals.len()));
    }
}
