// A workload that loops a refused call is refused every time, finishes, and cannot flood the
// box's telemetry: one key gives at most two records, and they account for every call.
use strands_det_harness::det_case;
use strands_det_harness::telemetry::CONTAINMENT_SCOPE;

det_case! {
    name: cn_k_02,
    id:   "CN-K-02",
    platforms: [Linux],
    desc: "100000 refused raw-socket calls all fail with EPERM and leave at most two records that sum to 100000",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r##"
import socket, time
start = time.monotonic()
refused = 0
for _ in range(100000):
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    except PermissionError:
        refused += 1
print("refused", refused, "seconds", round(time.monotonic() - start, 2))
"##,
        );
        r.assert_contains("refused 100000 ");
        let journal = b.telemetry();
        let socket: Vec<_> = journal.logs_under(CONTAINMENT_SCOPE).into_iter().filter(|record| {
            record.attributes.get("strands.box.containment.syscall").map(String::as_str) == Some("socket")
        }).collect();
        assert!(!socket.is_empty() && socket.len() <= 2, "{} records", socket.len());
        let calls: u64 = socket.iter().map(|record| {
            1 + record.attributes.get("strands.box.containment.suppressed").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        }).sum();
        assert_eq!(calls, 100_000);
        b.record_note(r.snippet());
    }
}
