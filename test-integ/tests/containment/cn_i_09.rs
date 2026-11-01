use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_i_09,
    id: "CN-I-09",
    platforms: [Linux],
    desc: "A native ptrace attach cannot stop or trace a live owned host marker",
    run: |b| {
        let probe = support::compile(b);
        let mut marker = support::Marker::start(&probe, &b.workspace().with_file_name("trace-marker"), true);
        let pid = marker.pid().to_string();
        let control = support::host(&probe, &["trace", &pid]);
        assert!(control.contains("TRACE_REACHED") && control.contains("TRACE_DETACHED"),
            "DET_ERROR: host trace control failed: {control}");
        marker.advance();
        let r = b.run_sh_with_config(b.with_exec_tree(),
            &format!("{} trace {pid}", support::q(&probe)));
        marker.advance();
        support::native_ok(&r, "TRACE_ENTERED");
        r.assert_contains("SELF_PID ");
        support::require_refusal(&r.out, "TRACE", &[1, 3]);
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("DET_ERROR: host marker status");
        assert!(status.lines().any(|l| l == "TracerPid:\t0"), "marker still traced: {status}");
        let after = support::host(&probe, &["trace", &pid]);
        assert!(after.contains("TRACE_DETACHED"), "DET_ERROR: trace observer stopped working");
        marker.advance();
    }
}
