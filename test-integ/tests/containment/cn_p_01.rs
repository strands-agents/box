use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_p_01,
    id: "CN-P-01",
    platforms: [Linux],
    desc: "The private proc view shows the native probe but hides a live owned host marker",
    run: |b| {
        let probe = support::compile(b);
        let mut marker = support::Marker::start(&probe, &b.workspace().with_file_name("marker"), false);
        let control = support::host(&probe, &["view", &marker.token]);
        assert!(control.contains("HOST_MARKER_VISIBLE"), "DET_ERROR: host cannot see marker: {control}");
        let host_namespace = std::fs::read_link("/proc/self/ns/pid").expect("DET_ERROR: host namespace");
        marker.advance();
        let r = b.run_sh_with_config(b.with_exec_tree(),
            &format!("{} view {}", support::q(&probe), marker.token));
        marker.advance();
        support::native_ok(&r, "VIEW_ENTERED");
        r.assert_contains("SELF_VISIBLE ");
        r.assert_contains("HOST_MARKER_ABSENT");
        r.assert_absent("HOST_MARKER_VISIBLE");
        r.assert_contains("PID_NAMESPACE pid:[");
        r.assert_absent(&format!("PID_NAMESPACE {}", host_namespace.display()));
        let after = support::host(&probe, &["view", &marker.token]);
        assert!(after.contains("HOST_MARKER_VISIBLE"), "DET_ERROR: host marker disappeared");
    }
}
