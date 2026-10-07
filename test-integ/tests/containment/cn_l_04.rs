use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_l_04,
    id: "CN-L-04",
    desc: "Ordinary workload exit removes a descendant observed alive from the host",
    run: |b| {
        use std::time::Duration;
        let probe = support::compile(b);
        let dir = b.workspace().join("descendant-state");
        std::fs::create_dir(&dir).expect("DET_ERROR: descendant directory");
        let _stop = support::StopDescendant(dir.clone());
        let script = format!("exec {} workload {} {} {} {}",
            support::q(&probe), support::q(&dir), support::q(&b.ready_marker()),
            support::q(&b.go_marker()), support::q(&probe));
        let mut original = Vec::new();
        let mut released = None;
        let r = b.run_sh_with_config_meanwhile(b.with_exec_tree(), &script, || {
            original = support::marked_rows(&probe, &dir);
            assert_eq!(original.len(), 1, "DET_ERROR: expected one marked descendant: {original:?}");
            let before = support::number(&dir.join("heartbeat"));
            support::until(
                || support::number(&dir.join("heartbeat")) > before,
                Duration::from_secs(3), "live descendant positive control"
            );
            assert_eq!(support::marked_rows(&probe, &dir).len(), 1, "DET_ERROR: descendant vanished before exit");
            original = support::process_tree(&probe, &original);
            println!("CN-L-04 HOST_TREE {original:?}");
            released = Some(std::time::Instant::now());
        });
        support::native_ok(&r, "DESCENDANT_STARTED ");
        r.assert_contains("ORDINARY_EXIT");
        support::require_exit_deadline(
            released.expect("DET_ERROR: workload was not released").elapsed(),
            Duration::from_secs(10));
        support::require_cleanup(&probe, &dir, Duration::from_secs(3), &original);
    }
}
