use strands_det_harness::det_case;

det_case! {
    name: cn_linux_future_deny_refusal,
    id: "CN-LINUX-FUTURE-DENY",
    platforms: [Linux],
    desc: "Linux refuses an absent deny path before the workload runs, while an existing deny path permits startup",
    run: |b| {
        let existing = b.workspace().join("startup-existing.env");
        let future = b.workspace().join("startup-future.env");
        std::fs::write(&existing, "STARTUP_PROTECTED\n")
            .expect("DET_ERROR: create the existing deny control");
        assert!(!future.exists(), "DET_ERROR: the future deny path already exists");
        let with_deny = |path: &std::path::Path| {
            let quoted = serde_json::to_string(&path.to_string_lossy()).unwrap();
            move |text: String| text.replacen(
                "[agent.filesystem]",
                &format!("[agent.filesystem]\ndeny = [{quoted}]"),
                1,
            )
        };
        let control = b.run_sh_with_config(with_deny(&existing), "printf DENY_CONTROL_RAN");
        control.assert_allow();
        control.assert_contains("DENY_CONTROL_RAN");
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "STARTUP_PROTECTED\n");

        let refused = b.run_sh_with_config(with_deny(&future), "printf DENY_WORKLOAD_RAN");
        refused.assert_refused_at_load(
            &["[agent]", "does not exist yet", "Linux", &future.to_string_lossy()],
            "DENY_WORKLOAD_RAN",
        );
        assert!(!future.exists(), "the refused startup created the absent deny path");
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "STARTUP_PROTECTED\n");
    }
}
