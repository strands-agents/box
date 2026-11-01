use strands_det_harness::{det_case, sh_quote};

// Current Linux limitation: revisit list-only grants when Landlock support is integrated and validated.
det_case! {
    name: cn_linux_list_refusal,
    id: "CN-LINUX-LIST",
    platforms: [Linux],
    desc: "Linux refuses a list-only grant before the workload runs, while a read grant exposes the same directory",
    run: |b| {
        let directory = b.listed_tree();
        let quoted = serde_json::to_string(&directory.to_string_lossy()).unwrap();
        let control_path = sh_quote(&directory.join("entry.txt").to_string_lossy());
        let read = quoted.clone();
        let control = b.run_sh_with_config(
            move |text| text.replacen("read = [", &format!("read = [{read}, "), 1),
            &format!("read -r value < {control_path}; printf 'LIST_CONTROL=%s\\n' \"$value\""),
        );
        control.assert_allow();
        control.assert_contains("LIST_CONTROL=LISTED_CONTENT");

        let refused = b.run_sh_with_config(
            move |text| text.replacen(
                "[agent.filesystem]",
                &format!("[agent.filesystem]\nlist = [{quoted}]"),
                1,
            ),
            "printf LIST_WORKLOAD_RAN",
        );
        refused.assert_refused_at_load(
            &["[agent]", "no lowering for `list`", &directory.to_string_lossy()],
            "LIST_WORKLOAD_RAN",
        );
    }
}
