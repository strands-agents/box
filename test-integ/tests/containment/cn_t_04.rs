use strands_det_harness::det_case;

// A tool states six filesystem lists. `metadata` and `exec` are refused at load by name, because a
// leaf discovers metadata across the operator home and runs its toolchain through broad exec.
det_case! {
    name: cn_t_04,
    id:   "CN-T-04",
    desc: "A [tool.<name>.filesystem] metadata or exec list is refused at load, naming the key",
    run: |b| {
        b.reset_policy();
        let workspace = serde_json::to_string(&b.workspace().to_string_lossy()).unwrap();
        let tool = move |list: &str| {
            let workspace = workspace.clone();
            let list = list.to_string();
            move |text: String| format!(
                "{text}\n[tool.echo]\ncommand = [\"/bin/echo\"]\n\
                 [tool.echo.filesystem]\n{list} = [{workspace}]\n"
            )
        };

        let control = b.run_sh_with_config(tool("read"), "printf RAN");
        control.assert_allow();
        control.assert_contains("RAN");

        for (list, removed) in [
            ("metadata", "[tool.<name>.filesystem] metadata"),
            ("exec", "[tool.<name>.filesystem] exec"),
        ] {
            let r = b.run_sh_with_config(tool(list), "printf RAN");
            r.assert_refused_at_load(&[removed], "RAN");
        }
    }
}
