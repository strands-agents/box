use strands_det_harness::{det_case, sh_quote};

// docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

const LIBRARY: &str = "#[no_mangle]\npub extern \"C\" fn det_leaf_value() -> i32 {\n    4204\n}\n";

det_case! {
    name: when_tool_runs_or_loads_written_output_then_it_works_but_agent_execution_and_loading_are_refused,
    id:   "CN-X-04",
    platforms: [Macos, Linux],
    desc: "Leaf build output: a tool with write=[work] (and read of it) execs a program and dlopens a library it copied into work; the agent's own exec and load of the same written files are refused",
    run: |b| {
        let probe = b.compile_probe("leafprobe-x04", PROBE);
        let out = b.exec_tree();
        let source = out.join("detx04.rs");
        let library = out.join(format!("libdetx04.{}", std::env::consts::DLL_EXTENSION));
        std::fs::write(&source, LIBRARY).expect("DET_ERROR: write the library source");
        let compiled = std::process::Command::new("rustc")
            .args(["--edition", "2021", "--crate-type", "cdylib", "-O", "-o"])
            .arg(&library)
            .arg(&source)
            .output()
            .expect("DET_ERROR: rustc is on PATH");
        assert!(compiled.status.success(), "DET_ERROR: rustc failed on the library: {}",
            String::from_utf8_lossy(&compiled.stderr));
        let work = b.workspace().join("x04-work");
        std::fs::create_dir(&work).expect("DET_ERROR: the tool's work directory");
        let program = work.join("hello-copy");
        let loaded = work.join(format!("libcopy.{}", std::env::consts::DLL_EXTENSION));

        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let exec_tree = b.with_exec_tree();
        let edit = |text: String| format!(
            "{}\n[tool.x04]\ncommand = [{}]\n\n[tool.x04.filesystem]\nread = [{}, {}]\nwrite = [{}]\n",
            exec_tree(text), quoted(&probe), quoted(&out), quoted(&work), quoted(&work)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let p = sh_quote(&probe.to_string_lossy());
        let s = |path: &std::path::Path| sh_quote(&path.to_string_lossy());
        let r = b.run_mediated_with_config(edit, &format!(
            "{p} copy {h} {c}; {p} exec {c} leaf-ran; {p} copy {l} {d}; {p} dlopen {d}",
            h = s(&b.built_tool()), c = s(&program), l = s(&library), d = s(&loaded),
        ));
        r.assert_mediated_permitted("shell:spawn", "leafprobe-x04");
        let line = |tag: &str, path: &std::path::Path| format!("{tag} {:?}", path.to_string_lossy());

        // The tool wrote both files, and the host holds them.
        r.assert_contains(&format!("{} -> {:?}", line("COPY_OK", &b.built_tool()), program.to_string_lossy()));
        r.assert_contains(&format!("{} -> {:?}", line("COPY_OK", &library), loaded.to_string_lossy()));
        assert_eq!(std::fs::read(&program).unwrap(), std::fs::read(b.built_tool()).unwrap(), "the copied program differs on the host");
        assert_eq!(std::fs::read(&loaded).unwrap(), std::fs::read(&library).unwrap(), "the copied library differs on the host");
        // The tool ran and loaded what it wrote.
        r.assert_contains(&format!("{} :: BUILD_OUTPUT_RAN leaf-ran", line("EXEC_OK", &program)));
        r.assert_contains(&format!("{} value=4204", line("DLOPEN_OK", &loaded)));

        // The agent: the original program runs under its exec entry, and the written copies do not.
        let agent = b.run_sh_with_config(edit, &format!(
            "{h} agent-original; {c} agent-ran; printf 'AGENT_EXEC_RC=%s\\n' \"$?\"; {p} dlopen {d}",
            h = s(&b.built_tool()), c = s(&program), d = s(&loaded),
        ));
        agent.assert_contains("BUILD_OUTPUT_RAN agent-original");
        agent.assert_absent("BUILD_OUTPUT_RAN agent-ran");
        agent.assert_contains("AGENT_EXEC_RC=126");
        agent.assert_kernel_marker();
        agent.assert_absent("DLOPEN_OK");
        agent.assert_contains(&line("DLOPEN_REFUSED", &loaded));
        #[cfg(target_os = "macos")]
        agent.assert_contains("file system sandbox blocked mmap()");
        #[cfg(target_os = "linux")]
        agent.assert_contains("failed to map segment from shared object");
    }
}
