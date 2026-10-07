use strands_det_harness::{det_case, sh_quote};

// macOS only: a leaf runs its whole toolchain and loads what it builds
// (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds). A tool with
// `write = [work]` copies a compiled program and a compiled dynamic library into `work`, then runs
// the program and loads the library, both by its own syscalls: broad exec and the one
// `file-map-executable` allow over its writable grant. `write` does not imply `read`, and `dlopen`
// opens the file for reading, so the tool also reads `work`. The agent box keeps full W^X: its
// own exec of the same written program is refused, and its load of the same written library is
// refused by the sandbox, while the original program under its `exec` entry runs (CN-X-01, CN-X-03).
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

const LIBRARY: &str = "#[no_mangle]\npub extern \"C\" fn det_leaf_value() -> i32 {\n    4204\n}\n";

det_case! {
    name: cn_x_04,
    id:   "CN-X-04",
    platforms: [Macos],
    desc: "Leaf build output: a tool with write=[work] (and read of it) execs a program and dlopens a library it copied into work; the agent's own exec and load of the same written files are refused",
    run: |b| {
        let probe = b.compile_probe("leafprobe-x04", PROBE);
        let out = b.exec_tree();
        let source = out.join("detx04.rs");
        let library = out.join("libdetx04.dylib");
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
        let loaded = work.join("libcopy.dylib");

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
        agent.assert_contains("file system sandbox blocked mmap()");
    }
}
