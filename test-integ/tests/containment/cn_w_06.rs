use strands_det_harness::{det_case, user_home};

// Containment CN-W (Linux workload, act 6)
//
// A `[tool.cargo]` with enumerated exec trees builds a crate; the built binary then runs as its own
// declared tool by path spelling, and a same-tree binary no tool names is refused.
fn with_cargo(text: String, hello_tool: bool) -> String {
    let ws = text
        .lines()
        .find_map(|line| line.strip_prefix("workspace = "))
        .expect("the template names the workspace")
        .trim_matches('"')
        .to_string();
    let home = user_home().canonicalize().expect("home").display().to_string();
    let q = |s: &str| serde_json::to_string(s).unwrap();
    let crate_root = format!("{ws}/hello-crate");
    let mut tables = format!(
        "\n[tool.cargo]\ncommand = [\"cargo\"]\nworkspace = {c}\n\n[tool.cargo.env]\nTMPDIR = {tmp}\nRUSTFLAGS = \"-C linker=/usr/bin/gcc -C link-arg=-fuse-ld=bfd\"\n\n[tool.cargo.filesystem]\nread = [{w}, {rustup}, \"/usr/lib/gcc\"]\nwrite = [{c}, {cargo_home}]\nexec = [{cargo_bin}, {toolchains}, \"/usr/bin/gcc\", \"/usr/bin/ld.bfd\", \"/usr/libexec/gcc\", {target}]\n",
        c = q(&crate_root),
        tmp = q(&format!("{crate_root}/target/tmp")),
        w = q(&ws),
        rustup = q(&format!("{home}/.rustup")),
        cargo_home = q(&format!("{home}/.cargo")),
        cargo_bin = q(&format!("{home}/.cargo/bin")),
        toolchains = q(&format!("{home}/.rustup/toolchains")),
        target = q(&format!("{crate_root}/target")),
    );
    if hello_tool {
        tables.push_str(&format!(
            "\n[tool.hello]\ncommand = [{bin}]\nworkspace = {c}\n\n[tool.hello.filesystem]\nread = [{c}]\nexec = [{target}]\n",
            bin = q(&format!("{crate_root}/target/debug/hello")),
            c = q(&crate_root),
            target = q(&format!("{crate_root}/target")),
        ));
    }
    text + &tables
}

// TEMPORARY QUARANTINE (linux): this fixture authors `[tool.cargo.filesystem]` and
// `[tool.hello.filesystem] exec`, which a box refuses at load
// (docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds). Broad exec
// ships on macOS only; broad exec for a Linux tool leaf is a currently-missing feature. The case
// runs only on linux, so it records an authorized SKIP there (see test-integ/src/quarantine.rs
// and QUARANTINE.md) until that Linux broad-exec feature lands. The body and its assertions are
// unchanged.
det_case! {
    name: cn_w_06,
    id:   "CN-W-06",
    platforms: [Linux],
    desc: "Workload act 6: cargo builds inside [tool.cargo] with enumerated exec trees; the built binary runs as a declared tool and a stranger beside it is refused",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_any") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let crate_root = b.workspace().join("hello-crate");
        let r = b.run_sh_with_config(
            |text| with_cargo(text, false),
            &format!("zsh -c 'cd {c} && cargo build -q 2>&1; echo CARGO_RC=$?'", c = crate_root.display()),
        );
        r.assert_contains("CARGO_RC=0");
        let built = crate_root.join("target/debug/hello");
        assert!(built.is_file(), "cargo must leave the binary at {}", built.display());
        let stranger = crate_root.join("target/debug/other");
        std::fs::copy(&built, &stranger).expect("DET_ERROR: copy the binary beside itself");
        let r = b.run_sh_with_config(
            |text| with_cargo(text, true),
            &format!("zsh -c '{} && echo HELLO_RC=$?'", built.display()),
        );
        r.assert_contains("HELLO_RAN");
        r.assert_contains("HELLO_RC=0");
        let r = b.run_sh_with_config(
            |text| with_cargo(text, true),
            &format!("zsh -c '{}; echo OTHER_RC=$?'", stranger.display()),
        );
        r.assert_absent("HELLO_RAN");
        r.assert_contains("no `[tool.<name>] command` matches this program");
    }
}
