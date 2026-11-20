use crate::support::*;

#[test]
fn a_standalone_pnpm_reads_its_program_and_not_pnpm_home() {
    let host = FakeHost::new();
    let standalone = host.home().join("Library/pnpm");
    strands_box_cli_profile::fixtures::binary(&standalone.join("pnpm"));
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["node", "pnpm"])
        .search_path(std::env::join_paths([&standalone, &host.brew().join("bin")]).expect("a PATH"))
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let strings = |list: &str| -> Vec<String> {
        file["tool"]["pnpm"]["filesystem"][list]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let read = strings("read");
    assert!(
        !read
            .iter()
            .any(|entry| standalone.starts_with(entry) || Path::new(entry).starts_with(&standalone)),
        "no read reaches PNPM_HOME, its store, or a folder above it: {read:?}"
    );
    assert!(
        strings("read_file").contains(&standalone.join("pnpm").display().to_string()),
        "{:?}",
        strings("read_file")
    );
}

/// The `read` and `read_file` lists of the pnpm table for an npm-global pnpm whose program is
/// `bin/<program>`, with `~` and the Homebrew prefix written as `~` and `brew`.
fn npm_global_pnpm_reads(program: &str) -> (Vec<String>, Vec<String>) {
    let host = FakeHost::new();
    let package = host.brew().join("lib/node_modules/pnpm");
    strands_box_cli_profile::fixtures::write(&package.join("package.json"), r#"{"name":"pnpm"}"#);
    strands_box_cli_profile::fixtures::write(
        &package.join(format!("bin/{program}")),
        "#!/usr/bin/env node\n",
    );
    strands_box_cli_profile::fixtures::executable(&package.join(format!("bin/{program}")));
    strands_box_cli_profile::fixtures::write(&package.join("dist/pnpm.cjs"), "");
    strands_box_cli_profile::fixtures::link(
        &format!("../lib/node_modules/pnpm/bin/{program}"),
        &host.brew().join("bin/pnpm"),
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["node", "pnpm"])
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let brew = host.brew().display().to_string();
    let project = generated.project().display().to_string();
    let list = |name: &str| -> Vec<String> {
        file["tool"]["pnpm"]["filesystem"][name]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(|entry| entry.replace(&project, "project").replace(&brew, "brew"))
                    .collect()
            })
            .unwrap_or_default()
    };
    (list("read"), list("read_file"))
}

#[test]
fn an_npm_global_pnpm_reads_its_program_its_dist_and_its_package_json() {
    let hosts = if cfg!(target_os = "macos") {
        "/private/etc/hosts"
    } else {
        "/etc/hosts"
    };
    let package = "brew/lib/node_modules/pnpm";
    for program in ["pnpm.cjs", "pnpm.mjs"] {
        let (read, read_file) = npm_global_pnpm_reads(program);
        let pnpm: Vec<&String> = read
            .iter()
            .filter(|entry| entry.contains("node_modules/pnpm"))
            .collect();
        assert_eq!(pnpm, [&format!("{package}/dist")], "{program}: {read:?}");
        assert!(
            !read.iter().any(|entry| package.starts_with(entry.as_str())),
            "{program}: nothing above the package is read: {read:?}"
        );
        assert_eq!(
            read_file,
            [
                format!("{package}/bin/{program}"),
                format!("{package}/package.json"),
                hosts.to_string(),
            ],
            "{program}"
        );
    }
}

/// **@box/pnpm extends @box/node, so pnpm gets @box/node's variables, not only its interpreter.**
/// pnpm is a `#!/usr/bin/env node` script. The interpreter step gives it node's reads, and
/// `extend` gives it @box/node's `env` too. pnpm's own variables stay, and `PATH` and `TMPDIR` are
/// its own.
#[test]
fn pnpm_gets_the_variables_of_box_node_which_it_extends() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.folder("launchers/bin");
    binary(&bin.join("node"));
    script_with(&bin.join("pnpm"), "#!/usr/bin/env node\n");
    let generated = trial(&host, &[&bin])
        .os("linux")
        .tools(["pnpm"])
        .generate()
        .expect("a configuration");
    let pnpm = tool(&generated, "pnpm");
    let env = pnpm["env"].as_table().expect("an env table");
    let mut keys: Vec<&str> = env.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "COREPACK_ENABLE_DOWNLOAD_PROMPT",
            "COREPACK_HOME",
            "PATH",
            "PNPM_CONFIG_CACHE_DIR",
            "PNPM_CONFIG_STATE_DIR",
            "PNPM_CONFIG_STORE_DIR",
            "PNPM_HOME",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "npm_config_audit",
            "npm_config_cache",
            "npm_config_cache_dir",
            "npm_config_fund",
            "npm_config_script_shell",
            "npm_config_state_dir",
            "npm_config_store_dir",
            "npm_config_update_notifier",
        ],
        "{pnpm}"
    );
    assert_eq!(
        env["npm_config_cache"].as_str(),
        Some(format!("{}/.npm", text(&host.project())).as_str())
    );
    assert_eq!(env["npm_config_script_shell"].as_str(), Some("/bin/bash"));
    assert_eq!(env["npm_config_audit"].as_str(), Some("false"));
    assert_eq!(env["npm_config_fund"].as_str(), Some("false"));
    assert_ne!(env["TMPDIR"], tool(&generated, "node")["env"]["TMPDIR"]);
    assert!(
        strings(&pnpm["filesystem"]["read_file"]).contains(&text(
            &std::fs::canonicalize("/etc/hosts").expect("the hosts file")
        )),
        "{pnpm}"
    );
}
