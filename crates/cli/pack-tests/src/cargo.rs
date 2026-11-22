use crate::support::*;
use std::collections::BTreeMap;

#[test]
fn a_rustup_proxy_gets_a_table_on_the_proxy_and_a_permit_scoped_to_cargo() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let cargo = resolution(&generated, "cargo");
    let proxy = host.home().join(".cargo/bin/rustup");
    assert_eq!(cargo.identity, proxy);
    assert_eq!(cargo.pack, "@box/cargo");
    assert!(
        generated
            .box_toml()
            .contains(&format!("command = [\"{}\"]", proxy.display()))
    );
    assert!(generated.policy().contains(
        r#"context.input.program_path == "~/.cargo/bin/rustup" && context.input.program == "cargo" }"#
    ));
}

#[test]
fn a_hard_linked_rustup_proxy_runs_as_its_own_file() {
    let host = FakeHost::new();
    let cargo = host.home().join(".cargo/bin/cargo");
    std::fs::remove_file(&cargo).expect("remove the symlink");
    std::fs::hard_link(host.home().join(".cargo/bin/rustup"), &cargo).expect("a hard link");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let found = resolution(&generated, "cargo");
    assert_eq!(found.identity, cargo);
    assert!(!found.read.contains(&host.home().join(".cargo")));
    assert!(generated.policy().contains(
        r#"context.input.program_path == "~/.cargo/bin/cargo" && context.input.program == "cargo" }"#
    ));
}

#[test]
fn cargo_has_the_gateway_upgrade_its_rustup_downloads_to_https() {
    let host = FakeHost::new();
    pack(
        &host,
        "registry",
        "include = [\"@box/npm\"]\n[tool.npm]\n\
         hosts = [\"registry.npmjs.org\", \"static.rust-lang.org\"]\n\
         upgrade_http = [\"static.rust-lang.org\"]",
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .with("registry")
        .os("linux")
        .tools(["cargo", "npm"])
        .generate()
        .expect("a configuration");
    let config = box_toml(&generated);
    assert_eq!(
        strings(&config["gateway"]["upgrade_http"]),
        ["static.rust-lang.org"]
    );
    let cargo = tool(&generated, "cargo");
    assert!(
        cargo["env"].get("RUSTUP_DIST_SERVER").is_none(),
        "Linux rustup keeps https: {cargo}"
    );
    for name in ["cargo", "npm"] {
        assert!(
            tool(&generated, name).get("upgrade_http").is_none(),
            "{name}"
        );
    }
}

#[test]
fn rustup_on_macos_asks_the_gateway_over_plain_http() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let developer = trees.folder("CommandLineTools");
    binary(&developer.join("usr/bin/cc"));
    std::fs::create_dir_all(developer.join("SDKs/MacOSX.sdk")).expect("an SDK");
    let generated = macos_cargo(&host, &developer);
    assert_eq!(
        tool(&generated, "cargo")["env"]["RUSTUP_DIST_SERVER"].as_str(),
        Some("http://static.rust-lang.org")
    );
    assert_eq!(
        strings(&box_toml(&generated)["gateway"]["upgrade_http"]),
        ["static.rust-lang.org"]
    );
}

#[test]
fn cargo_trusts_the_certificate_authority_in_its_runs_box_folder() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["cargo"])
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let folder = file["box_dir"].as_str().expect("a box folder");
    assert_eq!(
        tool(&generated, "cargo")["env"]
            .get("CARGO_HTTP_CAINFO")
            .and_then(toml::Value::as_str),
        Some(format!("{folder}/trust/cert.pem").as_str())
    );
}

#[test]
fn rustup_home_is_in_the_tools_state_and_the_box_reads_the_one_rustup_home_names() {
    let host = FakeHost::new();
    let elsewhere = host.home().join("toolchains");
    std::fs::create_dir_all(&elsewhere).expect("a folder");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .variable("RUSTUP_HOME", text(&elsewhere))
        .tools(["cargo"])
        .generate()
        .expect("a configuration");
    let cargo = tool(&generated, "cargo");
    let home = cargo["env"]["RUSTUP_HOME"].as_str().expect("a rustup home");
    assert!(home.ends_with("/tool/cargo/rustup"), "{home}");
    assert!(!home.starts_with(&text(&elsewhere)), "{home}");
    let read = strings(&cargo["filesystem"]["read"]);
    assert!(read.contains(&text(&elsewhere)), "{read:?}");
    assert!(
        !read.contains(&text(&host.home().join(".rustup"))),
        "{read:?}"
    );
}

#[test]
fn cargo_links_with_the_compiler_and_sdk_of_the_selected_developer_folder() {
    for (layout, toolchain, sdk) in [
        (
            "Xcode.app/Contents/Developer",
            "Toolchains/XcodeDefault.xctoolchain/usr/bin",
            "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
        ),
        ("CommandLineTools", "usr/bin", "SDKs/MacOSX.sdk"),
    ] {
        let host = FakeHost::new();
        let trees = Trees::new();
        let developer = trees.folder(layout);
        binary(&developer.join(toolchain).join("cc"));
        binary(&developer.join("usr/bin/cc"));
        std::fs::create_dir_all(developer.join(sdk)).expect("an SDK");
        std::fs::create_dir_all(developer.join("SDKs/MacOSX.sdk")).expect("an SDK");
        let generated = macos_cargo(&host, &developer);
        let env = &tool(&generated, "cargo")["env"];
        let bin = developer.join(toolchain);
        let apple: BTreeMap<&str, &str> = env
            .as_table()
            .expect("an env table")
            .iter()
            .filter(|(name, _)| name.contains("apple_darwin") || name.contains("APPLE_DARWIN"))
            .map(|(name, value)| (name.as_str(), value.as_str().expect("a string")))
            .collect();
        let expected: Vec<(&str, String)> = [
            ("AR_aarch64_apple_darwin", "ar"),
            ("AR_x86_64_apple_darwin", "ar"),
            ("CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", "cc"),
            ("CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER", "cc"),
            ("CC_aarch64_apple_darwin", "cc"),
            ("CC_x86_64_apple_darwin", "cc"),
            ("CXX_aarch64_apple_darwin", "c++"),
            ("CXX_x86_64_apple_darwin", "c++"),
        ]
        .into_iter()
        .map(|(name, program)| (name, text(&bin.join(program))))
        .collect();
        assert_eq!(
            apple
                .into_iter()
                .map(|(name, value)| (name, value.to_string()))
                .collect::<Vec<_>>(),
            expected,
            "{layout}"
        );
        assert!(
            env.get("CC").is_none(),
            "{layout}: a plain CC reaches every target"
        );
        assert_eq!(
            env["SDKROOT"].as_str(),
            Some(text(&developer.join(sdk)).as_str()),
            "{layout}"
        );
        for (name, value) in [("macos.toolchain", toolchain), ("macos.sdk_root", sdk)] {
            assert!(
                generated
                    .inputs()
                    .iter()
                    .any(|(read, found, source)| read == name
                        && found == &text(&developer.join(value))
                        && source == "macos.developer_dir"),
                "{name}: {:?}",
                generated.inputs()
            );
        }
    }
}

#[test]
fn a_developer_folder_with_no_compiler_skips_cargo_with_the_reason() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let developer = trees.folder("Empty/Developer");
    std::fs::create_dir_all(developer.join("SDKs/MacOSX.sdk")).expect("an SDK");
    let generated = macos_cargo(&host, &developer);
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, why)| name.starts_with("cargo") && why.contains("macos.toolchain")),
        "{:?}",
        generated.skipped()
    );
}

#[test]
fn a_dnf_cargo_reads_rustc_as_a_file_and_a_rustup_cargo_reads_its_proxies() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("usr/bin/cargo"));
    binary(&trees.path("usr/bin/rustc"));
    trees.folder("usr/lib/rustlib");
    let generated = trial(&host, &[&trees.path("usr/bin")])
        .os("linux")
        .variable("CARGO_HOME", text(&host.home().join("absent")))
        .tools(["cargo"])
        .generate()
        .expect("a configuration");
    let read = strings(&tool(&generated, "cargo")["filesystem"]["read"]);
    assert!(
        read.contains(&text(&trees.path("usr/bin/rustc"))),
        "{read:?}"
    );
    assert!(
        read.contains(&text(&trees.path("usr/lib/rustlib"))),
        "{read:?}"
    );
    assert!(!read.contains(&text(&trees.path("usr/bin"))), "{read:?}");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .os("linux")
        .tools(["cargo"])
        .generate()
        .expect("a configuration");
    let cargo = tool(&generated, "cargo");
    assert!(
        strings(&cargo["filesystem"]["read"]).contains(&text(&host.home().join(".cargo/bin"))),
        "{cargo}"
    );
    assert!(cargo["env"].get("RUSTC").is_none(), "{cargo}");
    for name in [
        "SDKROOT",
        "CC_aarch64_apple_darwin",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
    ] {
        assert!(cargo["env"].get(name).is_none(), "{name}: {cargo}");
    }
}
