use super::{MINIMAL, OnPath, Scene, profile, table};

#[test]
fn native_policy_is_absent_until_a_profile_selects_it() {
    let scene = Scene::new();
    let config = table(
        &scene
            .compile(&profile(MINIMAL), None)
            .expect("default profile"),
    );
    assert!(config.get("experimental-features").is_none());
    assert!(config["agent"].get("native-filesystem-policy").is_none());
}

#[test]
fn native_policy_preserves_each_explicit_global_selection() {
    let scene = Scene::new();
    for selected in [true, false] {
        let text =
            format!("{MINIMAL}\n[experimental-features]\nnative-filesystem-policy = {selected}\n");
        let config = table(
            &scene
                .compile(&profile(&text), None)
                .expect("selected profile"),
        );
        assert_eq!(
            config["experimental-features"]["native-filesystem-policy"].as_bool(),
            Some(selected)
        );
    }
}

#[test]
fn native_policy_conditions_apply_to_profiles_and_process_overrides() {
    let scene = Scene::new();
    for table_when in [false, true] {
        for os in ["macos", "linux"] {
            for selected in [false, true] {
                let selection = if table_when {
                    format!(
                        "[experimental-features]\nwhen = {os:?}\nnative-filesystem-policy = {selected}"
                    )
                } else {
                    format!(
                        "[experimental-features]\nnative-filesystem-policy = {{ value = {selected}, when = {os:?} }}"
                    )
                };
                let text = format!(
                    "{MINIMAL}\nnative-filesystem-policy = {{ value = false, when = {os:?} }}\n{selection}"
                );
                let config = table(
                    &scene
                        .compile(&profile(&text), None)
                        .expect("a conditional profile selection"),
                );
                assert_eq!(
                    config
                        .get("experimental-features")
                        .and_then(|features| features.get("native-filesystem-policy"))
                        .and_then(toml::Value::as_bool),
                    (os == "macos").then_some(selected),
                    "{text}"
                );
                assert_eq!(
                    config["agent"]
                        .get("native-filesystem-policy")
                        .and_then(toml::Value::as_bool),
                    (os == "macos").then_some(false),
                    "{text}"
                );
            }
        }
    }
}

#[test]
fn native_policy_rejects_inherited_pack_selection_before_profile_overrides() {
    let scene = Scene::new();
    scene.share_raw(
        "wrapper",
        "[pack]\nname = \"@box/wrapper\"\nversion = 1\nkind = \"support\"\nextend = [\"@box/native-policy\"]",
    );
    for selected in [false, true] {
        for condition in ["", "when = \"linux\"\n"] {
            scene.share(
                "native-policy",
                &format!(
                    "[experimental-features]\n{condition}native-filesystem-policy = {selected}"
                ),
            );
            for profile_value in [false, true] {
                let text = format!(
                    "packs = [\"@box/wrapper\"]\n{MINIMAL}\n[experimental-features]\nnative-filesystem-policy = {profile_value}"
                );
                let (path, line, reason) = scene.located(&text);
                assert_eq!(path, scene.root.join("packs/native-policy/pack.toml"));
                assert!(line.is_some(), "{reason}");
                assert!(reason.contains("experimental-features"), "{reason}");
                assert!(reason.contains("profile.toml"), "{reason}");
            }
        }
    }
}

#[test]
fn native_policy_rejects_pack_process_settings_before_profile_overrides() {
    let scene = Scene::new();
    for section in ["agent", "tool.custom"] {
        for value in ["true", "false", "{ value = true, when = \"linux\" }"] {
            scene.share(
                "process-policy",
                &format!(
                    "[{section}]\ncommand = [\"/usr/bin/true\"]\nnative-filesystem-policy = {value}"
                ),
            );
            let text = format!(
                "packs = [\"@box/process-policy\"]\n[experimental-features]\nnative-filesystem-policy = true\n{MINIMAL}\nnative-filesystem-policy = false\n[tool.custom]\ncommand = [\"/usr/bin/true\"]\nnative-filesystem-policy = false"
            );
            let (path, line, reason) = scene.located(&text);
            assert_eq!(path, scene.root.join("packs/process-policy/pack.toml"));
            assert!(line.is_some(), "{section}: {reason}");
            assert!(reason.contains("native-filesystem-policy"), "{reason}");
            assert!(reason.contains("profile.toml"), "{reason}");
        }
    }
}

#[test]
fn native_policy_rejects_pack_tools_inside_conditional_value_tables() {
    let scene = Scene::new();
    for os in ["macos", "linux"] {
        for selected in [false, true] {
            scene.share(
                "wrapped-tool-policy",
                &format!(
                    "[tool]\nwhen = \"{os}\"\n[tool.value.command]\ncommand = [\"/usr/bin/true\"]\nnative-filesystem-policy = {selected}"
                ),
            );
            let text = format!(
                "packs = [\"@box/wrapped-tool-policy\"]\n{MINIMAL}\n[experimental-features]\nnative-filesystem-policy = false"
            );
            let (path, line, reason) = scene.located(&text);
            assert_eq!(path, scene.root.join("packs/wrapped-tool-policy/pack.toml"));
            assert!(line.is_some(), "{reason}");
            assert!(reason.contains("native-filesystem-policy"), "{reason}");
            assert!(reason.contains("profile.toml"), "{reason}");
        }
    }
}

#[test]
fn native_policy_keeps_workload_overrides_and_inheritance_distinct() {
    let scene = Scene::new();
    let text = r#"
[experimental-features]
native-filesystem-policy = true
[agent]
command = ["/usr/bin/true"]
native-filesystem-policy = false
[tool.explicit]
command = ["/usr/bin/true"]
native-filesystem-policy = true
[tool.inherited]
command = ["/usr/bin/true"]
[mcp.explicit]
type = "stdio"
command = ["/usr/bin/true"]
native-filesystem-policy = false
[mcp.inherited]
type = "stdio"
command = ["/usr/bin/true"]
"#;
    let config = table(
        &scene
            .compile(&profile(text), None)
            .expect("workload selections"),
    );
    assert_eq!(
        config["agent"]["native-filesystem-policy"].as_bool(),
        Some(false)
    );
    assert_eq!(
        config["tool"]["explicit"]["native-filesystem-policy"].as_bool(),
        Some(true)
    );
    assert!(
        config["tool"]["inherited"]
            .get("native-filesystem-policy")
            .is_none()
    );
    assert_eq!(
        config["mcp"]["explicit"]["native-filesystem-policy"].as_bool(),
        Some(false)
    );
    assert!(
        config["mcp"]["inherited"]
            .get("native-filesystem-policy")
            .is_none()
    );
}

#[test]
fn native_policy_refuses_unknown_features_and_non_boolean_selections() {
    let scene = Scene::new();
    for (setting, expected) in [
        (
            "native-filesystem-policy = \"true\"",
            "is `true` or `false`",
        ),
        ("native-filesystem-policy = 1", "is `true` or `false`"),
        (
            "native-filesystem-polic = true",
            "did you mean `native-filesystem-policy`?",
        ),
        ("tool-grammars = true", "unknown key `tool-grammars`"),
    ] {
        let text = format!("{MINIMAL}\n[experimental-features]\n{setting}");
        let reason = scene.resolve_refusal(&text);
        assert!(reason.contains(expected), "{setting}: {reason}");
    }
    for section in ["agent", "tool.custom"] {
        let text = format!(
            "[{section}]\ncommand = [\"/usr/bin/true\"]\nnative-filesystem-policy = \"false\""
        );
        let reason = scene.resolve_refusal(&text);
        assert!(reason.contains("expected a boolean"), "{section}: {reason}");
    }
}

#[test]
fn native_policy_coexists_with_automatic_tool_grammar_activation() {
    let scene = Scene::new();
    let bin = scene.root.join("bin");
    crate::test_support::binary(&bin.join("greet"));
    scene.share("greet", &crate::lang::test_tool_pack("greet", ""));
    let grammar = r#"
format = 1
version = 1
name = "greet"
program = "greet"

[effects]
loud = "Shouts the greeting"

[shell.hello]
usage = "greet hello [options] [<name>]"
options.loud = { flag = ["--loud"], adds = ["loud"] }
"#;
    std::fs::write(scene.root.join("packs/greet/grammar.toml"), grammar)
        .expect("a tool pack grammar");
    let text = format!(
        "packs = [\"@box/greet\"]\n{MINIMAL}\n[experimental-features]\nnative-filesystem-policy = true"
    );
    let (_, compiled) = scene
        .compile_using(&profile(&text), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("a native policy profile with a valid tool grammar");
    let config = table(&compiled);
    assert_eq!(
        config["experimental-features"]["native-filesystem-policy"].as_bool(),
        Some(true)
    );
    assert_eq!(
        config["experimental-features"]["tool-grammars"].as_bool(),
        Some(true)
    );
    assert_eq!(
        config["tool"]["greet"]["grammar"],
        toml::from_str::<toml::Value>(grammar).expect("the expected grammar")
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn native_policy_profile_selection_is_saved_without_an_activation_pack() {
    for selected in [None, Some(false)] {
        let host = crate::FakeHost::new();
        let created = host
            .profile()
            .name("native-check")
            .with("@box/claude")
            .with("@box/bedrock")
            .create()
            .expect("a profile from the bundled packs");
        let path = created.path().to_path_buf();
        created.write(false).expect("a saved profile");
        let saved = std::fs::read_to_string(&path).expect("the saved profile text");
        if let Some(value) = selected {
            std::fs::write(
                &path,
                format!("{saved}\n[experimental-features]\nnative-filesystem-policy = {value}\n"),
            )
            .expect("an explicit profile selection");
        }
        let preview = host
            .launcher()
            .preview("native-check", &host.project())
            .expect("a preview with native checks unselected or explicitly disabled");
        let config: toml::Value = toml::from_str(&preview.box_toml).expect("engine configuration");
        assert_eq!(
            config
                .get("experimental-features")
                .and_then(|features| features.get("native-filesystem-policy"))
                .and_then(toml::Value::as_bool),
            selected
        );
    }
}
