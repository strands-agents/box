//! Incoming mount selections survive profile composition without adding filesystem authority.

use super::*;

fn linux(scene: &Scene, text: &str) -> (Resolved, Compiled) {
    scene
        .compile_using_in(
            &profile(text),
            &Context {
                workspace: scene.workspace(),
                os: "linux",
            },
            &mut Fixed,
            "/usr/bin:/bin",
        )
        .expect("a Linux profile compiles")
}

const PROCESSES: &str = r#"
[agent]
command = ["/usr/bin/true"]
[tool.reader]
command = ["/usr/bin/true"]
[mcp.local]
type = "stdio"
command = ["/usr/bin/true"]
"#;

#[test]
fn incoming_mount_selections_reach_only_the_process_that_declares_them() {
    for recipient in ["agent", "tool.reader", "mcp.local"] {
        let scene = Scene::new();
        let (_, ordinary) = linux(&scene, PROCESSES);
        let text = format!(
            "{PROCESSES}\n[{recipient}.filesystem]\nreceive_mounts = ['${{{{ home }}}}/incoming', '~/incoming']\n"
        );
        let (_, compiled) = linux(&scene, &text);
        let mut actual = table(&compiled);
        let expected = table(&ordinary);
        let process = match recipient {
            "agent" => &mut actual["agent"],
            "tool.reader" => &mut actual["tool"]["reader"],
            _ => &mut actual["mcp"]["local"],
        };
        let selections = process["filesystem"]
            .as_table_mut()
            .unwrap()
            .remove("receive_mounts")
            .unwrap();
        assert_eq!(
            selections,
            toml::Value::Array(vec![toml::Value::String(
                scene.home().join("incoming").display().to_string()
            )])
        );
        assert_eq!(
            actual, expected,
            "selection changes no grants, other recipient, or experimental features"
        );
        assert_eq!(
            compiled.policy, ordinary.policy,
            "selection adds no policy permission"
        );
    }
}

#[test]
fn explicitly_empty_incoming_mount_selections_survive_compilation() {
    for recipient in ["agent", "tool.reader", "mcp.local"] {
        let scene = Scene::new();
        let (_, compiled) = linux(
            &scene,
            &format!("{PROCESSES}\n[{recipient}.filesystem]\nreceive_mounts = []\n"),
        );
        let compiled = table(&compiled);
        let process = match recipient {
            "agent" => &compiled["agent"],
            "tool.reader" => &compiled["tool"]["reader"],
            _ => &compiled["mcp"]["local"],
        };
        assert_eq!(
            process["filesystem"]["receive_mounts"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}

#[test]
fn macos_refuses_incoming_mount_key_presence_even_when_empty() {
    let scene = Scene::new();
    scene
        .resolve(&profile(PROCESSES))
        .expect("omission is ordinary on macOS");
    for recipient in ["agent", "tool.reader", "mcp.local"] {
        for selection in ["[]", "['/mnt/data']"] {
            let reason = scene.resolve_refusal(&format!(
                "{PROCESSES}\n[{recipient}.filesystem]\nreceive_mounts = {selection}\n"
            ));
            assert!(
                reason.contains(&format!("{recipient}.filesystem.receive_mounts"))
                    && reason.contains("supported only on Linux"),
                "{reason}"
            );
        }
    }
}

#[test]
fn incoming_mount_selections_use_the_normal_platform_condition() {
    let scene = Scene::new();
    let text = format!(
        "{PROCESSES}\n[agent.filesystem]\nreceive_mounts = {{ value = ['/mnt/data'], when = 'linux' }}\n"
    );
    let mac = scene
        .resolve(&profile(&text))
        .expect("the Linux-only setting is omitted on macOS");
    assert_eq!(mac.agent.filesystem.receive_mounts, None);
    let (linux, _) = linux(&scene, &text);
    assert_eq!(
        linux.agent.filesystem.receive_mounts,
        Some(vec!["/mnt/data".into()])
    );
}

#[test]
fn incoming_mount_selections_refuse_non_list_and_non_string_values() {
    let scene = Scene::new();
    for recipient in ["agent", "tool.reader", "mcp.local"] {
        for selection in ["'/mnt/data'", "false", "[1]", "[{ path = '/mnt/data' }]"] {
            let error = scene
                .resolve_with(
                    &profile(&format!(
                        "{PROCESSES}\n[{recipient}.filesystem]\nreceive_mounts = {selection}\n"
                    )),
                    &Context {
                        workspace: scene.workspace(),
                        os: "linux",
                    },
                )
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("{recipient}.filesystem.receive_mounts"))
                    && error.contains("list of directory paths"),
                "{error}"
            );
        }
    }
}

#[test]
fn incoming_mount_paths_are_not_expanded_as_globs_or_resolved_as_links() {
    let scene = Scene::new();
    let target = scene.root.join("target");
    let link = scene.root.join("incoming");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (resolved, _) = linux(
        &scene,
        &format!("{PROCESSES}\n[agent.filesystem]\nreceive_mounts = [{link:?}, '/mnt/*']\n"),
    );
    assert_eq!(
        resolved.agent.filesystem.receive_mounts,
        Some(vec![link.display().to_string(), "/mnt/*".into()])
    );
}

#[test]
fn incoming_mounts_are_a_process_setting_and_need_no_experimental_switch() {
    let scene = Scene::new();
    let reason = scene.resolve_refusal(&format!(
        "{PROCESSES}\n[filesystem]\nreceive_mounts = ['/mnt/data']\n"
    ));
    assert!(
        reason.contains("process's") && reason.contains("[mcp.<name>.filesystem]"),
        "{reason}"
    );
    let reason = scene.resolve_refusal(&format!(
        "[experimental-features]\nlinux-storage-mounts = true\n{PROCESSES}"
    ));
    assert!(
        reason.contains("unknown key `linux-storage-mounts`"),
        "{reason}"
    );
}

fn receiving_agent(_scene: &Scene, selected: &Path) -> String {
    std::fs::create_dir_all(selected).unwrap();
    format!(
        "[agent]\ncommand = ['/usr/bin/true']\n[agent.filesystem]\nread = [{selected:?}]\nwrite = [{selected:?}]\nexec = [{selected:?}]\nreceive_mounts = [{selected:?}]\n"
    )
}

fn linux_refusal(scene: &Scene, text: &str) -> Error {
    scene
        .compile_using_in(
            &profile(text),
            &Context {
                workspace: scene.workspace(),
                os: "linux",
            },
            &mut Fixed,
            "/usr/bin:/bin",
        )
        .unwrap_err()
}

#[test]
fn an_exact_selected_exec_directory_accepts_native_read_write_execute_access() {
    let scene = Scene::new();
    let selected = scene.root.join("incoming");
    let text = receiving_agent(&scene, &selected);
    let (_, compiled) = linux(&scene, &text);
    let config = table(&compiled);
    for kind in ["read", "write", "exec", "receive_mounts"] {
        assert!(
            config["agent"]["filesystem"][kind]
                .as_array()
                .unwrap()
                .contains(&toml::Value::String(selected.display().to_string())),
            "{kind}"
        );
    }
}

#[test]
fn a_tool_selection_does_not_exempt_an_agents_executable_directory() {
    let scene = Scene::new();
    let selected = scene.root.join("incoming");
    let text = receiving_agent(&scene, &selected)
        .replace(&format!("receive_mounts = [{selected:?}]\n"), "");
    let text = format!(
        "{text}\n[tool.reader]\ncommand = ['/usr/bin/true']\nfilesystem.receive_mounts = [{selected:?}]\n"
    );
    assert!(matches!(
        linux_refusal(&scene, &text),
        Error::WriteUnderExec { .. }
    ));
}

#[test]
fn another_process_can_write_selected_data_but_cannot_make_ordinary_exec_writable() {
    let scene = Scene::new();
    let selected = scene.root.join("incoming");
    let ordinary = scene.root.join("ordinary");
    std::fs::create_dir(&ordinary).unwrap();
    let text = format!(
        "{}\n[tool.reader]\ncommand = ['/usr/bin/true']\nfilesystem.read = [{selected:?}]\nfilesystem.write = [{selected:?}]\n",
        receiving_agent(&scene, &selected)
    );
    linux(&scene, &text);
    let text = text
        .replace(
            &format!("exec = [{selected:?}]"),
            &format!("exec = [{selected:?}, {ordinary:?}]"),
        )
        .replace(
            &format!("filesystem.write = [{selected:?}]"),
            &format!("filesystem.write = [{selected:?}, {ordinary:?}]"),
        );
    assert!(
        matches!(linux_refusal(&scene, &text), Error::WriteUnderExec { exec, .. } if exec == ordinary)
    );
}

#[test]
fn incoming_selection_keeps_configured_commands_arguments_and_path_protected() {
    let scene = Scene::new();
    let selected = scene.root.join("incoming");
    let text = receiving_agent(&scene, &selected);
    let program = selected.join("program");
    std::fs::write(&program, "script").unwrap();
    let cases = [
        text.replace(
            "command = ['/usr/bin/true']",
            &format!("command = [{selected:?}]"),
        ),
        text.replace(
            "command = ['/usr/bin/true']",
            &format!("command = ['/usr/bin/true', {program:?}]"),
        ),
        text.replace("[agent]\n", &format!("[agent]\nenv.PATH = {selected:?}\n")),
        format!("{text}\n[tool.reader]\ncommand = [{program:?}]\n"),
    ];
    for case in cases {
        assert!(
            matches!(
                linux_refusal(&scene, &case),
                Error::ProgramUnderWrite { .. }
            ),
            "{case}"
        );
    }
}

#[test]
fn an_exec_ancestor_of_a_selection_has_an_actionable_refusal() {
    let scene = Scene::new();
    let parent = scene.root.join("data");
    let selected = parent.join("incoming");
    let text = receiving_agent(&scene, &selected);
    let covering = text
        .replace(
            &format!("read = [{selected:?}]"),
            &format!("read = [{parent:?}]"),
        )
        .replace(
            &format!("write = [{selected:?}]"),
            &format!("write = [{parent:?}]"),
        );
    linux(&scene, &covering);
    let text = covering.replace(
        &format!("exec = [{selected:?}]"),
        &format!("exec = [{parent:?}]"),
    );
    let error = linux_refusal(&scene, &text);
    assert!(
        matches!(&error, Error::IncomingMountExecAncestor { exec, selected: root, .. } if exec == &parent && root == &selected)
    );
    assert!(
        error
            .to_string()
            .contains("replace that exec entry with the exact selected directory")
    );
}

#[test]
fn incoming_selection_does_not_exempt_box_state_from_write_protection() {
    let scene = Scene::new();
    let selected = scene.home().join(".strands/box");
    let text = receiving_agent(&scene, &selected);
    assert!(matches!(
        linux_refusal(&scene, &text),
        Error::WriteOverProtected { .. }
    ));
}

#[test]
fn packed_mount_selections_compile_for_agent_tool_and_local_mcp_separately() {
    let scene = Scene::new();
    scene.share(
        "base",
        "[run]\ncommand = ['/usr/bin/true']\n[filesystem]\nreceive_mounts = ['/mnt/agent']",
    );
    scene.share("additions", "[tool.reader]\ncommand = ['/usr/bin/true']\nfilesystem.receive_mounts = ['/mnt/tool']\n[mcp.local.filesystem]\nreceive_mounts = ['/mnt/mcp']");
    let (_, compiled) = linux(
        &scene,
        "packs = ['@box/base', '@box/additions']\n[agent.filesystem]\nreceive_mounts = ['/mnt/agent', '/mnt/extra']\n[tool.reader.filesystem]\nreceive_mounts = []\n[mcp.local]\ntype = 'stdio'\ncommand = ['/usr/bin/true']\nfilesystem.receive_mounts = ['/mnt/mcp-extra']",
    );
    let config = table(&compiled);
    let selections = |process: &toml::Value| {
        process["filesystem"]["receive_mounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(selections(&config["agent"]), ["/mnt/agent", "/mnt/extra"]);
    assert_eq!(selections(&config["tool"]["reader"]), ["/mnt/tool"]);
    assert_eq!(
        selections(&config["mcp"]["local"]),
        ["/mnt/mcp", "/mnt/mcp-extra"]
    );
}
