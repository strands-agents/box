//! Execute the research broker through Box's agent and tool launch paths.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support"
))]

use std::path::PathBuf;
use std::process::Command;

fn run(
    operation: &str,
    allow: bool,
    agent_enabled: bool,
    tool: Option<bool>,
    shared_history: bool,
) {
    let test_root = std::env::var_os("NATIVE_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("test working directory"));
    let root = tempfile::tempdir_in(test_root)
        .expect("native test directory")
        .keep();
    let workspace = root.as_path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let file_directory = if operation == "outside" {
        root.clone()
    } else if operation == "lchild" {
        let directory = workspace.join("child");
        std::fs::create_dir(&directory).unwrap();
        directory
    } else {
        workspace.clone()
    };
    let creating = operation.starts_with('c') && operation != "cexisting";
    let source = file_directory.join(if creating { "new.txt" } else { "source.txt" });
    let destination = workspace.join("destination.txt");
    if !creating {
        std::fs::write(&source, "original\n").unwrap();
    }
    let workload = PathBuf::from(
        std::env::var("NATIVE_WORKLOAD").unwrap_or_else(|_| env!("NATIVE_WORKLOAD").to_owned()),
    );
    assert!(workload.is_file());
    let staged = root.join("native-workload");
    std::fs::copy(&workload, &staged).unwrap();
    let workload = staged;
    let mut policy = String::from(
        "permit(principal, action == Box::Action::\"fs:read\", resource);\n\
         permit(principal, action == Box::Action::\"shell:exec\", resource);\n\
         permit(principal, action == Box::Action::\"shell:spawn\", resource);\n",
    );
    if matches!(
        operation,
        "read" | "quiet" | "urandom" | "virtual" | "vchild" | "enumerate" | "handle"
    ) && !allow
    {
        policy.push_str("forbid(principal, action == Box::Action::\"fs:read\", resource);\n");
    }
    if shared_history {
        policy.push_str(
            "permit(principal, action == Box::Action::\"fs:write\", resource)\n\
             when temporal { formerly within 1h (Box::Action::\"shell:spawn\"::request{input.program_path: \"~/native-workload\"}) };\n"
        );
    } else if allow {
        for action in ["fs:write", "fs:delete", "fs:move"] {
            policy.push_str(&format!(
                "permit(principal, action == Box::Action::\"{action}\", resource);\n"
            ));
        }
    }
    let mediated = tool.unwrap_or(agent_enabled);
    let permitted = if shared_history {
        tool.is_some()
    } else {
        allow
    };
    let expected = if operation == "handle" && mediated && permitted {
        "probe"
    } else if (operation == "xtruncate" && !mediated)
        || matches!(operation, "zero" | "grantless" | "outside")
    {
        "deny"
    } else if permitted || !mediated {
        "allow"
    } else {
        "deny"
    };
    let args = [
        operation.to_string(),
        source.display().to_string(),
        destination.display().to_string(),
        expected.into(),
    ];
    let command = if tool.is_some() {
        // The native agent uses the Box shell alias. The hosted Shell selects the declared tool.
        let script = format!("zsh -c '{} {}'", workload.display(), args.join(" "));
        vec!["/bin/bash".to_string(), "-c".into(), script]
    } else {
        std::iter::once(workload.display().to_string())
            .chain(args)
            .collect()
    };
    let quoted =
        |path: &std::path::Path| toml::Value::String(path.display().to_string()).to_string();
    let mut config = format!(
        "name = \"native-launch-research\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
         [experimental-features]\nnative-filesystem-policy = true\n\
         [agent]\ncommand = {}\nworkspace = {}\nnative-filesystem-policy = {agent_enabled}\n\
         [agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
        quoted(&root.as_path().join("state")),
        toml::Value::Array(command.into_iter().map(toml::Value::String).collect()),
        quoted(&workspace),
        quoted(&workspace),
        quoted(&workspace)
    );
    if let Some(enabled) = tool {
        config.push_str(&format!(
            "[tool.native]\ncommand = [{}]\nworkspace = {}\nnative-filesystem-policy = {enabled}\n\
             [tool.native.filesystem]\nread = [{}]\nwrite = [{}]\n",
            quoted(&workload),
            quoted(&workspace),
            quoted(&workspace),
            quoted(&workspace)
        ));
    }
    if operation == "grantless" {
        config = config.replace(&format!("write = [{}]", quoted(&workspace)), "write = []");
    }
    let config_path = root.as_path().join("box.toml");
    std::fs::write(&config_path, config).unwrap();
    std::fs::write(root.as_path().join("policy.dw"), policy).unwrap();
    let mut launch = if !agent_enabled && !tool.unwrap_or(false) {
        let mut command = Command::new("/usr/bin/setpriv");
        command.args(["--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]);
        command.arg(env!("CARGO_BIN_EXE_strands-box"));
        command
    } else {
        Command::new(env!("CARGO_BIN_EXE_strands-box"))
    };
    let output = launch
        .args(["run", "--config"])
        .arg(&config_path)
        .env("HOME", root.as_path())
        .current_dir(&workspace)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let path_handles = !stderr.contains("this kernel cannot transfer O_PATH");
    let expected = if expected == "probe" {
        if path_handles { "allow" } else { "deny" }
    } else {
        expected
    };
    println!("case={operation}, allow={allow}, agent={agent_enabled}, tool={tool:?}\n{stderr}");
    assert!(output.status.success(), "{output:?}");
    let marker = if expected == "allow" {
        "NATIVE_ALLOWED"
    } else {
        "NATIVE_DENIED"
    };
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(marker),
        "{output:?}"
    );
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).expect("native policy event"))
        .collect();
    assert_eq!(
        events.len(),
        usize::from(mediated) * if operation == "fd" { 2 } else { 1 },
        "{stderr}"
    );
    if operation == "fd" {
        assert_eq!(events[0]["outcome"], "descriptor_issued", "{stderr}");
        assert_eq!(
            events[0]["decisions"][0]["operation"], "Enumerate",
            "{stderr}"
        );
    }
    if matches!(operation, "zero" | "outside") {
        assert!(
            events[0]["decisions"].as_array().unwrap().is_empty(),
            "{stderr}"
        );
        if operation == "zero" {
            assert_eq!(events[0]["broker_errno"], libc::ENOENT, "{stderr}");
        }
    } else if operation == "grantless" {
        assert_eq!(events[0]["outcome"], "failed", "{stderr}");
        assert_eq!(events[0]["broker_errno"], libc::EROFS, "{stderr}");
        assert_eq!(events[0]["decisions"][0]["allow"], true, "{stderr}");
    } else if operation == "handle" && mediated && !path_handles {
        assert_eq!(
            events[0]["refusal"], "kernel cannot transfer path-only handles",
            "{stderr}"
        );
        assert_eq!(events[0]["decisions"], serde_json::json!([]));
    } else if let Some(event) = events.last() {
        let decisions = event["decisions"].as_array().expect("policy decisions");
        assert!(!decisions.is_empty(), "{event}");
        if expected == "deny" {
            assert_eq!(event["outcome"], "denied", "{event}");
            assert_eq!(decisions.last().unwrap()["allow"], false, "{event}");
        } else {
            let outcome = if matches!(
                operation,
                "move" | "delete" | "mlocal" | "dlocal" | "xtruncate"
            ) {
                "completed"
            } else {
                "descriptor_issued"
            };
            assert_eq!(event["outcome"], outcome, "{event}");
            assert!(
                decisions.iter().all(|decision| decision["allow"] == true),
                "{event}"
            );
        }
    }
    if mediated {
        let journal =
            std::fs::read_to_string(root.join("state/private/telemetry/records.jsonl")).unwrap();
        let target = match operation {
            "urandom" => "/dev/urandom".to_owned(),
            "virtual" => "/proc/2/stat".to_owned(),
            "vchild" => "/proc/3/stat".to_owned(),
            "enumerate" => "~/workspace".to_owned(),
            "handle" if !path_handles => workspace.display().to_string(),
            "handle" => "~/workspace".to_owned(),
            "zero" => "absent.txt".to_owned(),
            "outside" => source.display().to_string(),
            _ => format!("~/{}", source.strip_prefix(&root).unwrap().display()),
        };
        let mut found = false;
        for line in journal.lines() {
            let payload: serde_json::Value =
                serde_json::from_str(line).expect("OTLP journal payload");
            for resource in payload["resourceLogs"].as_array().into_iter().flatten() {
                for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                    if scope["scope"]["name"] != "strands-box.policy" {
                        continue;
                    }
                    for record in scope["logRecords"].as_array().into_iter().flatten() {
                        let attributes: std::collections::HashMap<_, _> = record["attributes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter_map(|a| {
                                Some((a["key"].as_str()?, a["value"]["stringValue"].as_str()?))
                            })
                            .collect();
                        if attributes.get("file.path") == Some(&target.as_str())
                            && attributes.get("strands.box.policy.verdict")
                                == Some(&if expected == "allow" {
                                    "permit"
                                } else {
                                    "deny"
                                })
                        {
                            found = true;
                        }
                    }
                }
            }
        }
        assert!(
            found,
            "missing {expected} journal record for {target}: {journal}"
        );
    }
    if expected == "deny" {
        if creating {
            assert!(!source.exists());
        } else {
            assert_eq!(std::fs::read_to_string(&source).unwrap(), "original\n");
        }
        assert!(!destination.exists());
    } else if matches!(operation, "move" | "mlocal") {
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "original\n");
    } else if matches!(operation, "delete" | "dlocal") {
        assert!(!source.exists());
    } else {
        let expected = match operation {
            "read" | "quiet" | "urandom" | "virtual" | "vchild" | "enumerate" | "handle" => {
                "original\n"
            }
            "append" => "original\nnative workload wrote\n",
            "xtruncate" => "ori",
            _ => "native workload wrote\n",
        };
        assert_eq!(std::fs::read_to_string(&source).unwrap(), expected);
        if operation == "cwide" || operation == "clocal" {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&source).unwrap().permissions().mode() & 0o777,
                if operation == "cwide" { 0o640 } else { 0o600 }
            );
        }
    }
}

#[test]
fn agent_write_allow() {
    run("write", true, true, None, false);
}
#[test]
fn agent_write_deny() {
    run("write", false, true, None, false);
}
#[test]
fn agent_create_allow() {
    run("create", true, true, None, false);
}
#[test]
fn agent_create_deny() {
    run("create", false, true, None, false);
}
#[test]
fn agent_delete_allow() {
    run("delete", true, true, None, false);
}
#[test]
fn agent_delete_deny() {
    run("delete", false, true, None, false);
}
#[test]
fn agent_move_allow() {
    run("move", true, true, None, false);
}
#[test]
fn agent_move_deny() {
    run("move", false, true, None, false);
}
#[test]
fn disabled_agent_uses_only_filesystem_grants() {
    run("write", false, false, None, false);
}
#[test]
fn enabled_tool_denies_native_write() {
    run("write", false, false, Some(true), false);
}
#[test]
fn disabled_tool_uses_only_filesystem_grants() {
    run("write", false, false, Some(false), false);
}
#[test]
fn native_tool_observes_the_hosted_shells_request_history() {
    run("write", true, false, Some(true), true);
}

#[test]
fn native_agent_has_no_shell_spawn_history() {
    run("write", false, true, None, true);
}

#[test]
fn tool_create_allow() {
    run("create", true, false, Some(true), false);
}
#[test]
fn tool_create_deny() {
    run("create", false, false, Some(true), false);
}
#[test]
fn tool_delete_allow() {
    run("delete", true, false, Some(true), false);
}
#[test]
fn tool_delete_deny() {
    run("delete", false, false, Some(true), false);
}
#[test]
fn tool_move_allow() {
    run("move", true, false, Some(true), false);
}
#[test]
fn tool_move_deny() {
    run("move", false, false, Some(true), false);
}

fn dynamic_program(permit: bool) {
    let parent = std::env::var_os("NATIVE_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let quote = |p: &std::path::Path| toml::Value::String(p.display().to_string()).to_string();
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-dynamic-test\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
        [experimental-features]\nnative-filesystem-policy = true\n\
        [agent]\ncommand = [\"/bin/true\"]\nworkspace = {}\nnative-filesystem-policy = true\n",
            quote(&root.join("state")),
            quote(&workspace)
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("policy.dw"),
        if permit {
            "permit(principal, action == Box::Action::\"fs:read\", resource);\n"
        } else {
            "forbid(principal, action, resource);\n"
        },
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_strands-box"))
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    std::fs::write(root.join("stderr.log"), stderr.as_bytes()).unwrap();
    println!(
        "dynamic_program permit={permit}, fixture={}\n{stderr}",
        root.display()
    );
    assert_eq!(output.status.success(), permit, "{output:?}");
    assert!(
        stderr.contains(if permit {
            "descriptor_issued"
        } else {
            "Forbidden"
        }),
        "{stderr}"
    );
}
#[test]
fn dynamic_program_loads_permitted_libraries() {
    dynamic_program(true);
}
#[test]
fn dynamic_program_cannot_load_a_denied_library() {
    dynamic_program(false);
}

#[test]
fn native_append_preserves_existing_content() {
    run("append", true, true, None, false);
}
#[test]
fn denied_append_preserves_existing_content() {
    run("append", false, true, None, false);
}
#[test]
fn native_open_preserves_an_unset_close_on_exec_flag() {
    run("preserve", true, true, None, false);
}
#[test]
fn native_open_accepts_no_follow_on_a_regular_file() {
    run("nofollow", true, true, None, false);
}
#[test]
fn native_open_accepts_nonblocking_on_a_regular_file() {
    run("blocking", true, true, None, false);
}
#[test]
fn native_read_returns_the_approved_files_bytes() {
    run("read", true, true, None, false);
}
#[test]
fn denied_native_read_does_not_deliver_a_descriptor() {
    run("read", false, true, None, false);
}

#[test]
fn native_read_from_urandom_requires_a_policy_permit() {
    run("urandom", true, true, None, false);
}
#[test]
fn denied_urandom_read_does_not_deliver_a_descriptor() {
    run("urandom", false, true, None, false);
}

#[test]
fn proc_self_identifies_the_requesting_workload() {
    run("virtual", true, true, None, false);
}
#[test]
fn proc_self_identifies_a_child_requester() {
    run("vchild", true, true, None, false);
}
#[test]
fn proc_self_read_requires_a_policy_permit() {
    run("virtual", false, true, None, false);
}

#[test]
fn relative_write_uses_the_requesting_workloads_directory() {
    run("local", true, true, None, false);
}
#[test]
fn relative_write_in_a_child_uses_the_childs_changed_directory() {
    run("lchild", true, true, None, false);
}
#[test]
fn denied_relative_write_preserves_content() {
    run("local", false, true, None, false);
}
#[test]
fn openat_uses_the_requesters_directory_descriptor() {
    run("fd", true, true, None, false);
}
#[test]
fn a_directory_descriptor_does_not_bypass_policy() {
    run("fd", false, true, None, false);
}
#[test]
fn absolute_open_ignores_the_directory_descriptor_argument() {
    run("ignorefd", true, true, None, false);
}
#[test]
fn kernel_largefile_flag_is_accepted() {
    run("largefile", true, true, None, false);
}
#[test]
fn directory_enumeration_requires_a_policy_permit() {
    run("enumerate", true, true, None, false);
}
#[test]
fn denied_directory_open_does_not_deliver_a_descriptor() {
    run("enumerate", false, true, None, false);
}
#[test]
fn unsupported_path_handle_refuses_without_stopping_box() {
    run("handle", true, true, None, false);
}
#[test]
fn unmediated_path_handle_preserves_the_path_only_flag() {
    run("handle", true, false, None, false);
}

#[test]
fn creation_preserves_the_requesters_umask() {
    run("cwide", true, true, None, false);
}
#[test]
fn relative_creation_preserves_a_private_umask() {
    run("clocal", true, true, None, false);
}
#[test]
fn creation_without_close_on_exec_preserves_that_flag() {
    run("cnoclose", true, true, None, false);
}
#[test]
fn create_flag_on_an_existing_file_uses_the_existing_object() {
    run("cexisting", true, true, None, false);
}
#[test]
fn denied_relative_creation_leaves_no_file() {
    run("clocal", false, true, None, false);
}
#[test]
fn relative_unlink_requires_policy() {
    run("dlocal", true, true, None, false);
}
#[test]
fn denied_relative_unlink_preserves_the_file() {
    run("dlocal", false, true, None, false);
}
#[test]
fn relative_rename_requires_policy() {
    run("mlocal", true, true, None, false);
}
#[test]
fn denied_relative_rename_preserves_the_file() {
    run("mlocal", false, true, None, false);
}

#[test]
fn a_missing_optional_file_returns_the_kernel_not_found_error() {
    run("zero", true, true, None, false);
}
#[test]
fn a_policy_permit_cannot_write_through_a_read_only_mount() {
    run("grantless", true, true, None, false);
}
#[test]
fn a_policy_permit_cannot_open_a_file_outside_workload_grants() {
    run("outside", true, true, None, false);
}

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

fn local_server_write(permit: bool) {
    use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};
    use std::time::Duration;
    let box_ = RuntimeMcpBox::new("native-mcp");
    let server = Server::new("alpha", "alpha-mcp", "read", DiscoveryBehavior::Ready);
    box_.install_server(&server);
    let program = box_.server_executable("alpha-mcp");
    let script = std::fs::read_to_string(&program).unwrap();
    let script = script.replace(
        "        fetch_target = os.environ.get(\"FIXTURE_FETCH_TARGET\")",
        r#"        try:
            (control / "native-target.txt").write_text("changed\n")
            write("native-result", "allow")
        except PermissionError:
            write("native-result", "deny")
        fetch_target = os.environ.get("FIXTURE_FETCH_TARGET")"#,
    );
    assert!(script.contains("native-target.txt"));
    std::fs::write(&program, script).unwrap();
    let target = box_
        .operator_home()
        .join(".runtime-mcp-test/native-target.txt");
    std::fs::write(&target, "original\n").unwrap();
    let mut policy = "permit(principal, action, resource);\n".to_owned();
    if !permit {
        policy.push_str(
            r#"@id("protected_native_file")
            forbid(principal, action == Box::Action::"fs:write", resource)
            when { context.input.path like "*native-target.txt" };"#,
        );
    }
    box_.write_workspace_as_authored(
        &policy,
        &[server],
        r#"
        : > "$HOME/workload.started"
        while [ ! -e "$HOME/release" ]; do :; done
    "#,
    );
    let config = box_.operator_home().join("workspace/.strands-box/box.toml");
    let mut value: toml::Value =
        toml::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    value["agent"].as_table_mut().unwrap().insert(
        "native-filesystem-policy".into(),
        toml::Value::Boolean(false),
    );
    value.as_table_mut().unwrap().insert(
        "experimental-features".into(),
        toml::Value::Table(
            [(
                "native-filesystem-policy".into(),
                toml::Value::Boolean(true),
            )]
            .into_iter()
            .collect(),
        ),
    );
    std::fs::write(&config, toml::to_string(&value).unwrap()).unwrap();
    let timeout = Duration::from_secs(15);
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), timeout);
    let mut client = box_.open_client("alpha-mcp");
    client.initialize_and_activate(serde_json::json!("native-initialize"), timeout);
    let catalog = client.list_root(serde_json::json!("native-list"), timeout);
    assert!(catalog.get("result").is_some(), "{catalog}");
    let response = client.call(serde_json::json!("native-call"), "read", timeout);
    assert!(response.get("result").is_some(), "{response}");
    assert_eq!(
        std::fs::read_to_string(box_.event("alpha-mcp", "native-result")).unwrap(),
        if permit { "allow\n" } else { "deny\n" }
    );
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        if permit { "changed\n" } else { "original\n" }
    );
    drop(client);
    box_.release_workload();
    let output = run.wait(timeout);
    assert!(output.status.success(), "{output:?}");
    let journal =
        std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl")).unwrap();
    assert!(journal.contains("native-target.txt"));
    if !permit {
        assert!(journal.contains("protected_native_file"));
    }
}

#[test]
fn local_mcp_server_native_write_reaches_the_policy_engine() {
    local_server_write(true);
}
#[test]
fn local_mcp_server_continues_after_a_denied_native_write() {
    local_server_write(false);
}

#[test]
fn regular_read_accepts_the_no_controlling_terminal_flag() {
    run("quiet", true, true, None, false);
}
#[test]
fn no_controlling_terminal_flag_does_not_bypass_policy() {
    run("quiet", false, true, None, false);
}

#[test]
fn agent_path_truncate_allow() {
    run("xtruncate", true, true, None, false);
}
#[test]
fn agent_path_truncate_deny() {
    run("xtruncate", false, true, None, false);
}
#[test]
fn tool_path_truncate_allow() {
    run("xtruncate", true, false, Some(true), false);
}
#[test]
fn tool_path_truncate_deny() {
    run("xtruncate", false, false, Some(true), false);
}
#[test]
fn disabled_native_path_truncate_keeps_the_baseline_behavior() {
    run("xtruncate", false, false, None, false);
}
