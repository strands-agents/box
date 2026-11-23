use std::process::Command;

#[test]
fn bare_command_groups_print_help_without_a_terminal_or_box_home() {
    for columns in ["40", "100"] {
        for (group, commands) in [
            (
                "profile",
                &["create", "edit", "list", "show", "clean", "reset", "delete"][..],
            ),
            ("runs", &["list", "history"][..]),
            ("telemetry", &["on", "off", "status"][..]),
        ] {
            let home = tempfile::tempdir().unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_box"))
                .arg(group)
                .env_clear()
                .env("BOX_HOME", "relative")
                .env("COLUMNS", columns)
                .current_dir(home.path())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            let help = String::from_utf8(output.stderr).unwrap();
            assert!(
                help.contains(&format!("Usage: box {group} <COMMAND>")),
                "{help}"
            );
            for command in commands {
                assert!(
                    help.lines()
                        .any(|line| line.split_whitespace().next() == Some(command)),
                    "{group} help must list {command}: {help}"
                );
            }
            assert!(
                help.matches("Examples:").count() <= 1,
                "COLUMNS={columns}: {help}"
            );
            assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn an_empty_profile_list_names_a_command_that_creates_one() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "list"])
        .env("HOME", home.path())
        .current_dir(home.path())
        .output()
        .unwrap();
    let list = String::from_utf8(output.stdout).unwrap();
    assert!(
        list.contains("Create one from a starter: `box profile create <starter>`."),
        "{list}"
    );
}

#[test]
fn the_create_help_explains_agent_selection() {
    let output = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "create", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("`--with <agent>,bedrock`"), "{help}");
}

#[test]
fn history_help_exposes_the_runs_namespace_and_existing_flags() {
    let home = tempfile::tempdir().unwrap();
    let help = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(args)
            .env_clear()
            .env("HOME", home.path())
            .current_dir(home.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{args:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    for (args, command) in [
        (&["--help"][..], "runs"),
        (&["runs", "--help"][..], "history"),
    ] {
        let output = help(args);
        assert!(
            output
                .lines()
                .any(|line| line.split_whitespace().next() == Some(command)),
            "{args:?} must list {command}: {output}"
        );
    }
    let output = help(&["runs", "history", "--help"]);
    assert!(output.contains("box runs history"), "{output}");
    assert!(output.contains("<BOX_ID>"), "{output}");
    for flag in [
        "--deny",
        "--would-deny",
        "--format",
        "--action",
        "--resource",
        "--since",
        "--tail",
    ] {
        assert!(
            output
                .lines()
                .any(|line| line.split_whitespace().next() == Some(flag)),
            "history help must list {flag}: {output}"
        );
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn history_replaces_the_top_level_records_command_without_an_alias() {
    let home = tempfile::tempdir().unwrap();
    for args in [["records", "--help"], ["records", "probe-01234567"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(args)
            .env_clear()
            .env("HOME", home.path())
            .current_dir(home.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            stderr.contains("unrecognized subcommand 'records'"),
            "{stderr}"
        );
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
