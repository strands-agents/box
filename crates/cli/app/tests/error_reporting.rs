#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn argument_and_command_errors_share_the_command_usage_and_help() {
    for (args, status, usage) in [
        (vec!["profile", "create"], 1, "box profile create"),
        (vec!["profile", "show"], 2, "box profile show"),
        (vec!["profile", "edit"], 2, "box profile edit"),
        (vec!["profile", "edit", "missing"], 1, "box profile edit"),
        (vec!["profile", "show", "missing"], 1, "box profile show"),
        (vec!["profile", "list"], 1, "box profile list"),
        (
            vec!["profile", "delete", "--all", "--no-ask"],
            1,
            "box profile delete",
        ),
        (vec!["run"], 1, "box run"),
        (vec!["run", "missing"], 1, "box run"),
        (vec!["profile", "show", "--ful"], 2, "box profile show"),
    ] {
        let home = tempfile::tempdir().unwrap();
        if args.contains(&"list") || args.contains(&"delete") {
            std::fs::create_dir_all(home.path().join(".strands/box")).unwrap();
            std::fs::write(home.path().join(".strands/box/profiles"), "not a directory").unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(&args)
            .env_clear()
            .env("HOME", home.path())
            .env("TERM", "dumb")
            .current_dir(home.path())
            .output()
            .unwrap();
        let message = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(status), "{args:?}: {message}");
        assert!(message.starts_with("box: error: "), "{args:?}: {message}");
        assert!(
            message.contains(&format!("\n\nUsage: {usage}")),
            "{args:?}: {message}"
        );
        assert!(
            message.ends_with("\n\nFor more information, try '--help'.\n"),
            "{args:?}: {message}"
        );
        assert!(!message.contains('\x1b'), "{args:?}: {message}");
        if args.contains(&"--ful") {
            assert!(message.contains("--full"), "{message}");
        }
        assert!(!home.path().join(".strands/box/profiles").is_dir());
    }
}

#[test]
fn reporting_failure_keeps_the_exit_status_when_stderr_is_not_writable() {
    let home = tempfile::tempdir().unwrap();
    for writable in [true, false] {
        let stderr = if writable {
            Stdio::piped()
        } else {
            let (reader, writer) = nix::unistd::pipe().unwrap();
            drop(reader);
            writer.into()
        };
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(["profile", "show", "missing"])
            .env_clear()
            .env("HOME", home.path())
            .current_dir(home.path())
            .stdout(Stdio::null())
            .stderr(stderr)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "writable stderr: {writable}");
        if writable {
            let message = String::from_utf8(output.stderr).unwrap();
            assert!(message.contains("missing"));
        }
    }
}
