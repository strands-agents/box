#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::process::Command;

#[test]
fn box_run_from_the_home_names_the_home_first_and_creates_no_profile() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().canonicalize().unwrap().join("home");
    std::fs::create_dir_all(&home).unwrap();
    for arguments in [&["run"][..], &["run", "claude"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(arguments)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&home)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}: {stderr}");
        assert!(
            stderr.contains("is your home folder"),
            "{arguments:?}: {stderr}"
        );
        assert!(!stderr.contains("Creating one"), "{arguments:?}: {stderr}");
    }
    assert!(!home.join(".strands/box/profiles/claude").exists());
}
