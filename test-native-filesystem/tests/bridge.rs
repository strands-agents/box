#![cfg(target_os = "macos")]

#[test]
fn bridge_denials_shutdown_errors_and_signed_device_ids() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("bridge-checks");
    let compiled = std::process::Command::new("/usr/bin/xcrun")
        .args(["clang", "-fblocks", "-Wall", "-Wextra", "-Werror"])
        .arg(root.join("support/bridge_checks.c"))
        .args(["-lEndpointSecurity", "-lbsm", "-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    let result = std::process::Command::new(executable).output().unwrap();
    if result.status.code() == Some(77) {
        assert!(
            std::env::var_os("STRANDS_BOX_SIGNED_TEST_BINARY").is_none(),
            "signed validation requires the macOS 27 SDK"
        );
        eprintln!("{}", String::from_utf8_lossy(&result.stdout));
        return;
    }
    assert!(result.status.success(), "{result:?}");
    println!("{}", String::from_utf8_lossy(&result.stdout));
}
