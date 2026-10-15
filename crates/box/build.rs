use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-changed=src/run/macos_enforcement/bridge.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || std::env::var_os("CARGO_FEATURE_NATIVE_FILESYSTEM_POLICY").is_none()
    {
        return;
    }
    let target = std::env::var("TARGET").expect("target");
    let deployment = Command::new(std::env::var_os("RUSTC").expect("Rust compiler"))
        .args(["--print", "deployment-target", "--target", &target])
        .output()
        .expect("read Rust deployment target");
    assert!(
        deployment.status.success(),
        "Rust deployment target query failed"
    );
    let deployment = String::from_utf8(deployment.stdout).expect("UTF-8 deployment target");
    let deployment = deployment
        .trim()
        .strip_prefix("MACOSX_DEPLOYMENT_TARGET=")
        .expect("macOS deployment target");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("build output"));
    let object = output.join("box_endpoint_security.o");
    let archive = output.join("libbox_endpoint_security.a");
    let status = Command::new("/usr/bin/xcrun")
        .args(["clang", "-target"])
        .arg(&target)
        .arg(format!("-mmacosx-version-min={deployment}"))
        .args(["-fblocks", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c"])
        .arg("src/run/macos_enforcement/bridge.c")
        .arg("-o")
        .arg(&object)
        .status()
        .expect("compile Endpoint Security bridge");
    assert!(
        status.success(),
        "Endpoint Security bridge compilation failed"
    );
    let status = Command::new("/usr/bin/xcrun")
        .args(["ar", "crs"])
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("archive Endpoint Security bridge");
    assert!(status.success(), "Endpoint Security bridge archive failed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=box_endpoint_security");
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=bsm");
}
