//! Embeds an `Info.plist` as the `__TEXT,__info_plist` section of each shipped
//! macOS binary, so CD Signer reads `CFBundleIdentifier` and `CFBundleName`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-changed=src/run/macos_enforcement/bridge.c");
    // Only macOS binaries carry the section; Linux links unchanged.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    embed(&dir, &out, "strands-box", "Info.plist");
    embed(
        &dir,
        &out,
        "strands-box-sock-alias",
        "Info-sock-alias.plist",
    );
    if std::env::var_os("CARGO_FEATURE_NATIVE_FILESYSTEM_POLICY").is_some() {
        compile_bridge();
    }
}

/// Attach `template` to the `bin` binary via the darwin `-sectcreate` link args,
/// with the crate's own version substituted so a stamped release cannot ship a
/// plist that disagrees with `--version`.
fn embed(dir: &Path, out: &Path, bin: &str, template: &str) {
    let source = dir.join(template);
    println!("cargo:rerun-if-changed={}", source.display());

    let version = std::env::var("CARGO_PKG_VERSION").expect("set by cargo");
    let body = std::fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()))
        .replace("__VERSION__", &version);
    let rendered = out.join(template);
    std::fs::write(&rendered, body)
        .unwrap_or_else(|error| panic!("write {}: {error}", rendered.display()));

    println!("cargo:rustc-link-arg-bin={bin}=-sectcreate");
    println!("cargo:rustc-link-arg-bin={bin}=__TEXT");
    println!("cargo:rustc-link-arg-bin={bin}=__info_plist");
    println!("cargo:rustc-link-arg-bin={bin}={}", rendered.display());
}

fn compile_bridge() {
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
