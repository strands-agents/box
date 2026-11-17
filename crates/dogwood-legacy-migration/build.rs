//! Embeds the macOS identity used by the release signer.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let source = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("Info.plist");
    let output =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("build output")).join("Info.plist");
    let body = std::fs::read_to_string(source)
        .expect("read helper plist")
        .replace(
            "__VERSION__",
            &std::env::var("CARGO_PKG_VERSION").expect("package version"),
        );
    std::fs::write(&output, body).expect("write helper plist");
    for argument in ["-sectcreate", "__TEXT", "__info_plist"] {
        println!("cargo:rustc-link-arg={argument}");
    }
    println!("cargo:rustc-link-arg={}", output.display());
}
