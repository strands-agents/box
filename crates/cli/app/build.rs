//! Embeds `Info.plist` as the `__TEXT,__info_plist` section of the macOS `box`, so the signing
//! service reads its `CFBundleIdentifier`.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let source = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("Info.plist");
    let version = std::env::var("CARGO_PKG_VERSION").expect("set by cargo");
    let body = std::fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()))
        .replace("__VERSION__", &version);
    let rendered =
        PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo")).join("Info.plist");
    std::fs::write(&rendered, body)
        .unwrap_or_else(|error| panic!("write {}: {error}", rendered.display()));
    for argument in ["-sectcreate", "__TEXT", "__info_plist"] {
        println!("cargo:rustc-link-arg-bin=box={argument}");
    }
    println!("cargo:rustc-link-arg-bin=box={}", rendered.display());
}
