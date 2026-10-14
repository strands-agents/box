//! Embeds an `Info.plist` as the `__TEXT,__info_plist` section of the
//! `strands-box-contain-trampoline` binary, so CD Signer reads
//! `CFBundleIdentifier` and `CFBundleName`.

use std::path::PathBuf;

fn main() {
    // Only the macOS binary carries the section; Linux links unchanged.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let source = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"))
        .join("Info.plist");
    println!("cargo:rerun-if-changed={}", source.display());

    // The crate's own version is substituted so a stamped release cannot ship a
    // plist that disagrees with `--version`.
    let version = std::env::var("CARGO_PKG_VERSION").expect("set by cargo");
    let body = std::fs::read_to_string(&source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()))
        .replace("__VERSION__", &version);
    let rendered =
        PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo")).join("Info.plist");
    std::fs::write(&rendered, body)
        .unwrap_or_else(|error| panic!("write {}: {error}", rendered.display()));

    let bin = "strands-box-contain-trampoline";
    println!("cargo:rustc-link-arg-bin={bin}=-sectcreate");
    println!("cargo:rustc-link-arg-bin={bin}=__TEXT");
    println!("cargo:rustc-link-arg-bin={bin}=__info_plist");
    println!("cargo:rustc-link-arg-bin={bin}={}", rendered.display());
}
