//! Embeds an `Info.plist` as the `__TEXT,__info_plist` section of each shipped
//! macOS binary, so CD Signer reads `CFBundleIdentifier` and `CFBundleName`.

use std::path::{Path, PathBuf};

fn main() {
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
