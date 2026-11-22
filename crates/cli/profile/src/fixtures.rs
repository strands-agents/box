//! Files that tests write: programs, scripts, and links.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

/// An executable file with no `#!` line, as a compiled program is.
pub fn binary(path: &Path) {
    write(path, "\u{7f}ELF");
    for ancestor in path.ancestors().skip(1) {
        if ancestor
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "Cellar")
        {
            let receipt = ancestor.join("INSTALL_RECEIPT.json");
            if !receipt.exists() {
                write(&receipt, r#"{"runtime_dependencies":[]}"#);
            }
            break;
        }
    }
    executable(path);
}

pub fn npm_script(package: &Path) {
    write(&package.join("package.json"), r#"{"name":"npm"}"#);
    write(&package.join("bin/npm-cli.js"), "#!/usr/bin/env node\n");
    executable(&package.join("bin/npm-cli.js"));
}

pub fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    std::fs::write(path, text).expect("a file");
}

pub fn executable(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode 0755");
}

pub fn script(path: &Path, body: &str) {
    write(path, &format!("#!/bin/sh\n{body}\n"));
    executable(path);
}

/// The real file of `/bin/sh`, which each `script` runs.
pub fn shell() -> String {
    std::fs::canonicalize("/bin/sh")
        .expect("a shell")
        .display()
        .to_string()
}

pub fn link(target: &str, path: &Path) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    symlink(target, path).expect("a symlink");
}
