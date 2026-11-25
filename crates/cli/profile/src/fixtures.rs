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

/// The `package.json` of the `@openai/codex` 0.171.0 launcher package, as npm publishes it.
pub const CODEX_LAUNCHER_PACKAGE: &str = r#"{
  "name": "@openai/codex",
  "version": "0.171.0",
  "description": "Codex CLI is a coding agent from OpenAI that runs locally on your computer.",
  "license": "Apache-2.0",
  "bin": {
    "codex": "bin/codex.js"
  },
  "type": "module",
  "engines": {
    "node": ">=16"
  },
  "files": [
    "bin/codex.js"
  ],
  "optionalDependencies": {
    "@openai/codex-linux-x64": "npm:@openai/codex@0.171.0-linux-x64",
    "@openai/codex-linux-arm64": "npm:@openai/codex@0.171.0-linux-arm64",
    "@openai/codex-darwin-x64": "npm:@openai/codex@0.171.0-darwin-x64",
    "@openai/codex-darwin-arm64": "npm:@openai/codex@0.171.0-darwin-arm64",
    "@openai/codex-win32-x64": "npm:@openai/codex@0.171.0-win32-x64",
    "@openai/codex-win32-arm64": "npm:@openai/codex@0.171.0-win32-arm64"
  }
}"#;

/// The Rust target of a Codex 0.171.0 platform package, such as `darwin-arm64`.
pub fn codex_target(platform: &str) -> &'static str {
    match platform {
        "darwin-arm64" => "aarch64-apple-darwin",
        "darwin-x64" => "x86_64-apple-darwin",
        "linux-arm64" => "aarch64-unknown-linux-musl",
        "linux-x64" => "x86_64-unknown-linux-musl",
        other => panic!("no Codex target for {other}"),
    }
}

/// A Codex 0.171.0 platform package for `platform` in `folder`, as npm installs it, and its
/// program.
pub fn codex_platform_package(folder: &Path, platform: &str) -> std::path::PathBuf {
    let (os, cpu) = platform.split_once('-').expect("an os and a cpu");
    let target = codex_target(platform);
    write(
        &folder.join("package.json"),
        &format!(
            r#"{{
  "name": "@openai/codex",
  "version": "0.171.0-{platform}",
  "license": "Apache-2.0",
  "os": ["{os}"],
  "cpu": ["{cpu}"],
  "files": ["vendor"],
  "engines": {{ "node": ">=16" }}
}}"#
        ),
    );
    let vendor = folder.join("vendor").join(target);
    write(
        &vendor.join("codex-package.json"),
        &format!(
            r#"{{
  "layoutVersion": 1,
  "version": "0.171.0",
  "target": "{target}",
  "variant": "codex",
  "entrypoint": "bin/codex",
  "resourcesDir": "codex-resources",
  "pathDir": "codex-path"
}}"#
        ),
    );
    binary(&vendor.join("bin/codex"));
    binary(&vendor.join("bin/codex-code-mode-host"));
    binary(&vendor.join("codex-path/rg"));
    vendor.join("bin/codex")
}

/// `npm i -g @openai/codex` under `prefix`, with the platform package of each of `platforms`
/// nested in the launcher package, and the program of each.
pub fn npm_codex(prefix: &Path, platforms: &[&str]) -> Vec<std::path::PathBuf> {
    let package = prefix.join("lib/node_modules/@openai/codex");
    write(&package.join("package.json"), CODEX_LAUNCHER_PACKAGE);
    write(
        &package.join("bin/codex.js"),
        "#!/usr/bin/env node\n// Unified entry point for the Codex CLI.\n",
    );
    executable(&package.join("bin/codex.js"));
    link(
        "../lib/node_modules/@openai/codex/bin/codex.js",
        &prefix.join("bin/codex"),
    );
    platforms
        .iter()
        .map(|platform| {
            codex_platform_package(
                &package.join(format!("node_modules/@openai/codex-{platform}")),
                platform,
            )
        })
        .collect()
}
