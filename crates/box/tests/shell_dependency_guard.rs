//! Guards on the Strands Shell dependency: its one network client is a path the box never calls,
//! and every `Kernel` method is one the box's kernel serves.
//!
//! The box routes the Shell's HTTP through its egress gateway
//! (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway) and decides every
//! filesystem effect in its own kernel. Both hold only while the dependency reaches the network
//! and the filesystem through the `Kernel` the box supplies, so these tests read the dependency's
//! source as cargo resolved it.

use std::path::{Path, PathBuf};

/// The dependency's only file that may build a client: `VfsKernel::http_request`, which the box's
/// kernel replaces.
const ALLOWED_FILES: &[&str] = &["vfs_kernel.rs"];

/// Construction of a network client, never a `reqwest` type name or a DNS lookup.
const CLIENT_TOKENS: &[&str] = &[
    "Client::builder(",
    "Client::new(",
    "Client::default(",
    "ClientBuilder::new(",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "hyper::",
];

/// Each `Kernel` method the dependency declares, and whether the box's kernel serves it.
const KERNEL_METHODS: &[(&str, Served)] = &[
    ("new_process", Served::Box),
    ("open", Served::Box),
    ("list_dir", Served::Box),
    ("change_dir", Served::Box),
    ("stat", Served::Box),
    ("lstat", Served::Box),
    ("access", Served::Box),
    ("canonicalize", Served::Box),
    ("is_executable", Served::Box),
    ("glob", Served::Box),
    ("isatty", Served::Box),
    ("remove_file", Served::Box),
    ("remove_dir", Served::Box),
    ("create_dir", Served::Box),
    ("rename", Served::Box),
    ("symlink", Served::Box),
    ("read_link", Served::Box),
    ("set_permissions", Served::Box),
    ("now", Served::Box),
    ("check_url", Served::Box),
    ("resolve_credential", Served::Default),
    ("http_request", Served::Box),
    ("command_fallback", Served::Box),
    ("check_command", Served::Box),
    ("check_fallback", Served::Box),
    ("command_finished", Served::Box),
    ("command_dropped", Served::Box),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Served {
    /// The box's kernel implements it.
    Box,
    /// The dependency's default holds: no credential is injected.
    Default,
}

/// The `src` directory of the `strands-shell` package cargo resolved for this workspace.
fn shell_src() -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let manifest = metadata["packages"]
        .as_array()
        .expect("a package list")
        .iter()
        .find(|package| package["name"] == "strands-shell")
        .and_then(|package| package["manifest_path"].as_str())
        .expect("strands-shell is a dependency");
    Path::new(manifest)
        .parent()
        .expect("a manifest has a directory")
        .join("src")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a shell source directory") {
        let path = entry.expect("a shell source entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A file's source above its bottom `#[cfg(test)] mod`, which may build a client of its own.
fn non_test_source(source: &str) -> &str {
    let marker = "\n#[cfg(test)]\nmod ";
    match source.find(marker) {
        Some(cut) => &source[..cut],
        None => source,
    }
}

/// The box's Shell kernel, which must replace the dependency's network path.
fn box_kernel_source() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../box-shell/src/kernel.rs"),
    )
    .expect("read the box's Shell kernel")
}

#[test]
fn the_only_network_client_is_one_the_box_kernel_replaces() {
    let root = shell_src();
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(!files.is_empty(), "found no Shell sources to scan");

    let mut offenders = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .expect("a path under the Shell's src");
        let relative = relative.to_string_lossy();
        // The Python and Node bindings are behind features the box never enables.
        if ALLOWED_FILES.contains(&relative.as_ref())
            || relative == "python.rs"
            || relative == "js.rs"
        {
            continue;
        }
        let source = std::fs::read_to_string(file).expect("read a Shell source file");
        for token in CLIENT_TOKENS {
            if non_test_source(&source).contains(token) {
                offenders.push(format!("{relative} builds a client with `{token}`"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a network client in the Shell outside `VfsKernel::http_request` is an egress path the \
         box's kernel does not replace; found: {offenders:#?}"
    );

    let kernel = box_kernel_source();
    assert!(
        kernel.contains("async fn http_request(") && kernel.contains("fn check_url("),
        "the box's kernel must serve HTTP itself, through the gateway"
    );
}

#[test]
fn the_box_kernel_serves_every_kernel_method_the_shell_declares() {
    let os = std::fs::read_to_string(shell_src().join("os.rs")).expect("read the Shell's os.rs");
    let start = os
        .find("pub trait Kernel: Send + Sync {")
        .expect("the Shell declares `Kernel`");
    let body = &os[start..];
    let body = &body[..body.find("\n}\n").expect("the trait closes")];
    let declared: Vec<String> = body
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line
                .strip_prefix("async fn ")
                .or_else(|| line.strip_prefix("fn "))?;
            Some(rest.split(['(', '<']).next()?.to_string())
        })
        .collect();
    let pinned: Vec<String> = KERNEL_METHODS
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    assert_eq!(
        declared, pinned,
        "the Shell's `Kernel` changed; serve each new method in the box's kernel, then pin it here"
    );

    let kernel = box_kernel_source();
    let impl_start = kernel
        .find("impl Kernel for ShellKernel {")
        .expect("the box implements `Kernel`");
    let implementation = &kernel[impl_start..];
    for (name, served) in KERNEL_METHODS {
        let implemented = implementation.contains(&format!("fn {name}("));
        match served {
            Served::Box => assert!(implemented, "the box's kernel must serve `{name}`"),
            Served::Default => assert!(!implemented, "`{name}` is pinned to the Shell's default"),
        }
    }
}
