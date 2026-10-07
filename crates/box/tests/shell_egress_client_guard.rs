//! Guard: the Shell builds a network client only at its egress chokepoint.
//! The Shell's one outbound path is `VfsKernel::http_request_effect`, routed through the
//! box's egress gateway; a network client built anywhere else in `shell/src` would be an ungoverned
//! path around the gateway. This scans the vendored Shell's source and fails the build if a client
//! is *constructed* outside the two sanctioned files — a `reqwest` HTTP client, a raw TCP/UDP
//! socket, or a `hyper` client — matched on construction, not the `reqwest::` token, which
//! `shell/src` uses widely for `Method`/`Version`/`Certificate`/`Proxy`.
//!
//! It lives in `box/tests/` and reads `../shell/src` so the vendored crate is untouched — the same
//! source-scan approach as `monty_egress_guard.rs`, and with the same client-token sweep.

use std::path::{Path, PathBuf};

/// The only files allowed to construct a client, as paths relative to `shell/src`: the routed
/// client (`http_request_effect`) and the config-time CA setup (`ShellBuilder::egress_proxy`). A
/// same-named file in a subdirectory is not allowed — the match is on the relative path.
const ALLOWED_FILES: &[&str] = &["vfs_kernel.rs", "shell.rs"];

/// Construction of a network client — a `reqwest` HTTP client (qualified `reqwest::Client::…` or
/// via `use reqwest::Client`), a raw TCP/UDP socket (`std::net`/`tokio::net`), or a `hyper` client.
/// Never `reqwest::Method`/`Version`/`Certificate`/`Proxy`, and never `tokio::net::lookup_host`,
/// which is DNS and not a client — `shell/src` references all of those legitimately.
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

fn shell_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../shell/src")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a shell/src directory") {
        let path = entry.expect("a shell/src dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A file's non-test source: a bottom `#[cfg(test)]` module is scaffolding that may build a client
/// of its own, so the scan stops there. It cuts on the `#[cfg(test)]` attribute paired with the
/// `mod` declaration it gates — not on the bare attribute — so a `#[cfg(test)]`-gated function
/// helper added earlier cannot move the cut up and silently drop real host code below it. A file
/// with two such test modules would make the cut ambiguous, so the scan refuses it.
fn non_test_source<'a>(file: &Path, source: &'a str) -> &'a str {
    let marker = "\n#[cfg(test)]\nmod ";
    assert!(
        source.matches(marker).count() <= 1,
        "{} has more than one `#[cfg(test)] mod`; the guard's cut point is ambiguous",
        file.display()
    );
    match source.find(marker) {
        Some(cut) => &source[..cut],
        None => source,
    }
}

/// No network client is constructed in `shell/src` outside the two sanctioned files.
#[test]
fn the_only_network_client_is_the_egress_chokepoint() {
    let root = shell_src();
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(!files.is_empty(), "found no shell/src sources to scan");

    let mut offenders = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root).expect("a path under shell/src");
        if ALLOWED_FILES.contains(&relative.to_string_lossy().as_ref()) {
            continue;
        }
        let source = std::fs::read_to_string(file).expect("read a shell source file");
        let source = non_test_source(file, &source);
        for token in CLIENT_TOKENS {
            if source.contains(token) {
                offenders.push(format!("{} builds a client with `{token}`", file.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a network client may only be built at the Shell's egress chokepoint \
         (vfs_kernel.rs::http_request_effect) or the config-time CA setup (shell.rs::egress_proxy) \
         (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway). \
         A client built elsewhere is an ungoverned egress path around the gateway; \
         found: {offenders:#?}"
    );
}

/// The two sanctioned sites still build a client that routes through the gateway — so the allowlist
/// cannot silently point at files that no longer route.
#[test]
fn the_chokepoint_builds_the_routed_client() {
    let root = shell_src();
    let vfs = std::fs::read_to_string(root.join("vfs_kernel.rs")).expect("read vfs_kernel.rs");
    assert!(
        vfs.contains("reqwest::Client::builder("),
        "the routed client must be built in http_request_effect \
         (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway)"
    );
    assert!(
        vfs.contains("Proxy::all("),
        "the routed client must proxy through the egress gateway \
         (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway)"
    );

    let shell = std::fs::read_to_string(root.join("shell.rs")).expect("read shell.rs");
    assert!(
        shell.contains("reqwest::Client::builder("),
        "the config-time CA setup must build its client in egress_proxy \
         (docs/design/decisions.md#shell-network-goes-through-the-egress-gateway)"
    );
}
