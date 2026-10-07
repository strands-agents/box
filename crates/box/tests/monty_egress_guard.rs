//! Guard: the only network client in the Monty host path is the one `fetch` handler, built from
//! `EgressRouting`.
//!
//! Monty performs no I/O of its own, so the interpreter has no client to sweep — unlike the
//! vendored Shell, which can build a bare `reqwest` client anywhere and needs a broader guard.
//! The single box-owned client lives in `fetch_inner` in `python/fetch.rs`, and it must route
//! through the gateway (`EgressRouting`'s proxy) and trust only the gateway CA, never dialing an
//! origin. This pins both: no client construction anywhere else in the non-test source of any file
//! under `src/run/broker/python/`, and `fetch_inner` routes.
//!
//! The box is `[[bin]]`-private, so this reads the source text rather than naming its types —
//! the same approach as `tests/support/parser_source.rs`.

use std::path::{Path, PathBuf};

/// The file that holds the one sanctioned client.
const FETCH_FILE: &str = "fetch.rs";

/// The non-test source of each file of the Monty host module, keyed by its path in that module.
///
/// A `mod tests` block stands up a fake proxy with `std::net::TcpListener`; that is test
/// scaffolding, not the host path, so the scan of each file stops at its test module. It cuts on
/// the module declaration itself — not on any `#[cfg(test)]` attribute — so a `#[cfg(test)]`-gated
/// helper added earlier cannot move the cut up and silently drop real host code below it from the
/// scan.
fn host_path_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/run/broker/python");
    let mut pending = vec![root.clone()];
    let mut files: Vec<PathBuf> = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read a run/broker/python/ directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    assert!(
        files.contains(&root.join("mod.rs")) && files.contains(&root.join(FETCH_FILE)),
        "the Monty host module must hold mod.rs and {FETCH_FILE}: {files:?}"
    );
    let marker = "\nmod tests {";
    files
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(&root)
                .expect("a file under the module")
                .to_string_lossy()
                .into_owned();
            let source = std::fs::read_to_string(&path).expect("read a Monty host source file");
            assert!(
                source.matches(marker).count() <= 1,
                "expected at most one `mod tests {{` in {name}; the guard's cut point is ambiguous \
                 otherwise"
            );
            let host = match source.find(marker) {
                Some(cut) => source[..cut].to_string(),
                None => source,
            };
            (name, host)
        })
        .collect()
}

/// The non-test source of `fetch.rs`.
fn fetch_source() -> String {
    host_path_sources()
        .into_iter()
        .find(|(name, _)| name == FETCH_FILE)
        .map(|(_, source)| source)
        .expect("fetch.rs is part of the Monty host module")
}

/// No HTTP/TLS/TCP client is constructed in the Monty host path outside the one `fetch` handler.
///
/// The scan covers ALL non-test source of every file outside `fetch_inner` — in `fetch.rs`, the
/// text before it AND the text after — because a second client added anywhere must be caught too.
/// Excludes only `fetch_inner`'s own body (the sanctioned site), by finding the `}` at column 0
/// that closes it.
#[test]
fn the_only_network_client_is_the_fetch_handler() {
    let mut regions: Vec<(String, String)> = Vec::new();
    for (name, source) in host_path_sources() {
        if name != FETCH_FILE {
            regions.push((name, source));
            continue;
        }
        let fetch_inner_at = source
            .find("async fn fetch_inner(")
            .expect("fetch_inner is the sanctioned client site");
        // `fetch_inner` is a top-level `async fn`, so its close-brace is the first `\n}\n` after
        // its signature. Anything after that closing brace is scanned again.
        let after_signature = &source[fetch_inner_at..];
        let close_offset = after_signature
            .find("\n}\n")
            .expect("fetch_inner has a top-level closing brace")
            + "\n}\n".len();
        let fetch_inner_end = fetch_inner_at + close_offset;

        regions.push((
            format!("{name} before fetch_inner"),
            source[..fetch_inner_at].to_string(),
        ));
        regions.push((
            format!("{name} after fetch_inner"),
            source[fetch_inner_end..].to_string(),
        ));
    }

    for token in [
        "reqwest::",
        "hyper::",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "tokio::net::",
    ] {
        for (region, slice) in &regions {
            assert!(
                !slice.contains(token),
                "a network client ({token}) may only be built in fetch_inner; found \
                 it in {region} in the Monty host path — the interpreter must reach the network \
                 solely through the one curated fetch handler \
                 (docs/design/decisions.md#a-monty-script-reaches-the-network-through-one-fetch-function)"
            );
        }
    }
}

/// The one client dials the gateway (`EgressRouting`'s proxy) and trusts only its CA, never the
/// origin.
#[test]
fn the_fetch_client_routes_through_egress_routing() {
    let source = fetch_source();
    let fetch_inner_at = source
        .find("async fn fetch_inner(")
        .expect("fetch_inner is the sanctioned client site");
    let fetch_inner = &source[fetch_inner_at..];

    assert!(
        fetch_inner.contains("reqwest::Proxy::all(&routing.proxy_target)"),
        "the fetch client must proxy through EgressRouting's target \
         (docs/design/decisions.md#a-monty-script-reaches-the-network-through-one-fetch-function)"
    );
    assert!(
        fetch_inner.contains(".tls_built_in_root_certs(false)")
            && fetch_inner.contains(".add_root_certificate("),
        "the fetch client must trust only the gateway CA, not the built-in roots \
         (docs/design/decisions.md#a-monty-script-reaches-the-network-through-one-fetch-function)"
    );
}
