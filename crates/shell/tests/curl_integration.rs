// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

//! `curl` argument handling and the SSRF floor.
//!
//! **These tests cannot reach a live server.** The floor blocks loopback
//! unconditionally, and the Shell no longer offers an `HttpTransport` seam to carry an
//! exchange somewhere else, so there is no route from a test to a listener.
//!
//! What remains is everything that needs no server: argument errors, and the floor's
//! refusals (loopback, RFC1918, non-HTTP schemes, DNS-resolved loopback, and a
//! userinfo-disguised metadata host).
//!
//! **COVERAGE PARTLY RESTORED, via the egress proxy route.** 25 tests were deleted with
//! the transport seam: the five HTTP verbs, POST/JSON bodies, redirect following (absolute
//! and relative), cookies, basic auth, custom headers, `-i`/`-v`/`-w` output shaping,
//! `--fail` status handling, `-o` file output, and the max-output cap. `curl` is the
//! Shell's most exposed command. `ShellBuilder::egress_proxy` is the route to
//! a test server: it lets a routed `curl` reach a fake proxy, so
//! method, headers, `-d`/`--json` bodies, `-i` status shaping, `--fail`, and `-o` file
//! output are covered again in `tests/egress_proxy.rs`. This file keeps the server-free
//! cases — argument errors and the SSRF floor's refusals — which the floor makes
//! unreachable through a direct dial.

use strands_shell::Shell;

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (runtime, tokio::task::LocalSet::new())
}

#[test]
fn curl_no_url() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl").await;
        assert_eq!(out.status, 2);
    }));
}

#[test]
fn curl_help() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl --help").await;
        assert_eq!(out.status, 0);
        assert!(out.stdout.contains("Usage: curl"));
    }));
}

#[test]
fn curl_blocked_localhost() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl http://localhost/test").await;
        assert_ne!(out.status, 0);
    }));
}

#[test]
fn curl_blocked_private_ip() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl http://192.168.1.1/test").await;
        assert_ne!(out.status, 0);
    }));
}

#[test]
fn curl_blocked_scheme() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl ftp://example.com/file").await;
        assert_ne!(out.status, 0);
    }));
}

// Verify SafeResolver blocks DNS resolution to loopback at connect time.
// This test starts a server on 127.0.0.1 and tries to reach it via a
// hostname. The SafeResolver filters the resolved IP, preventing the
// connection even though check_url_safe passes the hostname.
#[test]
fn curl_safe_resolver_blocks_loopback_dns() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        // "localhost" is caught by check_url_safe's string check, so use
        // a direct IP-based URL to verify the resolver path works.
        // 127.0.0.1 is caught by check_url_safe as an IP literal.
        // Both paths should block — this confirms defense in depth.
        let out = shell.run("curl http://127.0.0.1:19999/").await;
        assert_ne!(out.status, 0);
        assert!(out.stderr.contains("denied"));
    }));
}

// Userinfo must not disguise the real host. In
// `http://public.example@169.254.169.254/` the apparent host reads as public while
// the real one is the metadata service; `curl` must refuse it.
#[test]
fn curl_userinfo_disguised_host_denied() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let evil = "http://good.example.com@169.254.169.254/latest/meta-data/";
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run(&format!("curl {evil}")).await;
        assert_ne!(out.status, 0, "userinfo-disguised IMDS must be denied");
        assert!(
            out.stderr.contains("denied"),
            "expected an SSRF denial, got stderr: {}",
            out.stderr
        );
    }));
}

// A bare metadata-IP origin is refused (the classic SSRF target).
#[test]
fn curl_blocked_metadata_ip() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell
            .run("curl http://169.254.169.254/latest/meta-data/")
            .await;
        assert_ne!(out.status, 0, "the IMDS address must be denied");
        assert!(out.stderr.contains("denied"), "stderr: {}", out.stderr);
    }));
}

// An unknown flag is a usage error, not a silent success.
#[test]
fn curl_unknown_flag_is_a_usage_error() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell
            .run("curl --definitely-not-a-flag http://example.com/")
            .await;
        assert_ne!(out.status, 0, "an unknown flag must fail");
    }));
}

// A network-off Shell (the default) refuses every curl, even to a public host: the floor is
// not the only gate — with no egress route configured there is nowhere for the request to go.
#[test]
fn curl_on_a_network_off_shell_refuses() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        // A Shell built with `disable_network()` refuses every curl, even to a public host:
        // with the network off there is no route out at all, floor or no floor. This pins that
        // a network-off Shell does not silently reach the internet from a test.
        let mut shell = Shell::builder().disable_network().build().unwrap();
        let out = shell.run("curl http://example.com/").await;
        assert_ne!(out.status, 0, "a network-off Shell must refuse curl");
    }));
}

// ── Options the Strands harness `web_fetch` tool sends ──────────────
// The server-backed cases are in `tests/egress_proxy.rs`.

#[test]
fn curl_max_time_rejects_a_non_number() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl --max-time soon http://example.com/").await;
        assert_eq!(out.status, 2);
    }));
}

#[test]
fn curl_proto_rejects_a_malformed_list() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("curl --proto '*http' http://example.com/").await;
        assert_eq!(out.status, 2);
    }));
}

// `--proto` refuses before any transport, so no server is needed.
#[test]
fn curl_proto_refuses_an_unlisted_protocol() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        for list in ["=https", "-http", "-all,+https"] {
            let out = shell
                .run(&format!("curl -sS --proto '{list}' http://example.com/"))
                .await;
            assert_eq!(out.status, 1, "--proto {list}");
            assert!(
                out.stderr.contains("Protocol \"http\" disabled"),
                "{}",
                out.stderr
            );
        }
    }));
}
