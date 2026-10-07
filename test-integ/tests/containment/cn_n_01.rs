
use strands_det_harness::det_case;

// Permit only three channels.
//
// The macOS profile carries `(deny network*)` and then one outbound rule per composed
// localhost port, so the gateway port connects and every other route is refused — which is
// what makes the gateway the only way out. The served port is dynamic, so the case reads it
// from the composed HTTPS_PROXY rather than hard-coding one; that doubles as a check that the
// environment was composed at all.
//
// No IPv6 arm: `(allow network-outbound (remote tcp "localhost:<port>"))` covers ::1 too, so
// an IPv6 attempt returns ECONNREFUSED from the host rather than EPERM from the profile,
// which is not evidence about containment.
//
// macOS-only: there is no Linux counterpart in the shared tree.
//
// No `[egress.*]` fixture: Core composes HTTP_PROXY/HTTPS_PROXY for every run from the gateway
// port it always serves (`boundary.rs::environment::compose`), so a probe of the gateway port needs
// no credential entry. The earlier `[egress.deterministic] destinations = […]` fixture is refused at
// load by the current contract ("an entry with no secret declares only a destination"), and this
// case sends no request, so no credential-shaped fixture is required.
det_case! {
    name: cn_n_01,
    id:   "CN-N-01",
    platforms: [Macos],
    desc: "Egress: only the composed gateway port connects; every other route is refused with errno 1",
    run: |b| {
        b.reset_policy();
        let r = b.probe_py(
            r#"
import socket
proxy = os.environ.get("HTTPS_PROXY", "")
print("proxy_composed", proxy.startswith("http://127.0.0.1:"))
port = int(proxy.rsplit(":", 1)[1]) if ":" in proxy else 0
def connect(family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(addr)
        return "connected"
    finally:
        s.close()
t("connect_gateway", lambda: connect(socket.AF_INET, ("127.0.0.1", port)))
t("connect_unserved", lambda: connect(socket.AF_INET, ("127.0.0.1", 43124)))
t("connect_remote", lambda: connect(socket.AF_INET, ("93.184.216.34", 80)))
t("connect_link_local", lambda: connect(socket.AF_INET, ("169.254.169.254", 80)))
"#,
        );
        // Positive control: HTTPS_PROXY names a composed loopback port, so the box built its
        // environment.
        r.assert_contains("proxy_composed True");
        // Positive control: the composed gateway port connects, so the network half works.
        r.assert_ok("connect_gateway", "connected");
        // An unserved loopback port is refused with errno 1.
        r.assert_errno("connect_unserved", 1);
        // A direct connection to a public address is refused, so nothing bypasses the gateway.
        r.assert_errno("connect_remote", 1);
        // The link-local metadata address has no direct route out of the box.
        r.assert_errno("connect_link_local", 1);
    }
}
