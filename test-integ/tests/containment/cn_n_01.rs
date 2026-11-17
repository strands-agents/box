
use strands_det_harness::{Platform, det_case};

det_case! {
    name: cn_n_01,
    id:   "CN-N-01",
    platforms: [Macos, Linux],
    desc: "Egress: the composed gateway connects; other loopback, public, and link-local routes cannot bypass it",
    run: |b| {
        b.reset_policy();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("DET_ERROR: bind a host control listener");
        let address = listener.local_addr().unwrap();
        let _control = std::net::TcpStream::connect(address)
            .expect("DET_ERROR: the host listener accepts connections");
        let r = b.probe_py(
            &format!(r#"
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
t("connect_host_listener", lambda: connect(socket.AF_INET, ("127.0.0.1", {host_port})))
t("connect_remote", lambda: connect(socket.AF_INET, ("93.184.216.34", 80)))
t("connect_link_local", lambda: connect(socket.AF_INET, ("169.254.169.254", 80)))
"#, host_port = address.port()),
        );
        // Positive control: HTTPS_PROXY names a composed loopback port, so the box built its
        // environment.
        r.assert_contains("proxy_composed True");
        // Positive control: the composed gateway port connects, so the network half works.
        r.assert_ok("connect_gateway", "connected");
        // Only the composed gateway crosses the network boundary.
        let linux = Platform::current() == Platform::Linux;
        r.assert_errno("connect_unserved", if linux { 111 } else { 1 });
        r.assert_errno("connect_host_listener", if linux { 111 } else { 1 });
        // A direct connection to a public address is refused, so nothing bypasses the gateway.
        r.assert_errno("connect_remote", if linux { 101 } else { 1 });
        // The link-local metadata address has no direct route out of the box.
        r.assert_errno("connect_link_local", if linux { 101 } else { 1 });
    }
}
