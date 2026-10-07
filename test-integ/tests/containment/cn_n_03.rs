use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use strands_det_harness::{Platform, det_case, user_home};

// Containment CN-N (an inbound bind)
//
// The platforms differ on an inbound TCP bind, and this case
// asserts the property they share. On Linux the permit filter allows `bind` and `listen`
// unconditionally, because seccomp sees a descriptor and not an address family, so a TCP listener
// inside the box's own network namespace succeeds and is unreachable from the host. On macOS
// Seatbelt scopes `network-bind` to the declared write roots, so an AF_INET bind is refused. Both
// platforms bind a pathname UNIX socket inside a declared write grant and nowhere else.
//
// The probe is a binary the case compiles into the workspace's `out/` tree and runs in the agent's
// own boundary through an `exec` entry on that tree (the F1 fallback), so the sockets it opens are
// the agent's. While the Linux listener is held, the host, outside the box, tries to connect.

/// The probe's source. `tcp <loopback-port> <any-port> <ready> <go>` binds and listens on
/// 127.0.0.1 and 0.0.0.0, reports each outcome, and while any listener is held touches `ready`
/// and waits for `go`; `unix <path>...` binds a pathname socket at each path and reports.
const PROBE: &str = r#"
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out = std::io::stdout();
    match args.get(1).map(String::as_str) {
        Some("tcp") if args.len() == 6 => {
            let ready = Path::new(&args[4]);
            let go = Path::new(&args[5]);
            let mut held = Vec::new();
            for addr in [format!("127.0.0.1:{}", args[2]), format!("0.0.0.0:{}", args[3])] {
                match TcpListener::bind(&addr) {
                    Ok(listener) => {
                        writeln!(out, "TCP_LISTENING {addr}").unwrap();
                        held.push(listener);
                    }
                    Err(e) => writeln!(out, "TCP_REFUSED {addr}: {e}").unwrap(),
                }
            }
            out.flush().unwrap();
            if !held.is_empty() {
                std::fs::write(ready, "ready\n").expect("touch the ready marker");
                let deadline = Instant::now() + Duration::from_secs(30);
                while !go.exists() {
                    if Instant::now() > deadline {
                        writeln!(out, "GO_TIMEOUT").unwrap();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                writeln!(out, "TCP_RELEASED").unwrap();
            }
        }
        Some("unix") => {
            for path in &args[2..] {
                match UnixListener::bind(path) {
                    Ok(_listener) => {
                        writeln!(out, "UNIX_BOUND {path}").unwrap();
                        let _ = std::fs::remove_file(path);
                    }
                    Err(e) => writeln!(out, "UNIX_REFUSED {path}: {e}").unwrap(),
                }
            }
        }
        _ => {
            eprintln!("usage: sockprobe tcp <loopback-port> <any-port> <ready> <go> | unix <path>...");
            std::process::exit(2);
        }
    }
}
"#;

/// The host's primary address: the source a connect toward a non-loopback target would use.
fn primary_interface_ip() -> IpAddr {
    let route = UdpSocket::bind("0.0.0.0:0").expect("DET_ERROR: open a UDP socket on the host");
    route
        .connect("10.255.255.255:9")
        .expect("DET_ERROR: the host routes to a non-loopback address");
    route
        .local_addr()
        .expect("DET_ERROR: read the host's primary address")
        .ip()
}

/// Whether a connect from the host to `addr` is refused or times out.
fn unreachable_from_host(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err()
}

/// Two consecutive ports nothing on the host answers, over loopback or the primary address.
fn free_port_pair(primary: IpAddr) -> (u16, u16) {
    let base = 20000 + (std::process::id() % 20000) as u16;
    (0..50u16)
        .map(|i| base + 2 * i)
        .find(|&port| {
            [port, port + 1].iter().all(|&candidate| {
                unreachable_from_host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), candidate))
                    && unreachable_from_host(SocketAddr::new(primary, candidate))
            })
        })
        .map(|port| (port, port + 1))
        .expect("DET_ERROR: find two free ports on the host")
}

det_case! {
    name: cn_n_03,
    id:   "CN-N-03",
    desc: "Inbound bind: a TCP listener inside the box is unreachable from the host (Linux) or refused (macOS); a UNIX socket binds only inside a write grant",
    run: |b| {
        b.apply_policy(
            r#"@id("workspace_spawn") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        // The probe, compiled beside the declared tool in the exec tree. Canonical, because a
        // grant names the identity the kernel checks.
        let out = b
            .built_tool()
            .parent()
            .expect("DET_ERROR: the built tool sits in the exec tree")
            .canonicalize()
            .expect("DET_ERROR: resolve the exec tree");
        let probe = out.join("sockprobe");
        std::fs::write(out.join("sockprobe.rs"), PROBE).expect("DET_ERROR: write the probe's source");
        let compiled = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-O", "-o"])
            .arg(&probe)
            .arg(out.join("sockprobe.rs"))
            .output()
            .expect("DET_ERROR: rustc is on PATH");
        assert!(
            compiled.status.success(),
            "DET_ERROR: rustc failed on the probe: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let exec_entry = serde_json::to_string(&out.to_string_lossy()).unwrap();
        let with_exec = |text: String| {
            text.replacen("read_file = [", &format!("exec = [{exec_entry}]\nread_file = ["), 1)
        };

        if Platform::current() == Platform::Linux {
            // The listener succeeds inside the box's network namespace; the host, outside it,
            // reaches neither port over loopback nor over its primary address.
            let primary = primary_interface_ip();
            let (loopback_port, any_port) = free_port_pair(primary);
            let mut reached = Vec::new();
            let r = b.run_sh_with_config_meanwhile(
                with_exec,
                &format!(
                    "zsh -c '{} tcp {loopback_port} {any_port} {} {}'",
                    probe.display(),
                    b.ready_marker().display(),
                    b.go_marker().display()
                ),
                || {
                    for port in [loopback_port, any_port] {
                        for ip in [IpAddr::V4(Ipv4Addr::LOCALHOST), primary] {
                            let addr = SocketAddr::new(ip, port);
                            if !unreachable_from_host(addr) {
                                reached.push(addr.to_string());
                            }
                        }
                    }
                },
            );
            r.assert_contains(&format!("TCP_LISTENING 127.0.0.1:{loopback_port}"));
            r.assert_contains(&format!("TCP_LISTENING 0.0.0.0:{any_port}"));
            r.assert_contains("TCP_RELEASED");
            assert!(
                reached.is_empty(),
                "the host reached a listener the box opened: {reached:?}; out=[{}]",
                r.out
            );
        } else {
            // Seatbelt refuses the AF_INET bind, so the probe holds nothing and returns at once.
            let r = b.run_sh_with_config(
                with_exec,
                &format!(
                    "zsh -c '{} tcp 8799 8800 {} {}'",
                    probe.display(),
                    b.ready_marker().display(),
                    b.go_marker().display()
                ),
            );
            r.assert_contains("TCP_REFUSED 127.0.0.1:8799");
            r.assert_contains("TCP_REFUSED 0.0.0.0:8800");
            r.assert_absent("TCP_LISTENING");
        }

        // A pathname socket binds inside the workspace, a declared write grant, and not under the
        // operator home, which no grant covers.
        let inside = b.workspace().join(".det-cnn03.sock");
        let outside = user_home()
            .canonicalize()
            .expect("DET_ERROR: resolve operator home")
            .join(format!(".det-cnn03-{}.sock", std::process::id()));
        let r = b.run_sh_with_config(
            with_exec,
            &format!("zsh -c '{} unix {} {}'", probe.display(), inside.display(), outside.display()),
        );
        let outside_exists = outside.exists();
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_file(&inside);
        r.assert_contains(&format!("UNIX_BOUND {}", inside.display()));
        r.assert_contains(&format!("UNIX_REFUSED {}", outside.display()));
        assert!(!outside_exists, "the socket outside every grant was created on the host");
    }
}
