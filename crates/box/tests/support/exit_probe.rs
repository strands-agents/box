//! Test-only host binary that exits with a given code or ends by a given signal.

#[cfg(unix)]
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [mode, code] if mode == "exit" => match code.parse::<i32>() {
            Ok(code) => std::process::exit(code),
            Err(_) => usage(),
        },
        [mode, signal] if mode == "signal" => match signal.parse::<libc::c_int>() {
            Ok(signal) => {
                // SAFETY: `raise` signals this thread and takes no pointer.
                // Linux permits this path through tgkill in the workload's PID namespace.
                let result = unsafe { libc::raise(signal) };
                assert_eq!(result, 0, "the probe must deliver its own signal");
                std::thread::sleep(std::time::Duration::from_secs(10));
                eprintln!("box-exit-probe: signal {signal} did not end the process");
                std::process::exit(2);
            }
            Err(_) => usage(),
        },
        #[cfg(target_os = "linux")]
        [mode, directory] if mode == "hold-tree" => hold_tree(std::path::Path::new(directory)),
        #[cfg(target_os = "linux")]
        [mode, directory] if mode == "serve-tree" => serve_tree(std::path::Path::new(directory)),
        #[cfg(target_os = "linux")]
        [mode, directory] if mode == "call-server" => call_server(std::path::Path::new(directory)),
        #[cfg(target_os = "linux")]
        [mode, directory] if mode == "call-tool" || mode == "timeout-tool" => {
            call_tool(std::path::Path::new(directory), mode == "timeout-tool")
        }
        _ => usage(),
    }
}

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn usage() -> ! {
    eprintln!("usage: box-exit-probe <exit CODE | signal NUMBER | hold-tree DIRECTORY>");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn hold_tree(directory: &std::path::Path) -> ! {
    spawn_tree(directory);
    std::fs::write(directory.join("leader"), b"ready").expect("write readiness");
    loop {
        if let Ok(code) = std::fs::read_to_string(directory.join("release")) {
            std::process::exit(code.trim().parse().expect("release exit code"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn spawn_tree(directory: &std::path::Path) {
    // SAFETY: this test probe forks before starting any threads.
    let child = unsafe { libc::fork() };
    assert_ne!(child, -1, "fork child");
    if child == 0 {
        hold(directory, "child");
    }
    // SAFETY: this test probe remains single-threaded.
    let detached = unsafe { libc::fork() };
    assert_ne!(detached, -1, "fork detached child");
    if detached == 0 {
        // SAFETY: this child is not a process-group leader.
        assert!(unsafe { libc::setsid() } > 0, "create a separate session");
        // SAFETY: this child remains single-threaded.
        let grandchild = unsafe { libc::fork() };
        assert_ne!(grandchild, -1, "fork grandchild");
        if grandchild == 0 {
            hold(directory, "grandchild");
        }
        hold(directory, "detached");
    }
}

#[cfg(target_os = "linux")]
fn hold(directory: &std::path::Path, name: &str) -> ! {
    // SAFETY: this single-threaded test child installs a fixed signal disposition.
    unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    std::fs::write(directory.join(name), b"ready").expect("write readiness");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[cfg(target_os = "linux")]
fn serve_tree(directory: &std::path::Path) -> ! {
    use serde_json::json;
    use std::io::{BufRead, Write};
    spawn_tree(directory);
    std::fs::write(directory.join("leader"), b"ready").expect("write server readiness");
    for line in std::io::stdin().lock().lines() {
        let frame: serde_json::Value =
            serde_json::from_str(&line.expect("read request")).expect("parse request");
        let Some(id) = frame.get("id") else { continue };
        let result = match frame["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cleanup-probe", "version": "1"}
            }),
            Some("tools/list") => json!({"tools": [{
                "name": "ready", "description": "Check server readiness",
                "inputSchema": {"type": "object", "properties": {}}
            }]}),
            Some("tools/call") => json!({"content": [{"type": "text", "text": "SERVER_READY"}]}),
            other => panic!("unexpected method {other:?}"),
        };
        println!("{}", json!({"jsonrpc": "2.0", "id": id, "result": result}));
        std::io::stdout().flush().expect("flush response");
    }
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
fn call_server(directory: &std::path::Path) -> ! {
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    let alias = std::env::var("PATH")
        .expect("alias PATH")
        .split(':')
        .next()
        .map(|bin| std::path::Path::new(bin).join("box-exit-probe"))
        .unwrap();
    let mut child = Command::new(alias)
        .arg("serve-tree")
        .arg(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start server alias");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    for (id, method, params) in [
        (
            1,
            "initialize",
            json!({"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "cleanup-test", "version": "1"}}),
        ),
        (2, "tools/list", json!({})),
        (3, "tools/call", json!({"name": "ready", "arguments": {}})),
    ] {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method,
                                    "params": params})
        )
        .unwrap();
        stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert_ne!(
                stdout.read_line(&mut line).unwrap(),
                0,
                "server alias closed"
            );
            let response: serde_json::Value = serde_json::from_str(&line).unwrap();
            if response["id"] == id {
                assert!(response.get("error").is_none(), "{response}");
                if id == 3 {
                    assert_eq!(response["result"]["content"][0]["text"], "SERVER_READY");
                }
                break;
            }
        }
        if id == 1 {
            writeln!(
                stdin,
                "{}",
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
            )
            .unwrap();
            stdin.flush().unwrap();
        }
    }
    std::fs::write(directory.join("called"), b"ready").unwrap();
    while !directory.join("agent-release").exists() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    drop(stdin);
    child.wait().expect("wait for alias");
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
fn call_tool(directory: &std::path::Path, timeout: bool) -> ! {
    use std::process::Command;
    let bin = std::env::var("PATH")
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_string();
    let alias = std::path::Path::new(&bin).join("zsh");
    let mut child = Command::new(&alias)
        .arg("-lc")
        .arg(format!("box-exit-probe hold-tree {}", directory.display()))
        .spawn()
        .expect("start tool through shell alias");
    if timeout {
        let status = child.wait().expect("wait for command deadline");
        std::fs::write(
            directory.join("status"),
            status.code().unwrap_or(-1).to_string(),
        )
        .unwrap();
        let output = Command::new(&alias)
            .args(["-lc", "printf STILL_SERVING"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        std::fs::write(directory.join("after"), output.stdout).unwrap();
    }
    while !directory.join("agent-release").exists() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::process::exit(0);
}
