//! A contained process that checks file access or calls a contained tool or server.

use std::io::{BufRead as _, Write as _};
use std::process::{Command, Stdio};

use serde_json::json;

fn access(mode: &str, path: &str, sibling: &str) {
    if mode == "write-only" {
        assert!(std::fs::read(path).is_err(), "write-only must refuse reads");
    } else {
        assert_eq!(std::fs::read_to_string(path).unwrap(), "seed");
    }
    if mode == "read-only" {
        assert!(
            std::fs::write(path, "changed").is_err(),
            "read-only must refuse writes"
        );
    } else {
        std::fs::write(path, "changed").unwrap();
        if matches!(mode, "read-write" | "read-write-overlap" | "partial-read") {
            assert_eq!(std::fs::read_to_string(path).unwrap(), "changed");
        }
    }
    if mode == "read-write-overlap" {
        assert_eq!(std::fs::read_to_string(sibling).unwrap(), "sibling");
        assert!(
            std::fs::write(sibling, "changed").is_err(),
            "write must stay inside its grant"
        );
    } else if mode == "partial-read" {
        assert!(
            std::fs::read(sibling).is_err(),
            "read must stay inside its grant"
        );
        std::fs::write(sibling, "changed").unwrap();
    }
}

fn main() {
    eprintln!("FILESYSTEM_PROBE_STARTED");
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args[0].as_str() {
        "tool-client" => {
            let output = Command::new("zsh")
                .args([
                    "-c",
                    &format!("mode-tool {} {} {}", args[1], args[2], args[3]),
                ])
                .output()
                .unwrap();
            std::io::stdout().write_all(&output.stdout).unwrap();
            std::io::stderr().write_all(&output.stderr).unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("FILESYSTEM_PROBE_OK"));
        }
        "server-client" => {
            let mut child = Command::new("mode-server")
                .args(["server", &args[1], &args[2], &args[3]])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
            writeln!(
                input,
                "{}",
                json!({
                    "jsonrpc":"2.0", "id":1, "method":"initialize",
                    "params":{"protocolVersion":"2024-11-05", "capabilities":{},
                        "clientInfo":{"name":"filesystem-probe", "version":"1"}}
                })
            )
            .unwrap();
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            let response: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(response.get("result").is_some(), "{response}");
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0",
                "method":"notifications/initialized"})
            )
            .unwrap();
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0", "id":2,
                "method":"tools/list", "params":{}})
            )
            .unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            let response: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(response.get("result").is_some(), "{response}");
            drop(input);
            assert!(child.wait().unwrap().success());
            println!("FILESYSTEM_PROBE_OK");
        }
        "server" => {
            access(&args[1], &args[2], &args[3]);
            for line in std::io::stdin().lock().lines() {
                let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
                let Some(id) = request.get("id") else {
                    continue;
                };
                let result = match request["method"].as_str().unwrap() {
                    "initialize" => json!({"protocolVersion":"2024-11-05",
                        "capabilities":{"tools":{}},
                        "serverInfo":{"name":"filesystem-probe", "version":"1"}}),
                    "tools/list" => json!({"tools":[]}),
                    method => panic!("unexpected method: {method}"),
                };
                println!("{}", json!({"jsonrpc":"2.0", "id":id, "result":result}));
                std::io::stdout().flush().unwrap();
            }
        }
        mode => {
            access(mode, &args[1], &args[2]);
            println!("FILESYSTEM_PROBE_OK");
        }
    }
}
