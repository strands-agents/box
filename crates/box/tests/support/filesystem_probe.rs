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

#[cfg(target_os = "linux")]
fn rename_path(
    mode: &str,
    source: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let relative = mode == "renameat-relative";
    let source_parent = relative.then(|| std::fs::File::open(source.parent().unwrap()).unwrap());
    let target_parent = relative.then(|| std::fs::File::open(target.parent().unwrap()).unwrap());
    let source_name = CString::new(if relative {
        source.file_name().unwrap().as_bytes()
    } else {
        source.as_os_str().as_bytes()
    })
    .unwrap();
    let target_name = CString::new(if relative {
        target.file_name().unwrap().as_bytes()
    } else {
        target.as_os_str().as_bytes()
    })
    .unwrap();
    let source_fd = source_parent
        .as_ref()
        .map_or(libc::AT_FDCWD, |file| file.as_raw_fd());
    let target_fd = target_parent
        .as_ref()
        .map_or(libc::AT_FDCWD, |file| file.as_raw_fd());
    // SAFETY: both names and optional directory descriptors remain valid for this call.
    let result = unsafe {
        match mode {
            "renameat" | "renameat-relative" => libc::renameat(
                source_fd,
                source_name.as_ptr(),
                target_fd,
                target_name.as_ptr(),
            ) as libc::c_long,
            "renameat2" | "renameat2-noreplace" | "renameat2-exchange" => libc::syscall(
                libc::SYS_renameat2,
                source_fd,
                source_name.as_ptr(),
                target_fd,
                target_name.as_ptr(),
                match mode {
                    "renameat2-noreplace" => libc::RENAME_NOREPLACE,
                    "renameat2-exchange" => libc::RENAME_EXCHANGE,
                    _ => 0,
                },
            ),
            _ => panic!("unknown rename variant: {mode}"),
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn permitted_operations(parent: &std::path::Path, name: &str) {
    let directory = parent.join(name);
    let moved_directory = parent.join(format!("{name}-moved"));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("value");
    let moved_file = directory.join("renamed");
    std::fs::write(&file, b"seed").unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"seed");
    std::fs::write(&file, b"allowed").unwrap();
    rename_path("renameat", &file, &moved_file).unwrap();
    rename_path("renameat-relative", &moved_file, &file).unwrap();
    rename_path("renameat", &directory, &moved_directory).unwrap();
    rename_path("renameat-relative", &moved_directory, &directory).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"allowed");
}

#[cfg(target_os = "linux")]
fn denial_ancestor(args: &[String]) {
    use std::path::Path;

    let mode = &args[1];
    let directory = args[2] == "directory";
    let work = Path::new(&args[3]);
    let source = Path::new(&args[4]);
    let destination = Path::new(&args[5]);
    let denied = Path::new(&args[6]);
    let original = if directory {
        denied.join("original")
    } else {
        denied.to_path_buf()
    };
    let attempted = if directory {
        denied.join("written")
    } else {
        denied.to_path_buf()
    };
    let relocated_original = destination.join(original.strip_prefix(source).unwrap());
    let reads_original =
        |path: &Path| std::fs::read(path).is_ok_and(|bytes| bytes == b"protected bytes");
    let original_read_before = reads_original(&original);
    let mut cross_parent = Vec::new();
    for (depth, parent) in ["one", "one/two", "one/two/three"].iter().enumerate() {
        for is_directory in [false, true] {
            for outward in [false, true] {
                let name = format!("unrelated-{depth}-{is_directory}-{outward}");
                let inner = work.join(parent).join(&name);
                let outer = work.join(&name);
                let (from, to) = if outward {
                    (inner, outer)
                } else {
                    (outer, inner)
                };
                if is_directory {
                    std::fs::create_dir(&from).unwrap();
                    std::fs::write(from.join("value"), b"allowed").unwrap();
                } else {
                    std::fs::write(&from, b"allowed").unwrap();
                }
                let variant = if outward {
                    "renameat"
                } else {
                    "renameat-relative"
                };
                let result = rename_path(variant, &from, &to);
                let content = if is_directory {
                    to.join("value")
                } else {
                    to.clone()
                };
                cross_parent.push(json!({
                    "directory": is_directory,
                    "source": from.strip_prefix(work).unwrap(),
                    "destination": to.strip_prefix(work).unwrap(),
                    "renamed": result.is_ok(),
                    "content_intact": std::fs::read(&content).is_ok_and(|bytes| bytes == b"allowed"),
                    "errno": result.as_ref().err().and_then(std::io::Error::raw_os_error),
                }));
            }
        }
    }
    for parent in [
        work.to_path_buf(),
        work.join("one"),
        work.join("one/two"),
        work.join("one/two/three"),
    ] {
        permitted_operations(&parent, "allowed-before");
    }
    let renamed = rename_path(mode, source, destination);
    let rename_errno = renamed
        .as_ref()
        .err()
        .and_then(std::io::Error::raw_os_error);
    let relocated_read_after = reads_original(&relocated_original);
    let recreated = std::fs::create_dir_all(attempted.parent().unwrap());
    let wrote_original_name = std::fs::write(&attempted, b"workload bytes").is_ok();
    let original_read_after = reads_original(&original);
    permitted_operations(work, "allowed-after");
    println!(
        "DENIAL_ANCESTOR_RESULT={}",
        json!({
            "renamed": renamed.is_ok(),
            "rename_errno": rename_errno,
            "recreated": recreated.is_ok(),
            "wrote_original_name": wrote_original_name,
            "original_read_before": original_read_before,
            "original_read_after": original_read_after,
            "relocated_read_after": relocated_read_after,
            "permitted_controls": true,
            "unrelated_cross_parent": cross_parent,
        })
    );
}

fn main() {
    eprintln!("FILESYSTEM_PROBE_STARTED");
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args[0].as_str() {
        #[cfg(target_os = "linux")]
        "denial-ancestor" => denial_ancestor(&args),
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
