//! Process checks for an MCP alias selecting ordinary execution.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct Alias {
    home: tempfile::TempDir,
    path: PathBuf,
}

impl Alias {
    fn new(program: &str) -> Self {
        let home = tempfile::Builder::new()
            .prefix("mcp")
            .tempdir_in("/var/tmp")
            .unwrap();
        for directory in ["bin", "run", "ordinary", "links"] {
            std::fs::create_dir(home.path().join(directory)).unwrap();
        }
        symlink(home.path().join("bin"), home.path().join("bin-link")).unwrap();
        let path = home.path().join("bin").join(program);
        std::fs::copy(env!("CARGO_BIN_EXE_strands-box-sock-alias"), &path).unwrap();
        Self { home, path }
    }

    fn program(&self, text: &str) {
        let path = self
            .home
            .path()
            .join("ordinary")
            .join(self.path.file_name().unwrap());
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn invoke(
        &self,
        arguments: &[&str],
        input: &[u8],
        reply: impl FnOnce(Value) -> Vec<Value> + Send + 'static,
    ) -> Output {
        self.serve(arguments, input, move |stream, open| {
            for response in reply(open) {
                write(stream, &response);
            }
        })
    }

    fn serve(
        &self,
        arguments: &[&str],
        input: &[u8],
        respond: impl FnOnce(&mut UnixStream, Value) + Send + 'static,
    ) -> Output {
        let listener = UnixListener::bind(self.home.path().join("run/box.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let broker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "alias did not connect");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let open = read(&mut stream);
            respond(&mut stream, open);
        });
        let mut command = Command::new(&self.path);
        command
            .args(arguments)
            .env_clear()
            .env(
                "PATH",
                std::env::join_paths([
                    self.home.path().join("bin"),
                    self.home.path().join("bin/."),
                    self.home.path().join("bin-link"),
                    self.home.path().join("links"),
                    PathBuf::from("ordinary"),
                ])
                .unwrap(),
            )
            .env("FALLBACK_VALUE", "agent value")
            .current_dir(self.home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: setrlimit accesses only the local limit value.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(libc::STDERR_FILENO, 200) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!("alias timed out: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(broker.join().is_ok(), "broker failed: {output:?}");
        std::fs::remove_file(self.home.path().join("run/box.sock")).unwrap();
        output
    }
}

fn read(stream: &mut UnixStream) -> Value {
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn write(stream: &mut UnixStream, frame: &Value) {
    let bytes = serde_json::to_vec(frame).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}

fn unmatched(open: Value) -> Vec<Value> {
    vec![
        json!({"version": open["version"], "program": open["program"], "frame_type": "mcp_unmatched"}),
    ]
}

#[test]
fn unmatched_aliases_preserve_process_inputs_and_skip_their_own_image() {
    for name in ["npx", "uvx", "node"] {
        let alias = Alias::new(name);
        alias.program("#!/bin/sh\nIFS= read -r line\nprintf '%s\\n' \"$line\" \"$1\" \"$2\" \"$FALLBACK_VALUE\" \"$PWD\"\nprintf 'ordinary stderr\\n' >&2\nexit 23\n");
        let link = alias.home.path().join("links").join(name);
        if name == "npx" {
            std::fs::hard_link(&alias.path, link).unwrap();
        } else {
            symlink(&alias.path, link).unwrap();
        }
        let output = alias.invoke(&["two words", ""], b"preserved input\n", unmatched);
        assert_eq!(output.status.code(), Some(23), "{output:?}");
        let lines = String::from_utf8(output.stdout).unwrap();
        let expected = format!(
            "preserved input\ntwo words\n\nagent value\n{}\n",
            alias.home.path().canonicalize().unwrap().display()
        );
        assert_eq!(lines, expected);
        assert_eq!(output.stderr, b"ordinary stderr\n");
    }
}

#[test]
fn fallback_reports_missing_and_nonexecutable_programs() {
    let alias = Alias::new("npx");
    assert_eq!(alias.invoke(&[], b"", unmatched).status.code(), Some(127));
    alias.program("not an executable image\n");
    assert_eq!(alias.invoke(&[], b"", unmatched).status.code(), Some(126));
    std::fs::set_permissions(
        alias.home.path().join("ordinary/npx"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(alias.invoke(&[], b"", unmatched).status.code(), Some(126));
}

#[test]
fn fallback_retains_signal_termination() {
    let alias = Alias::new("npx");
    alias.program("#!/bin/sh\nkill -TERM $$\n");
    assert_eq!(
        alias.invoke(&[], b"", unmatched).status.signal(),
        Some(libc::SIGTERM)
    );
}

#[test]
#[cfg(feature = "test-support")]
fn fallback_closes_inherited_and_broker_descriptors() {
    let alias = Alias::new("npx");
    std::fs::copy(
        env!("CARGO_BIN_EXE_box-inherited-handles-probe"),
        alias.home.path().join("ordinary/npx"),
    )
    .unwrap();
    let output = alias.invoke(&["reexec"], b"", unmatched);
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("only standard streams survived")
    );
}

#[test]
fn the_alias_waits_for_readiness_before_sending_input() {
    let alias = Alias::new("npx");
    let output = alias.serve(&["server"], b"client-input\n", |stream, open| {
        stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut probe = [0];
        let error = stream.read(&mut probe).expect_err("no input precedes readiness");
        assert!(matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write(stream, &json!({"version":open["version"],"program":1,"frame_type":"mcp_ready"}));
        let mut input = String::new();
        loop {
            let frame = read(stream);
            match frame["frame_type"].as_str().unwrap() {
                "input" => {
                    use base64::Engine as _;
                    input.push_str(&String::from_utf8(base64::engine::general_purpose::STANDARD.decode(frame["body"]["data"].as_str().unwrap()).unwrap()).unwrap());
                }
                "input_eof" => break,
                other => panic!("unexpected {other}"),
            }
        }
        assert_eq!(input, "client-input\n");
        write(stream, &json!({"version":open["version"],"program":1,"frame_type":"exit","body":{"status":23}}));
    });
    assert_eq!(output.status.code(), Some(23), "{output:?}");
}

#[test]
fn only_a_valid_nonmatch_response_can_execute_fallback() {
    for reply in [
        "denied",
        "wrong-version",
        "wrong-program",
        "early-exit",
        "closed",
        "input",
    ] {
        let alias = Alias::new("npx");
        alias.program("#!/bin/sh\nprintf 'FALLBACK RAN'\n");
        let output = alias.invoke(&[], b"", move |open| {
            let mut frame = unmatched(open).remove(0);
            match reply {
                "denied" => {
                    frame["frame_type"] = json!("denied");
                    frame["body"] = json!({"kind":"internal","reason":"policy denied"});
                }
                "wrong-version" => frame["version"] = json!(0),
                "wrong-program" => frame["program"] = json!(42),
                "early-exit" => {
                    frame["frame_type"] = json!("exit");
                    frame["body"] = json!({"status":0});
                }
                "closed" => return vec![],
                "input" => {
                    frame["frame_type"] = json!("input");
                    frame["body"] = json!({"data":""});
                }
                _ => unreachable!(),
            }
            vec![frame]
        });
        assert_eq!(output.status.code(), Some(125), "{reply}: {output:?}");
        assert!(output.stdout.is_empty(), "{reply}: {output:?}");
    }
}
