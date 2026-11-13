#![cfg(unix)]

//! The spawn seam says whether the command's stdin carries data (`HostSpawn::stdin`).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use strands_shell::os::{HostSpawn, HostSpawnOutcome, HostSpawner, STDIN, SpawnStdin};
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Shell};

struct Allow;
struct Permit;

#[async_trait]
impl EffectInterceptor for Allow {
    async fn intercept(&self, _: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        Ok(Box::new(Permit))
    }
}

#[async_trait]
impl EffectPermit for Permit {
    async fn record_outcome(self: Box<Self>, _: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

type Seen = Arc<Mutex<Vec<SpawnStdin>>>;

fn spawner(seen: &Seen) -> HostSpawner {
    let seen = Arc::clone(seen);
    Arc::new(move |spawn: HostSpawn| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            seen.lock().unwrap().push(spawn.stdin);
            Ok(HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

fn program() -> String {
    format!("'{}'", std::env::current_exe().unwrap().display())
}

/// Run `script` with an optional outside reader, and return what each spawn saw.
fn spawns(script: &str, outside: Option<Outside>) -> (Vec<SpawnStdin>, String) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    let seen = Seen::default();
    let stdout = runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(Arc::new(Allow))
            .host_spawner(spawner(&seen))
            .build()
            .unwrap();
        if let Some(outside) = outside {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            shell.proc.set_outside_reader(STDIN, rx);
            tokio::spawn(async move {
                match outside {
                    Outside::Eof => drop(tx),
                    Outside::Bytes(data) => {
                        let _ = tx.send(Bytes::from_static(data)).await;
                    }
                    Outside::Open => {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        drop(tx);
                    }
                }
            });
        }
        let output = shell.run(&script.replace("PROGRAM", &program())).await;
        assert_eq!(output.status, 0, "{}", output.stderr);
        output.stdout
    }));
    let seen = seen.lock().unwrap().clone();
    (seen, stdout)
}

enum Outside {
    Eof,
    Bytes(&'static [u8]),
    Open,
}

#[test]
fn spawn_stdin_is_none_without_input() {
    assert_eq!(spawns("PROGRAM", None).0, [SpawnStdin::None]);
    assert_eq!(spawns("PROGRAM <&-", None).0, [SpawnStdin::None]);
}

#[test]
fn spawn_stdin_is_data_for_a_pipe_heredoc_and_file() {
    assert_eq!(spawns("printf x | PROGRAM", None).0, [SpawnStdin::Data]);
    assert_eq!(spawns("true | PROGRAM", None).0, [SpawnStdin::Data]);
    assert_eq!(spawns("PROGRAM <<EOF\nx\nEOF", None).0, [SpawnStdin::Data]);
    assert_eq!(
        spawns("printf x > /tmp/f; PROGRAM < /tmp/f", None).0,
        [SpawnStdin::Data]
    );
}

#[test]
fn spawn_stdin_from_outside_is_none_only_when_it_ends_empty() {
    assert_eq!(spawns("PROGRAM", Some(Outside::Eof)).0, [SpawnStdin::None]);
    assert_eq!(
        spawns("PROGRAM", Some(Outside::Bytes(b"x"))).0,
        [SpawnStdin::Data]
    );
    let started = std::time::Instant::now();
    assert_eq!(spawns("PROGRAM", Some(Outside::Open)).0, [SpawnStdin::Data]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "an open outside input decides at the wait, not at its end"
    );
}

#[test]
fn spawn_stdin_leaves_outside_bytes_for_the_next_reader() {
    let (seen, stdout) = spawns("PROGRAM; cat", Some(Outside::Bytes(b"kept")));
    assert_eq!(seen, [SpawnStdin::Data]);
    assert_eq!(stdout, "kept");
}
