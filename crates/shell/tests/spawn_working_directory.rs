#![cfg(unix)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use strands_shell::os::{HostSpawn, HostSpawnOutcome, HostSpawner};
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Shell};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Admitted(String),
    DirectoryRead(String),
    Spawned(String, PathBuf),
    Recorded(String, i32),
    Indeterminate(String),
}

type Events = Arc<Mutex<Vec<Event>>>;

struct Admission {
    events: Events,
    relative: bool,
    deny_second: bool,
}

struct Permit {
    events: Events,
    argument: String,
    directory: Option<PathBuf>,
}

#[async_trait]
impl EffectInterceptor for Admission {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let (argument, directory) = match effect {
            EffectAttempt::ShellSpawn { args, .. } => {
                let argument = args.first().expect("test command argument").clone();
                self.events
                    .lock()
                    .unwrap()
                    .push(Event::Admitted(argument.clone()));
                if self.deny_second && argument == "second" {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "second stage denied",
                    ));
                }
                let root = if self.relative {
                    "relative"
                } else {
                    "/checked"
                };
                let directory = Path::new(root).join(&argument);
                (argument, Some(directory))
            }
            _ => (String::new(), None),
        };
        Ok(Box::new(Permit {
            events: Arc::clone(&self.events),
            argument,
            directory,
        }))
    }
}

#[async_trait]
impl EffectPermit for Permit {
    fn spawn_working_directory(&self) -> Option<&Path> {
        self.events
            .lock()
            .unwrap()
            .push(Event::DirectoryRead(self.argument.clone()));
        self.directory.as_deref()
    }

    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if !self.argument.is_empty() {
            let EffectOutcome::ShellCommand { reported_status } = outcome else {
                panic!("spawn must report a command outcome");
            };
            self.events
                .lock()
                .unwrap()
                .push(Event::Recorded(self.argument, reported_status));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        if !self.argument.is_empty() {
            self.events
                .lock()
                .unwrap()
                .push(Event::Indeterminate(self.argument));
        }
    }
}

fn spawner(events: &Events) -> HostSpawner {
    let events = Arc::clone(events);
    Arc::new(move |spawn: HostSpawn| {
        let events = Arc::clone(&events);
        Box::pin(async move {
            let argument = spawn.args.first().expect("test command argument").clone();
            events
                .lock()
                .unwrap()
                .push(Event::Spawned(argument, spawn.cwd));
            Ok(HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

fn command(argument: &str) -> String {
    format!(
        "'{}' {argument}",
        std::env::current_exe().unwrap().display()
    )
}

fn runtime() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    (
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        tokio::task::LocalSet::new(),
    )
}

#[test]
fn pipeline_stages_and_concurrent_calls_keep_their_admitted_directories() {
    let events = Events::default();
    let admission = Arc::new(Admission {
        events: Arc::clone(&events),
        relative: false,
        deny_second: false,
    });
    let (runtime, local) = runtime();
    runtime.block_on(local.run_until(async {
        let mut first = Shell::builder()
            .effect_interceptor(admission.clone())
            .host_spawner(spawner(&events))
            .build()
            .unwrap();
        let mut second = Shell::builder()
            .effect_interceptor(admission)
            .host_spawner(spawner(&events))
            .build()
            .unwrap();
        let before = first.run("pwd").await.stdout;
        let pipeline = format!("{} | $NO_COMMAND | {}", command("first"), command("second"));
        let concurrent = command("concurrent");
        let (pipeline, concurrent) = tokio::join!(first.run(&pipeline), second.run(&concurrent));
        assert_eq!(pipeline.status, 0, "{}", pipeline.stderr);
        assert_eq!(concurrent.status, 0, "{}", concurrent.stderr);
        assert_eq!(
            first.run("pwd").await.stdout,
            before,
            "a child directory must not change its parent"
        );
    }));
    let events = events.lock().unwrap();
    for argument in ["first", "second", "concurrent"] {
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::DirectoryRead(argument.into()))
                .count(),
            1,
            "{events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event
                    == Event::Spawned(argument.into(), Path::new("/checked").join(argument)))
                .count(),
            1,
            "{events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Recorded(argument.into(), 0))
                .count(),
            1,
            "{events:?}"
        );
    }
    let second_admitted = events
        .iter()
        .position(|event| *event == Event::Admitted("second".into()))
        .unwrap();
    for argument in ["first", "second"] {
        let spawned = events
            .iter()
            .position(|event| matches!(event, Event::Spawned(name, _) if name == argument))
            .unwrap();
        assert!(
            second_admitted < spawned,
            "all pipeline stages must be admitted first: {events:?}"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::Indeterminate(_)))
    );
}

#[test]
fn a_relative_admitted_directory_fails_before_spawn() {
    let events = Events::default();
    let (runtime, local) = runtime();
    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(Arc::new(Admission {
                events: Arc::clone(&events),
                relative: true,
                deny_second: false,
            }))
            .host_spawner(spawner(&events))
            .build()
            .unwrap();
        let output = shell.run(&command("first")).await;
        assert_eq!(output.status, 125, "{}", output.stderr);
        assert!(
            output.stderr.contains("must be absolute"),
            "{}",
            output.stderr
        );
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Admitted("first".into()),
            Event::DirectoryRead("first".into()),
            Event::Indeterminate("first".into())
        ]
    );
}

#[test]
fn a_denied_stage_abandons_the_prepared_directory_without_spawning() {
    let events = Events::default();
    let (runtime, local) = runtime();
    runtime.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .effect_interceptor(Arc::new(Admission {
                events: Arc::clone(&events),
                relative: false,
                deny_second: true,
            }))
            .host_spawner(spawner(&events))
            .build()
            .unwrap();
        let output = shell
            .run(&format!("{} | {}", command("first"), command("second")))
            .await;
        assert_eq!(output.status, 126, "{}", output.stderr);
    }));
    assert_eq!(
        *events.lock().unwrap(),
        [
            Event::Admitted("first".into()),
            Event::DirectoryRead("first".into()),
            Event::Admitted("second".into()),
            Event::Indeterminate("first".into())
        ]
    );
}
