//! An object swapped or planted inside the admission window, between a decision and its effect,
//! is refused, and never diverts the effect.
//!
//! Each case changes the host from inside the checkpoint, which is exactly the window, so the
//! proof does not depend on thread timing.

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use box_shell::{EffectAttempt, EffectInterceptor, FsPairOperation, HostSpawner};
use support::{Folder, Hook};

const STALE: &str = "filesystem identity changed during effect admission";

/// A checkpoint that runs `change` once, on the first attempt `matches` selects.
fn once<M, C>(matches: M, change: C) -> (Arc<dyn EffectInterceptor>, Arc<AtomicBool>)
where
    M: Fn(&EffectAttempt<'_>) -> bool + Send + Sync + 'static,
    C: Fn() + Send + Sync + 'static,
{
    let fired = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&fired);
    let hook = Hook(move |effect: &EffectAttempt<'_>| {
        if matches(effect) && !seen.swap(true, Ordering::SeqCst) {
            change();
        }
    });
    (Arc::new(hook), fired)
}

fn names_path(effect: &EffectAttempt<'_>, suffix: &str) -> bool {
    matches!(effect, EffectAttempt::Filesystem { path, .. } if path.ends_with(suffix))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("readable")
}

#[test]
fn a_host_effect_with_an_unbindable_identity_fails_closed() {
    let folder = Folder::standard();
    let ran = folder.run("printf x > /workspace/nodir/f");
    assert_ne!(ran.out.status, 0, "{}", ran.out.stderr);
    assert!(ran.out.stderr.contains(STALE), "{}", ran.out.stderr);
    assert!(!folder.exists("nodir/f"));
}

#[test]
fn a_directory_swapped_inside_the_admission_window_cannot_divert_a_host_write() {
    let folder = Folder::standard();
    std::fs::create_dir(folder.ws.join("d")).expect("approved dir");
    std::fs::create_dir(folder.ws.join("sealed")).expect("protected dir");
    std::fs::write(folder.ws.join("sealed/f"), "original").expect("protected file");
    let ws = folder.ws.clone();
    let (hook, fired) = once(
        |effect| names_path(effect, "/d/f"),
        move || {
            std::fs::remove_dir(ws.join("d")).expect("remove the approved dir");
            std::os::unix::fs::symlink("sealed", ws.join("d")).expect("swap in a link");
        },
    );
    let out = folder.run_with(hook, "printf PWNED > /workspace/d/f");
    assert!(fired.load(Ordering::SeqCst));
    assert_ne!(out.status, 0, "{}", out.stderr);
    assert_eq!(read(&folder.ws.join("sealed/f")), "original");
}

#[test]
fn a_destination_planted_inside_the_admission_window_is_not_replaced() {
    let folder = Folder::standard();
    let ws = folder.ws.clone();
    let (hook, fired) = once(
        |effect| {
            matches!(effect, EffectAttempt::FilesystemPair {
                to,
                operation: FsPairOperation::Rename { destination_exists: false, .. },
                ..
            } if to.ends_with("/target"))
        },
        move || std::fs::write(ws.join("target"), "planted").expect("plant the destination"),
    );
    let out = folder.run_with(hook, "mv real.txt target");
    assert!(fired.load(Ordering::SeqCst));
    assert_ne!(out.status, 0, "{}", out.stderr);
    assert!(out.stderr.contains(STALE), "{}", out.stderr);
    assert_eq!(read(&folder.ws.join("target")), "planted");
    assert_eq!(read(&folder.ws.join("real.txt")), "REAL_BYTES");
}

#[test]
fn a_rename_onto_a_dangling_host_symlink_is_refused_by_the_kernel() {
    let folder = Folder::standard();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let hook = Hook(move |effect: &EffectAttempt<'_>| {
        if let EffectAttempt::FilesystemPair { operation, .. } = effect {
            record.lock().expect("record").push(*operation);
        }
    });
    let out = folder.run_with(Arc::new(hook), "mv real.txt gone");
    assert_eq!(
        *seen.lock().expect("record"),
        vec![FsPairOperation::Rename {
            destination_exists: true,
            destination_is_dir: false,
        }],
        "the destination is the link itself"
    );
    assert!(
        out.stderr.contains("cannot rename onto a host symlink"),
        "{}",
        out.stderr
    );
    assert!(folder.is_link("gone"));
    assert_eq!(read(&folder.ws.join("real.txt")), "REAL_BYTES");
}

#[test]
fn a_rename_onto_a_live_host_symlink_is_refused_by_the_kernel() {
    let folder = Folder::standard();
    let ran = folder.run("mv real.txt flink");
    assert!(
        ran.out.stderr.contains("cannot rename onto a host symlink"),
        "{}",
        ran.out.stderr
    );
    assert!(folder.is_link("flink"));
    assert_eq!(
        read(&folder.ws.join("secret.txt")),
        "IN_MOUNT",
        "the target is not written"
    );
}

#[test]
fn mkdir_onto_a_host_symlink_does_not_show_whether_its_target_exists() {
    let folder = Folder::standard();
    let live = folder.run("mkdir dlink").out;
    let dangling = folder.run("mkdir gone").out;
    assert_ne!(live.status, 0);
    assert_ne!(dangling.status, 0);
    assert_eq!(
        live.stderr.replace("dlink", "LINK"),
        dangling.stderr.replace("gone", "LINK"),
        "the error does not show whether the target exists"
    );
}

#[test]
fn a_writable_bind_point_is_not_removed_or_replaced() {
    let folder = Folder::standard();
    let file = folder.ws.join("real.txt").display().to_string();
    let (removed, linked, after) = support::run(async {
        let mut shell = support::builder()
            .bind_direct(file, "/home/lash/cfg")
            .build()
            .expect("shell builds");
        (
            shell.run("rm /home/lash/cfg").await,
            shell.run("ln -s elsewhere /home/lash/cfg").await,
            shell.run("cat /home/lash/cfg").await,
        )
    });
    for out in [&removed, &linked] {
        assert!(
            out.stderr.contains("bind mount point is busy"),
            "{}",
            out.stderr
        );
    }
    assert_eq!(after.stdout, "REAL_BYTES", "the bind is still in place");
}

/// A spawner that records each program it receives.
fn recording_spawner(received: Arc<Mutex<Vec<PathBuf>>>) -> HostSpawner {
    Arc::new(move |spawn: box_shell::HostSpawn| {
        received.lock().expect("record").push(spawn.program.clone());
        Box::pin(async {
            Ok(box_shell::HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

/// Run `command` with `change` applied on the first `shell:spawn` decision, and return the
/// status, the programs decided, and the programs the spawner received.
fn spawn_with<C: Fn() + Send + Sync + 'static>(
    command: &str,
    change: C,
) -> (strands_shell::Output, Vec<String>, Vec<PathBuf>) {
    let decided = Arc::new(Mutex::new(Vec::new()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&decided);
    let fired = AtomicBool::new(false);
    let hook = Hook(move |effect: &EffectAttempt<'_>| {
        if let EffectAttempt::ShellSpawn { program_path, .. } = effect {
            record
                .lock()
                .expect("record")
                .push((*program_path).to_string());
            if !fired.swap(true, Ordering::SeqCst) {
                change();
            }
        }
    });
    let spawner = recording_spawner(Arc::clone(&received));
    let out = support::run(async {
        let mut shell = support::builder()
            .effect_interceptor(Arc::new(hook))
            .host_spawner(spawner)
            .build()
            .expect("shell builds");
        shell.run(command).await
    });
    let decided = decided.lock().expect("read").clone();
    let received = received.lock().expect("read").clone();
    (out, decided, received)
}

#[test]
fn a_symlink_swapped_inside_the_admission_window_cannot_divert_a_host_spawn() {
    let folder = Folder::standard();
    for program in ["built", "other"] {
        std::fs::write(folder.ws.join(program), "#!/bin/sh\n").expect("a program");
        folder.set_mode(program, 0o755);
    }
    let ws = folder.ws.canonicalize().expect("canonical");
    let link = ws.join("link");
    std::os::unix::fs::symlink(ws.join("built"), &link).expect("the approved link");
    let (swap_link, other) = (link.clone(), ws.join("other"));
    let (out, decided, received) = spawn_with(link.to_str().expect("UTF-8"), move || {
        std::fs::remove_file(&swap_link).expect("remove the approved link");
        std::os::unix::fs::symlink(&other, &swap_link).expect("swap in the other");
    });
    let built = ws.join("built");
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(
        decided,
        vec![built.display().to_string()],
        "decided on the target"
    );
    assert_eq!(received, vec![built], "the spawner runs what was decided");
}

#[test]
fn a_program_planted_inside_the_admission_window_does_not_reach_the_seam() {
    let folder = Folder::standard();
    let ws = folder.ws.canonicalize().expect("canonical");
    let at = ws.join("g");
    let planted = at.clone();
    let (out, decided, received) = spawn_with(&format!("{}/dir/../g", ws.display()), move || {
        std::os::unix::fs::symlink("/bin/sh", &planted).expect("plant the program");
    });
    assert_eq!(
        decided,
        vec![at.display().to_string()],
        "decided on the folded spelling"
    );
    assert!(received.is_empty(), "{received:?}");
    assert_eq!(out.status, 127, "{}", out.stderr);
    assert!(out.stderr.contains("command not found"), "{}", out.stderr);
}
