//! An object swapped or planted inside the admission window, between a decision and its effect,
//! is refused, and never diverts the effect.
//!
//! Each case changes the host from inside the checkpoint, which is exactly the window, so the
//! proof does not depend on thread timing.

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use box_shell::{
    EffectAttempt, EffectInterceptor, EffectPermit, FsOperation, FsPairOperation, HostSpawner,
};
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

/// A checkpoint that refuses each removal, rename, and symlink, and admits the rest.
struct RefuseRemoval;

#[async_trait::async_trait]
impl EffectInterceptor for RefuseRemoval {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        let removal = matches!(
            effect,
            EffectAttempt::Filesystem {
                operation: FsOperation::RemoveFile | FsOperation::RemoveDir,
                ..
            } | EffectAttempt::FilesystemPair {
                operation: FsPairOperation::Rename { .. } | FsPairOperation::Symlink,
                ..
            }
        );
        if removal {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refused by the checkpoint",
            ));
        }
        support::PermitAll.intercept(effect).await
    }
}

/// Serve `real.txt` at `/home/lash/cfg`, and each folder in `folders` at `/home/lash/<name>`.
fn bound(folder: &Folder, folders: &[&str]) -> support::Builder {
    let file = folder.ws.join("real.txt").display().to_string();
    let mut builder = support::builder().bind_direct(file, "/home/lash/cfg");
    for name in folders {
        let source = folder.ws.join(name).display().to_string();
        builder = builder.bind_direct(source, format!("/home/lash/{name}"));
    }
    builder
}

#[test]
fn the_checkpoint_decides_whether_a_root_is_removed_moved_or_replaced() {
    let folder = Folder::standard();
    std::fs::create_dir(folder.ws.join("empty")).expect("an empty folder");
    let outs = support::run(async {
        let mut shell = bound(&folder, &["empty", "dir"])
            .effect_interceptor(Arc::new(RefuseRemoval))
            .build()
            .expect("shell builds");
        let mut outs = Vec::new();
        for script in [
            "rm /home/lash/cfg",
            "ln -s elsewhere /home/lash/cfg",
            "rmdir /home/lash/empty",
            "mv /home/lash/dir /home/lash/moved",
        ] {
            outs.push((script, shell.run(script).await));
        }
        outs
    });
    for (script, out) in &outs {
        assert_ne!(out.status, 0, "{script}: {}", out.stderr);
        assert!(
            out.stderr.contains("refused by the checkpoint"),
            "{script}: {}",
            out.stderr
        );
    }
    assert_eq!(read(&folder.ws.join("real.txt")), "REAL_BYTES");
    assert!(folder.ws.join("empty").is_dir(), "the empty folder stays");
    assert_eq!(read(&folder.ws.join("dir/inner.txt")), "INNER");
}

#[test]
fn a_permitted_rmdir_removes_the_host_folder_at_a_root() {
    let folder = Folder::standard();
    std::fs::create_dir(folder.ws.join("empty")).expect("an empty folder");
    let out = support::run(async {
        let mut shell = bound(&folder, &["empty"]).build().expect("shell builds");
        shell.run("rmdir /home/lash/empty").await
    });
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(!folder.exists("empty"), "the host folder is removed");
}

#[test]
fn a_permitted_rm_removes_the_host_file_at_a_root() {
    let folder = Folder::standard();
    let out = support::run(async {
        let mut shell = bound(&folder, &[]).build().expect("shell builds");
        shell.run("rm /home/lash/cfg").await
    });
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert!(!folder.exists("real.txt"), "the host file is removed");
}

#[test]
fn a_permitted_link_at_a_root_is_refused_as_an_escape_from_the_bind() {
    let folder = Folder::standard();
    std::fs::create_dir(folder.ws.join("empty")).expect("an empty folder");
    let (removed, linked) = support::run(async {
        let mut shell = bound(&folder, &["empty"]).build().expect("shell builds");
        (
            shell.run("rmdir /home/lash/empty").await,
            shell.run("ln -s inner /home/lash/empty").await,
        )
    });
    assert_eq!(removed.status, 0, "{}", removed.stderr);
    assert_ne!(linked.status, 0, "{}", linked.stderr);
    assert!(
        linked
            .stderr
            .contains("symlink target escapes the bind mount"),
        "{}",
        linked.stderr
    );
    assert!(!folder.exists("empty"), "no host link is made");
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

#[test]
fn a_file_replaced_inside_the_admission_window_keeps_its_times() {
    use std::os::unix::fs::MetadataExt as _;
    let folder = Folder::standard();
    let ws = folder.ws.clone();
    let (hook, fired) = once(
        |effect| {
            matches!(
                effect,
                EffectAttempt::Filesystem {
                    path,
                    operation: box_shell::FsOperation::SetTimes,
                } if path.ends_with("/real.txt")
            )
        },
        move || {
            std::fs::write(ws.join("planted.txt"), "PLANTED").expect("a replacement");
            std::fs::rename(ws.join("planted.txt"), ws.join("real.txt")).expect("replace");
        },
    );
    let out = folder.run_with(hook, "touch -d @0 real.txt");
    assert!(fired.load(Ordering::SeqCst));
    assert_ne!(out.status, 0, "{}", out.stderr);
    assert!(out.stderr.contains(STALE), "{}", out.stderr);
    let replaced = std::fs::metadata(folder.ws.join("real.txt")).expect("stat");
    assert_eq!(read(&folder.ws.join("real.txt")), "PLANTED");
    assert_ne!(replaced.mtime(), 0, "the replacement's time is unchanged");
}
