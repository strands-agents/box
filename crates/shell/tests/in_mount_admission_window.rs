//! A directory swapped inside the admission window cannot divert a host write.
//!
//! The host counterpart of `kernel_effect_interception.rs`'s
//! `a_background_symlink_swap_cannot_beat_the_admission_window`, which pins the same
//! property for the in-memory VFS. Here the object is a real file under a `bind_direct`
//! mount, which is the shape the box runs: the workload's home is a writable host bind.
//!
//! The winnable race on a host bind is not a *pre-existing* symlink — the box floor refuses
//! a non-canonical spelling at admission — but a real directory that is replaced by a
//! symlink to a protected sibling **after** admission approves it and **before** the effect
//! runs. This test drives that swap deterministically from inside the interceptor, which is
//! exactly the admission window, so the proof does not depend on thread timing.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use strands_shell::{EffectAttempt, EffectInterceptor, EffectPermit, Shell};

/// A permit that records nothing and refuses nothing — the effect runs.
struct Pass;

#[async_trait]
impl EffectPermit for Pass {
    async fn record_outcome(
        self: Box<Self>,
        _outcome: strands_shell::EffectOutcome,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// Admits every attempt, and on the guarded write it first replaces the approved directory
/// `d` with a symlink to `sealed` — the swap a real attacker races into the window. The
/// binding the token captured at resolve time named the real `d`; the effect must see the
/// identity has moved and refuse.
struct Swapper {
    base: PathBuf,
    swapped: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl EffectInterceptor for Swapper {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::Filesystem { path, .. } = effect
            && path.ends_with("/d/f")
            && !self.swapped.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            // Inside the admission window: swap the approved directory for a symlink to the
            // protected sibling.
            std::fs::remove_dir(self.base.join("d")).expect("remove approved dir");
            std::os::unix::fs::symlink("sealed", self.base.join("d")).expect("swap in symlink");
        }
        Ok(Box::new(Pass))
    }
}

/// A host-backed effect whose object identity cannot be derived fails closed.
///
/// When the parent directory of a host-backed target does not exist, `resolve_host` still
/// reports the path as host-backed but no host identity can be bound. The admission-window guard
/// must refuse such an effect rather than pass it to the syscall — the fail-closed rule that also
/// covers a platform which cannot derive an identity at all. Exercised here at the
/// vendored-crate level, where no box reach floor refuses the absent parent first.
#[test]
fn a_host_effect_with_an_unbindable_identity_fails_closed() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-unbindable");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("fixture root");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .build()
            .expect("shell builds");
        shell.proc.cwd = PathBuf::from("/workspace");
        // The parent `nodir` does not exist, so no host identity can be bound for `nodir/f`.
        shell.run("printf x > /workspace/nodir/f").await
    });

    assert_ne!(
        out.status, 0,
        "an unbindable host write must be refused: {}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("filesystem identity changed during effect admission"),
        "the refusal must come from the admission-window guard, not the syscall: {}",
        out.stderr
    );
    assert!(
        !base.join("nodir/f").exists(),
        "nothing may be written when the identity cannot be bound",
    );
}

#[test]
fn a_directory_swapped_inside_the_admission_window_cannot_divert_a_host_write() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-admission-window");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d")).expect("approved dir");
    std::fs::create_dir_all(base.join("sealed")).expect("protected dir");
    std::fs::write(base.join("sealed/f"), "original").expect("protected file");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let swapped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let status = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .effect_interceptor(Arc::new(Swapper {
                base: base.clone(),
                swapped: Arc::clone(&swapped),
            }))
            .build()
            .expect("shell builds");
        shell.proc.cwd = PathBuf::from("/workspace");
        let out = shell.run("printf 'PWNED' > /workspace/d/f").await;
        out.status
    });
    // Drain any spawned writer task before reading the host.
    rt.block_on(local);

    assert!(
        swapped.load(std::sync::atomic::Ordering::SeqCst),
        "the interceptor must have run and performed the swap",
    );
    assert_ne!(
        status, 0,
        "a write whose directory was swapped after admission must be refused",
    );
    assert_eq!(
        std::fs::read_to_string(base.join("sealed/f")).expect("target readable"),
        "original",
        "a directory swapped inside the admission window must not divert the write into the \
         protected sibling",
    );
}

/// Admits every attempt, and on the rename that reports an absent destination it first plants a
/// file at that destination on the host, inside the admission window.
struct DestinationPlanter {
    base: PathBuf,
    planted: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl EffectInterceptor for DestinationPlanter {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::FilesystemPair {
            to,
            operation:
                strands_shell::FsPairOperation::Rename {
                    destination_exists: false,
                    ..
                },
            ..
        } = effect
            && to.ends_with("/d/target")
            && !self.planted.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            std::fs::write(self.base.join("d/target"), "planted").expect("plant the destination");
        }
        Ok(Box::new(Pass))
    }
}

/// A destination that appears after a rename was judged as "destination absent" is not replaced.
#[test]
fn a_destination_planted_inside_the_admission_window_is_not_replaced() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-rename-destination-window");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d")).expect("approved dir");
    std::fs::write(base.join("d/source"), "payload").expect("source file");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let planted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .effect_interceptor(Arc::new(DestinationPlanter {
                base: base.clone(),
                planted: Arc::clone(&planted),
            }))
            .build()
            .expect("shell builds");
        shell.proc.cwd = PathBuf::from("/workspace");
        shell
            .run("mv /workspace/d/source /workspace/d/target")
            .await
    });
    rt.block_on(local);

    assert!(
        planted.load(std::sync::atomic::Ordering::SeqCst),
        "the interceptor must have seen the rename and planted the destination",
    );
    assert_ne!(
        out.status, 0,
        "a rename whose destination appeared after admission must be refused: {}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("filesystem identity changed during effect admission"),
        "the refusal must come from the admission-window guard, not the syscall: {}",
        out.stderr
    );
    assert_eq!(
        std::fs::read_to_string(base.join("d/target")).expect("planted file readable"),
        "planted",
        "a destination planted inside the admission window must not be replaced",
    );
    assert_eq!(
        std::fs::read_to_string(base.join("d/source")).expect("source readable"),
        "payload",
        "a refused rename leaves its source in place",
    );
}

/// Admits every attempt and records the rename operation it sees.
struct RenameRecorder {
    seen: Arc<std::sync::Mutex<Vec<strands_shell::FsPairOperation>>>,
}

#[async_trait]
impl EffectInterceptor for RenameRecorder {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::FilesystemPair { operation, .. } = effect {
            self.seen.lock().expect("record").push(*operation);
        }
        Ok(Box::new(Pass))
    }
}

/// The kernel does not host-back a dangling symlink, so a rename onto one on a host bind reads
/// the destination as absent and is then refused by the kernel before any replacement. This
/// states that limitation so it cannot be mistaken for the in-memory case, where the fact is true.
/// A live host symlink is refused with the same error, so the refusal does not show its target.
#[test]
fn a_rename_onto_a_dangling_host_symlink_is_refused_by_the_kernel() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-rename-dangling-destination");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d")).expect("approved dir");
    std::fs::write(base.join("d/source"), "payload").expect("source file");
    std::os::unix::fs::symlink("nowhere", base.join("d/dangling")).expect("dangling symlink");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .effect_interceptor(Arc::new(RenameRecorder {
                seen: Arc::clone(&seen),
            }))
            .build()
            .expect("shell builds");
        shell.proc.cwd = PathBuf::from("/workspace");
        shell
            .run("mv /workspace/d/source /workspace/d/dangling")
            .await
    });
    rt.block_on(local);

    let seen = seen.lock().expect("record").clone();
    assert_eq!(
        seen,
        vec![strands_shell::FsPairOperation::Rename {
            destination_exists: false,
            destination_is_dir: false,
        }],
        "a dangling host symlink is not host-backed, so the fact reads absent"
    );
    assert_ne!(
        out.status, 0,
        "the kernel refuses a rename onto a dangling host symlink: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("cannot rename onto a host symlink"),
        "the refusal is the kernel's own: {}",
        out.stderr
    );
    assert_eq!(
        std::fs::read_link(base.join("d/dangling")).expect("the link remains a link"),
        PathBuf::from("nowhere")
    );
    assert_eq!(
        std::fs::read_to_string(base.join("d/source")).expect("source readable"),
        "payload",
        "a refused rename leaves its source in place",
    );
}

/// A rename onto a live host symlink is refused like one onto a dangling host symlink.
#[test]
fn a_rename_onto_a_live_host_symlink_is_refused_by_the_kernel() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-rename-live-destination");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d")).expect("approved dir");
    std::fs::write(base.join("d/source"), "payload").expect("source file");
    std::fs::write(base.join("d/target"), "original").expect("link target");
    std::os::unix::fs::symlink("target", base.join("d/live")).expect("live symlink");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .build()
            .expect("shell builds");
        shell.proc.cwd = PathBuf::from("/workspace");
        shell.run("mv /workspace/d/source /workspace/d/live").await
    });
    rt.block_on(local);

    assert_ne!(out.status, 0, "the kernel refuses: {}", out.stderr);
    assert!(
        out.stderr.contains("cannot rename onto a host symlink"),
        "the refusal matches the dangling case: {}",
        out.stderr
    );
    assert_eq!(
        std::fs::read_link(base.join("d/live")).expect("the link remains a link"),
        PathBuf::from("target")
    );
    assert_eq!(
        std::fs::read_to_string(base.join("d/target")).expect("target readable"),
        "original",
        "the link's target is not written"
    );
}

/// `mkdir` onto a host symlink fails the same way whether or not its target exists, and creates
/// nothing.
#[test]
fn mkdir_onto_a_host_symlink_does_not_show_whether_its_target_exists() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-mkdir-symlink");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d/target")).expect("link target");
    std::os::unix::fs::symlink("target", base.join("d/live")).expect("live symlink");
    std::os::unix::fs::symlink("nowhere", base.join("d/dangling")).expect("dangling symlink");
    let mount = base.to_str().expect("UTF-8 mount").to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let (live, dangling) = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&mount, "/workspace")
            .disable_network()
            .build()
            .expect("shell builds");
        (
            shell.run("mkdir /workspace/d/live").await,
            shell.run("mkdir /workspace/d/dangling").await,
        )
    });
    rt.block_on(local);

    assert_ne!(live.status, 0, "mkdir onto a live host symlink fails");
    assert_ne!(
        dangling.status, 0,
        "mkdir onto a dangling host symlink fails"
    );
    assert_eq!(
        live.stderr.replace("live", "LINK"),
        dangling.stderr.replace("dangling", "LINK"),
        "the error does not show whether the target exists"
    );
    assert!(
        !base.join("d/nowhere").exists(),
        "mkdir does not create the link's target"
    );
}

/// A rename onto a read-only bind point is refused and leaves the bind in place.
#[test]
fn a_rename_onto_a_read_only_bind_point_is_refused() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-rename-read-only-bind");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("dir")).expect("bound directory");
    std::fs::write(base.join("dir/secret"), "host").expect("bound directory file");
    std::fs::write(base.join("file"), "host").expect("bound file");
    let file = base.join("file").to_str().expect("UTF-8 path").to_string();
    let dir = base.join("dir").to_str().expect("UTF-8 path").to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let (onto_file, onto_dir, file_after, dir_after) = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct_readonly(&file, "/home/lash/cfg")
            .bind_direct_readonly(&dir, "/home/lash/proj")
            .disable_network()
            .build()
            .expect("shell builds");
        let setup = shell
            .run("printf fake > /tmp/fake && mkdir -p /tmp/fakedir")
            .await;
        assert_eq!(setup.status, 0, "setup: {}", setup.stderr);
        (
            shell.run("mv /tmp/fake /home/lash/cfg").await,
            shell.run("mv /tmp/fakedir /home/lash/proj").await,
            shell.run("cat /home/lash/cfg").await,
            shell.run("cat /home/lash/proj/secret").await,
        )
    });
    rt.block_on(local);

    for out in [&onto_file, &onto_dir] {
        assert_ne!(out.status, 0, "a read-only bind is not replaced");
        assert!(
            out.stderr.contains("read-only bind mount"),
            "the refusal is the bind's own: {}",
            out.stderr
        );
    }
    assert_eq!(file_after.stdout, "host", "the file bind is still in place");
    assert_eq!(
        dir_after.stdout, "host",
        "the directory bind is still in place"
    );
}

/// `rm` and `ln -s` onto a writable bind point are refused and leave the host file in place.
#[test]
fn a_writable_bind_point_is_not_removed_or_replaced() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-bind-point-busy");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("base");
    std::fs::write(base.join("file"), "host").expect("bound file");
    let file = base.join("file").to_str().expect("UTF-8 path").to_string();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let (removed, linked, after) = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .bind_direct(&file, "/home/lash/cfg")
            .disable_network()
            .build()
            .expect("shell builds");
        (
            shell.run("rm /home/lash/cfg").await,
            shell.run("ln -s elsewhere /home/lash/cfg").await,
            shell.run("cat /home/lash/cfg").await,
        )
    });
    rt.block_on(local);

    for out in [&removed, &linked] {
        assert_ne!(out.status, 0, "a bind point is not removed or replaced");
        assert!(
            out.stderr.contains("bind mount point is busy"),
            "{}",
            out.stderr
        );
    }
    assert_eq!(
        std::fs::read_to_string(base.join("file")).expect("host file remains"),
        "host"
    );
    assert_eq!(after.stdout, "host", "the bind is still in place");
}

/// Records the program each host spawn receives, so the test can compare it with the decision.
fn recording_spawner(
    received: Arc<std::sync::Mutex<Vec<PathBuf>>>,
) -> strands_shell::os::HostSpawner {
    Arc::new(move |spawn: strands_shell::os::HostSpawn| {
        let received = Arc::clone(&received);
        Box::pin(async move {
            received.lock().expect("record").push(spawn.program.clone());
            Ok(strands_shell::os::HostSpawnOutcome {
                status: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        })
    })
}

/// Admits every attempt, records the program each `shell:spawn` decision names, and on the first
/// one re-points `link` at `other` — the swap a real attacker races into the window between the
/// decision and the spawn.
struct LinkSwapper {
    link: PathBuf,
    other: PathBuf,
    decided: Arc<std::sync::Mutex<Vec<String>>>,
    swapped: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl EffectInterceptor for LinkSwapper {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::ShellSpawn { program_path, .. } = effect {
            self.decided
                .lock()
                .expect("record")
                .push((*program_path).to_string());
            if !self.swapped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::fs::remove_file(&self.link).expect("remove the approved link");
                std::os::unix::fs::symlink(&self.other, &self.link).expect("swap in the other");
            }
        }
        Ok(Box::new(Pass))
    }
}

/// **The spawn seam receives the identity the decision named.** A symbolic link spelling is
/// judged as its canonical target, and a link swapped inside the admission window cannot hand the
/// seam a different program.
#[cfg(unix)]
#[test]
fn a_symlink_swapped_inside_the_admission_window_cannot_divert_a_host_spawn() {
    use std::os::unix::fs::PermissionsExt as _;
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-spawn-window");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("out")).expect("fixture root");
    for program in ["out/built", "out/other"] {
        std::fs::write(base.join(program), "#!/bin/sh\n").expect("a program");
        std::fs::set_permissions(base.join(program), std::fs::Permissions::from_mode(0o755))
            .expect("an executable program");
    }
    let base = base.canonicalize().expect("a canonical root");
    let link = base.join("out/link");
    std::os::unix::fs::symlink(base.join("out/built"), &link).expect("the approved link");

    let decided = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let swapped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let status = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .disable_network()
            .effect_interceptor(Arc::new(LinkSwapper {
                link: link.clone(),
                other: base.join("out/other"),
                decided: Arc::clone(&decided),
                swapped: Arc::clone(&swapped),
            }))
            .host_spawner(recording_spawner(Arc::clone(&received)))
            .build()
            .expect("shell builds");
        shell.run(link.to_str().expect("UTF-8 link")).await.status
    });
    rt.block_on(local);

    let built = base.join("out/built");
    assert!(
        swapped.load(std::sync::atomic::Ordering::SeqCst),
        "the interceptor must have run and performed the swap",
    );
    assert_eq!(status, 0, "the permitted program runs");
    assert_eq!(
        *decided.lock().expect("read"),
        vec![built.display().to_string()],
        "the decision names the canonical target of the spelling, not the spelling",
    );
    assert_eq!(
        *received.lock().expect("read"),
        vec![built],
        "the seam receives the program the decision named, not the swapped-in one",
    );
}

/// Admits every attempt, records the program each `shell:spawn` decision names, and on the first
/// one plants a program at `at` — the file an attacker races into the window after a decision on a
/// spelling that named nothing.
struct Planter {
    at: PathBuf,
    decided: Arc<std::sync::Mutex<Vec<String>>>,
    planted: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl EffectInterceptor for Planter {
    async fn intercept(
        &self,
        effect: &EffectAttempt<'_>,
    ) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::ShellSpawn { program_path, .. } = effect {
            self.decided
                .lock()
                .expect("record")
                .push((*program_path).to_string());
            if !self.planted.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::os::unix::fs::symlink("/bin/sh", &self.at).expect("plant the program");
            }
        }
        Ok(Box::new(Pass))
    }
}

/// **A spelling that bound no file at decision time never reaches the seam.** The decision is
/// raised on the folded spelling, a permit answers `command not found`, and a program planted
/// inside the admission window does not run.
#[cfg(unix)]
#[test]
fn a_program_planted_inside_the_admission_window_does_not_reach_the_seam() {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("host-spawn-plant");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("tools")).expect("fixture root");
    let base = base.canonicalize().expect("a canonical root");
    let at = base.join("tools/g");

    let decided = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let planted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();

    let out = local.block_on(&rt, async {
        let mut shell = Shell::builder()
            .disable_network()
            .effect_interceptor(Arc::new(Planter {
                at: at.clone(),
                decided: Arc::clone(&decided),
                planted: Arc::clone(&planted),
            }))
            .host_spawner(recording_spawner(Arc::clone(&received)))
            .build()
            .expect("shell builds");
        shell
            .run(&format!("{}/tools/../tools/g", base.display()))
            .await
    });
    rt.block_on(local);

    assert!(
        planted.load(std::sync::atomic::Ordering::SeqCst),
        "the interceptor must have run and planted the program",
    );
    assert_eq!(
        *decided.lock().expect("read"),
        vec![at.display().to_string()],
        "the decision names the folded spelling",
    );
    assert!(
        received.lock().expect("read").is_empty(),
        "an unbound spelling must not reach the seam: {:?}",
        received.lock().expect("read")
    );
    assert_eq!(out.status, 127, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("command not found"),
        "a permitted spelling that bound no file is not found: {}",
        out.stderr
    );
}
