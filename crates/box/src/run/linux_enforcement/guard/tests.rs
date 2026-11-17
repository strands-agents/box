//! Kernel checks for worker-bound entry approvals.
use super::*;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Barrier;

fn pin(path: &Path) -> OwnedFd {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
        .into()
}
fn denied(result: io::Result<()>) {
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EACCES));
}
#[test]
fn a_registered_worker_cannot_delete_without_an_approval() {
    let guard = Guard::load().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source");
    std::fs::write(&file, "original").unwrap();
    let _worker = guard.register().unwrap();
    denied(std::fs::remove_file(&file));
    assert_eq!(std::fs::read(&file).unwrap(), b"original");
}
#[test]
fn an_approval_cannot_be_reused_for_a_second_link_to_the_same_file() {
    let guard = Guard::load().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let alias = directory.path().join("alias");
    std::fs::write(&source, "original").unwrap();
    std::fs::hard_link(&source, &alias).unwrap();
    let parent = pin(directory.path());
    let object = pin(&source);
    let worker = guard.register().unwrap();
    worker
        .effect(&parent, &object, None, || {
            std::fs::remove_file(&source)?;
            denied(std::fs::remove_file(&alias));
            Ok(())
        })
        .unwrap();
    assert_eq!(std::fs::read(alias).unwrap(), b"original");
}
#[test]
fn a_delete_approval_cannot_authorize_a_rename() {
    let guard = Guard::load().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let destination = directory.path().join("destination");
    std::fs::write(&source, "original").unwrap();
    let parent = pin(directory.path());
    let object = pin(&source);
    let worker = guard.register().unwrap();
    denied(worker.effect(&parent, &object, None, || {
        std::fs::rename(&source, &destination)
    }));
    assert_eq!(std::fs::read(source).unwrap(), b"original");
    assert!(!destination.exists());
}
#[test]
fn simultaneous_workers_keep_separate_approvals() {
    let guard = Guard::load().unwrap();
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let guard = Arc::clone(&guard);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let directory = tempfile::tempdir().unwrap();
                let source = directory.path().join("source");
                std::fs::write(&source, "original").unwrap();
                let parent = pin(directory.path());
                let object = pin(&source);
                let worker = guard.register().unwrap();
                worker
                    .effect(&parent, &object, None, || {
                        barrier.wait();
                        std::fs::remove_file(&source)
                    })
                    .unwrap();
                assert!(!source.exists());
            });
        }
    });
}
#[test]
fn unregistering_a_worker_restores_its_unmonitored_operations() {
    let guard = Guard::load().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, "original").unwrap();
    let worker = guard.register().unwrap();
    denied(std::fs::remove_file(&source));
    drop(worker);
    std::fs::remove_file(source).unwrap();
}
#[test]
fn dropping_a_different_box_guard_keeps_the_active_guard_attached() {
    let first = Guard::load().unwrap();
    let second = Guard::load().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::write(&source, "original").unwrap();
    let _worker = first.register().unwrap();
    drop(second);
    denied(std::fs::remove_file(&source));
}
