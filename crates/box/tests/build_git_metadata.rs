//! Checkout identity, archive boundaries, and rebuild inputs for Core build metadata.

#[path = "../build_metadata.rs"]
mod build_metadata;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use build_metadata::git_metadata;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "box-build-metadata-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Self(path.canonicalize().expect("canonical test directory")),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create test directory: {error}"),
            }
        }
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove test directory");
    }
}

fn git(root: &Path, arguments: &[&str]) -> String {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args([
        "-c",
        "user.name=Box metadata test",
        "-c",
        "user.email=metadata-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    command.args(arguments);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    let output = command.output().expect("run git");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository(root: &Path) -> String {
    std::fs::create_dir_all(root.join("crates/box")).unwrap();
    git(root, &["init", "--initial-branch=main"]);
    git(root, &["commit", "--allow-empty", "-m", "initial"]);
    git(root, &["rev-parse", "HEAD"])
}

#[test]
fn branch_and_packed_ref_changes_keep_their_rebuild_inputs() {
    let directory = Directory::new();
    let root = &directory.0;
    let first = repository(root);
    let initial = git_metadata(&root.join("crates/box"));
    assert_eq!(initial.commit.as_deref(), Some(first.as_str()));
    assert!(initial.watched_paths.contains(&root.join(".git/HEAD")));
    assert!(initial.watched_paths.contains(&root.join(".git/refs")));

    git(root, &["pack-refs", "--all"]);
    let packed = git_metadata(&root.join("crates/box"));
    assert_eq!(packed.commit.as_deref(), Some(first.as_str()));
    assert!(
        packed
            .watched_paths
            .contains(&root.join(".git/packed-refs"))
    );
    assert!(packed.watched_paths.contains(&root.join(".git/refs")));

    git(root, &["commit", "--allow-empty", "-m", "next"]);
    let next = git(root, &["rev-parse", "HEAD"]);
    assert_ne!(first, next);
    assert_eq!(
        git_metadata(&root.join("crates/box")).commit.as_deref(),
        Some(next.as_str())
    );
}

#[test]
fn detached_checkout_uses_its_head() {
    let directory = Directory::new();
    let root = &directory.0;
    let first = repository(root);
    git(root, &["commit", "--allow-empty", "-m", "next"]);
    let next = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "--detach", &first]);
    assert_eq!(
        git_metadata(&root.join("crates/box")).commit.as_deref(),
        Some(first.as_str())
    );
    git(root, &["checkout", "--detach", &next]);
    assert_eq!(
        git_metadata(&root.join("crates/box")).commit.as_deref(),
        Some(next.as_str())
    );
}

#[test]
fn worktree_uses_its_head_and_tracks_shared_refs() {
    let directory = Directory::new();
    let root = directory.0.join("main");
    let first = repository(&root);
    git(&root, &["branch", "linked", &first]);
    git(&root, &["commit", "--allow-empty", "-m", "main next"]);
    let worktree = directory.0.join("linked");
    git(
        &root,
        &["worktree", "add", worktree.to_str().unwrap(), "linked"],
    );
    std::fs::create_dir_all(worktree.join("crates/box")).unwrap();
    let metadata = git_metadata(&worktree.join("crates/box"));
    assert_eq!(metadata.commit.as_deref(), Some(first.as_str()));
    assert!(metadata.watched_paths.contains(&worktree.join(".git")));
    assert!(metadata.watched_paths.contains(&root.join(".git/refs")));
    assert!(
        metadata
            .watched_paths
            .contains(&root.join(".git/worktrees/linked/HEAD"))
    );
    assert!(
        metadata
            .watched_paths
            .contains(&root.join(".git/worktrees/linked/commondir"))
    );
    git(&worktree, &["commit", "--allow-empty", "-m", "linked next"]);
    let next = git(&worktree, &["rev-parse", "HEAD"]);
    assert_ne!(first, next);
    assert_eq!(
        git_metadata(&worktree.join("crates/box")).commit.as_deref(),
        Some(next.as_str())
    );
}

#[test]
fn source_archives_do_not_inherit_an_enclosing_repository() {
    let directory = Directory::new();
    repository(&directory.0);
    for manifest in [
        directory.0.join("archive/crates/box"),
        directory.0.join("vendor/strands-box"),
    ] {
        std::fs::create_dir_all(&manifest).unwrap();
        assert_eq!(git_metadata(&manifest).commit, None);
    }
}

#[test]
fn repository_environment_cannot_redirect_metadata() {
    if let Some(manifest) = std::env::var_os("BOX_METADATA_TEST_MANIFEST") {
        let expected = std::env::var("BOX_METADATA_TEST_COMMIT").unwrap();
        assert_eq!(
            git_metadata(Path::new(&manifest)).commit.as_deref(),
            (!expected.is_empty()).then_some(expected.as_str())
        );
        return;
    }
    let directory = Directory::new();
    let own = directory.0.join("own");
    let expected = repository(&own);
    let foreign = directory.0.join("foreign");
    repository(&foreign);
    git(&foreign, &["commit", "--allow-empty", "-m", "foreign next"]);
    assert_ne!(expected, git(&foreign, &["rev-parse", "HEAD"]));
    let archive = foreign.join("archive/crates/box");
    std::fs::create_dir_all(&archive).unwrap();
    for (manifest, commit) in [(own.join("crates/box"), expected), (archive, String::new())] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "repository_environment_cannot_redirect_metadata"])
            .env("BOX_METADATA_TEST_MANIFEST", manifest)
            .env("BOX_METADATA_TEST_COMMIT", commit)
            .env("GIT_DIR", foreign.join(".git"))
            .env("GIT_WORK_TREE", &foreign)
            .env("GIT_COMMON_DIR", foreign.join(".git"))
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.worktree")
            .env("GIT_CONFIG_VALUE_0", &foreign)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "metadata probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn invalid_head_does_not_produce_a_commit() {
    let directory = Directory::new();
    repository(&directory.0);
    std::fs::write(directory.0.join(".git/HEAD"), "not a commit\n").unwrap();
    let metadata = git_metadata(&directory.0.join("crates/box"));
    assert_eq!(metadata.commit, None);
    assert!(
        metadata
            .watched_paths
            .contains(&directory.0.join(".git/HEAD"))
    );
}

#[test]
fn unavailable_worktree_head_still_tracks_recovery() {
    let directory = Directory::new();
    let root = directory.0.join("main");
    let first = repository(&root);
    let worktree = directory.0.join("linked");
    git(
        &root,
        &["worktree", "add", "--detach", worktree.to_str().unwrap()],
    );
    std::fs::create_dir_all(worktree.join("crates/box")).unwrap();
    let head = root.join(".git/worktrees/linked/HEAD");
    std::fs::write(&head, "not a commit\n").unwrap();
    let metadata = git_metadata(&worktree.join("crates/box"));
    assert_eq!(metadata.commit, None);
    assert!(metadata.watched_paths.contains(&head));
    std::fs::write(&head, format!("{first}\n")).unwrap();
    assert_eq!(
        git_metadata(&worktree.join("crates/box")).commit.as_deref(),
        Some(first.as_str())
    );
}
