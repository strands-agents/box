//! The Core checkout identity and the Git files that can change it.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Default)]
pub(crate) struct GitMetadata {
    pub(crate) commit: Option<String>,
    pub(crate) watched_paths: Vec<PathBuf>,
}

pub(crate) fn git_metadata(manifest_dir: &Path) -> GitMetadata {
    let mut metadata = GitMetadata::default();
    let Ok(manifest_dir) = manifest_dir.canonicalize() else {
        return metadata;
    };
    let Some(root) = manifest_dir.parent().and_then(Path::parent) else {
        return metadata;
    };
    if root.join("crates/box") != manifest_dir {
        return metadata;
    }
    let marker = root.join(".git");
    if marker.is_file() {
        let git_dir = std::fs::read_to_string(&marker).ok().and_then(|pointer| {
            let path = pointer
                .trim_end_matches(['\r', '\n'])
                .strip_prefix("gitdir: ")?;
            (!path.is_empty()).then(|| root.join(path))
        });
        if let Some(git_dir) = git_dir {
            metadata
                .watched_paths
                .push(git_dir.canonicalize().unwrap_or(git_dir).join("HEAD"));
        }
        metadata.watched_paths.push(marker);
    } else if marker.is_dir() {
        metadata.watched_paths.push(marker.join("HEAD"));
    } else {
        return metadata;
    }
    let owns_checkout = git(root, &["rev-parse", "--show-toplevel"])
        .and_then(|path| PathBuf::from(path).canonicalize().ok())
        .is_some_and(|top| top == root);
    if !owns_checkout {
        return metadata;
    }
    let Some(paths) = git(
        root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "HEAD",
            "--git-path",
            "refs",
            "--git-path",
            "packed-refs",
            "--git-path",
            "commondir",
            "--git-path",
            "reftable",
        ],
    ) else {
        return metadata;
    };
    metadata.watched_paths.extend(
        paths
            .lines()
            .map(PathBuf::from)
            .filter(|path| path.exists()),
    );
    metadata.watched_paths.sort();
    metadata.watched_paths.dedup();
    metadata.commit = git(root, &["rev-parse", "--verify", "HEAD^{commit}"])
        .filter(|commit| valid_commit(commit));
    metadata
}

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(arguments);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8(output.stdout)
            .ok()?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    )
}

fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::valid_commit;

    #[test]
    fn commit_identifiers_require_full_lowercase_hex() {
        assert!(valid_commit("0123456789abcdef0123456789abcdef01234567"));
        for value in [
            "",
            "0123456",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "0123456789abcdef0123456789abcdef0123456g",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789abcdef0123456789abcdef01234567\n",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(!valid_commit(value), "accepted {value:?}");
        }
    }
}
