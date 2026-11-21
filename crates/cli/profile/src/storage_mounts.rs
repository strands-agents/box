//! Keep paths that depend on an incoming mount intact until Box Core captures its source.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Whether resolving `path` reaches an incoming root, without inspecting that root's contents.
pub(crate) fn depends(path: &Path, roots: &[PathBuf]) -> bool {
    if roots.is_empty() || !path.is_absolute() {
        return false;
    }
    if roots.iter().any(|root| path.starts_with(root)) {
        return true;
    }
    let mut pending: VecDeque<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let mut current = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        match Path::new(&part).components().next() {
            Some(Component::RootDir) => current.push(Path::new("/")),
            Some(Component::CurDir) => continue,
            Some(Component::ParentDir) => {
                current.pop();
            }
            Some(Component::Normal(name)) => current.push(name),
            _ => return false,
        }
        if roots.iter().any(|root| current.starts_with(root)) {
            return true;
        }
        if !std::fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.is_symlink()) {
            continue;
        }
        let Ok(target) = std::fs::read_link(&current) else {
            return false;
        };
        links += 1;
        if links > 40 {
            return false;
        }
        current.pop();
        for component in target.components().rev() {
            pending.push_front(component.as_os_str().to_os_string());
        }
    }
    false
}
