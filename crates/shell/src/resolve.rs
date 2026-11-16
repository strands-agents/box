//! The object a spelling names: symlinks in the Shell's own filesystem followed, and a mount point
//! where that filesystem stops.

use std::io;
use std::ops::ControlFlow;

use strands_shell::vfs::{self, InodeData, Vfs};

use crate::host::Mounts;

/// The most symlinks one resolution follows, as `Vfs::resolve` counts them.
const MAX_SYMLINK_HOPS: u32 = 40;

/// The message `Vfs::resolve` gives for a symlink loop.
const SYMLINK_LOOP: &str = "too many levels of symbolic links";

/// The inode number of the root directory.
const ROOT_INO: vfs::Ino = 1;

/// `path` made absolute against `cwd`, with `.` and `..` folded.
pub(super) fn absolute(cwd: &std::path::Path, path: &str) -> String {
    if path.starts_with('/') {
        vfs::normalize(path)
    } else {
        vfs::normalize(&format!("{}/{}", cwd.display(), path))
    }
}

/// `abs` with every symlink followed, a missing tail kept, and a dangling symlink replaced by the
/// path it names.
pub(super) fn target(vfs: &Vfs, mounts: &Mounts, abs: &str) -> String {
    if vfs
        .resolve(abs, true)
        .is_err_and(|error| error.to_string() == SYMLINK_LOOP)
    {
        return abs.to_string();
    }
    let mut path = abs.to_string();
    for _ in 0..=MAX_SYMLINK_HOPS {
        match existing_prefix(vfs, mounts, &path) {
            ControlFlow::Break(resolved) => return resolved,
            ControlFlow::Continue(named) => path = named,
        }
    }
    abs.to_string()
}

/// Canonicalize the existing prefix of `abs` and append the missing tail.
fn existing_prefix(vfs: &Vfs, mounts: &Mounts, abs: &str) -> ControlFlow<String, String> {
    let (canonical, consumed) = canonical_prefix(vfs, mounts, abs);
    let normalized = vfs::normalize(abs);
    let mut components = normalized
        .split('/')
        .filter(|component| !component.is_empty())
        .skip(consumed);
    let Some(first) = components.next() else {
        return ControlFlow::Break(canonical);
    };
    let base = canonical.trim_end_matches('/');
    let child = format!("{base}/{first}");
    let dangling = if mounts.serves(&canonical) {
        None
    } else {
        symlink_target(vfs, &child)
    };
    let mut resolved = match &dangling {
        Some(target) if target.starts_with('/') => vfs::normalize(target),
        Some(target) => vfs::normalize(&format!("{base}/{target}")),
        None => child,
    };
    for component in components {
        resolved.push('/');
        resolved.push_str(component);
    }
    match dangling {
        Some(_) => ControlFlow::Continue(resolved),
        None => ControlFlow::Break(resolved),
    }
}

/// The target of the symlink at `path`, when the entry there is one.
fn symlink_target(vfs: &Vfs, path: &str) -> Option<String> {
    let inode = vfs.get(vfs.resolve(path, false).ok()?).ok()?;
    match &inode.data {
        InodeData::Symlink(target) => Some(target.clone()),
        _ => None,
    }
}

/// The canonical form of the longest prefix of `path` that canonicalizes, and how many components
/// of the normalized `path` it holds. A mount point ends the walk.
fn canonical_prefix(vfs: &Vfs, mounts: &Mounts, path: &str) -> (String, usize) {
    let (result, consumed, _) = walk(vfs, mounts, path, 0);
    (format!("/{}", result.join("/")), consumed)
}

fn canonical(vfs: &Vfs, mounts: &Mounts, path: &str, depth: u32) -> io::Result<String> {
    match walk(vfs, mounts, path, depth) {
        (result, _, None) => Ok(format!("/{}", result.join("/"))),
        (_, _, Some(error)) => Err(error),
    }
}

fn walk(
    vfs: &Vfs,
    mounts: &Mounts,
    path: &str,
    depth: u32,
) -> (Vec<String>, usize, Option<io::Error>) {
    if depth > MAX_SYMLINK_HOPS {
        return (Vec::new(), 0, Some(io::Error::other(SYMLINK_LOOP)));
    }
    let path = vfs::normalize(path);
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let mut result: Vec<String> = Vec::new();
    let mut current = ROOT_INO;
    for (consumed, component) in components.iter().enumerate() {
        if !result.is_empty() && mounts.is_mount_point(&format!("/{}", result.join("/"))) {
            let below = io::Error::new(io::ErrorKind::NotADirectory, "not a directory");
            return (result, consumed, Some(below));
        }
        match step(vfs, mounts, current, &result, component, depth) {
            Ok((next, Some(replaced))) => {
                result = replaced;
                current = next;
            }
            Ok((next, None)) => {
                result.push((*component).to_string());
                current = next;
            }
            Err(error) => return (result, consumed, Some(error)),
        }
    }
    (result, components.len(), None)
}

/// Resolve `component` under `current`, whose canonical components are `result`.
fn step(
    vfs: &Vfs,
    mounts: &Mounts,
    current: vfs::Ino,
    result: &[String],
    component: &str,
    depth: u32,
) -> io::Result<(vfs::Ino, Option<Vec<String>>)> {
    let inode = vfs.get(current)?;
    let InodeData::Dir(entries) = &inode.data else {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        ));
    };
    let child_ino = *entries
        .get(component)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file or directory"))?;
    let child = vfs.get(child_ino)?;
    let InodeData::Symlink(link) = &child.data else {
        return Ok((child_ino, None));
    };
    let base = format!("/{}", result.join("/"));
    let resolved = if link.starts_with('/') {
        vfs::normalize(link)
    } else {
        vfs::normalize(&format!("{base}/{link}"))
    };
    let canonical = canonical(vfs, mounts, &resolved, depth + 1)?;
    let next = vfs.resolve(&canonical, true)?;
    let components = canonical
        .split('/')
        .filter(|c| !c.is_empty())
        .map(String::from)
        .collect();
    Ok((next, Some(components)))
}
