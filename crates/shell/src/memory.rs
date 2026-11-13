//! A write into the Shell's own filesystem, which lands before the writer sees it accepted.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use strands_shell::os::{Fd, FdKind, Kernel as _, OpenFlags, Process};
use strands_shell::vfs::{InodeData, LASH_GID, LASH_UID, Vfs};
use strands_shell::vfs_kernel::VfsKernel;

/// The channel depth of one writer, in chunks.
const WRITER_DEPTH: usize = 16;

fn permission_denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "permission denied")
}

/// Refuse a create in a parent the Shell's user cannot write.
fn check_parent_write(vfs: &Vfs, abs: &str) -> io::Result<()> {
    let parent = match abs.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &abs[..index],
    };
    if let Ok(parent) = vfs.resolve(parent, true)
        && !vfs.check_permission(parent, LASH_UID, LASH_GID, 2)
    {
        return Err(permission_denied());
    }
    Ok(())
}

/// Open `abs`; a write-only open of a regular file is served here and every other open by the
/// Shell's own kernel.
pub(super) async fn open(
    memory: &VfsKernel,
    proc: &mut Process,
    abs: &str,
    flags: OpenFlags,
) -> io::Result<Fd> {
    if !flags.write || flags.read {
        return memory.open(proc, abs, flags).await;
    }
    let mut vfs = memory.vfs.lock().await;
    let ino = match vfs.resolve(abs, true) {
        Ok(ino) => {
            if !matches!(vfs.get(ino)?.data, InodeData::File(_)) {
                drop(vfs);
                return memory.open(proc, abs, flags).await;
            }
            if !vfs.check_permission(ino, LASH_UID, LASH_GID, 2) {
                return Err(permission_denied());
            }
            ino
        }
        Err(error) => {
            if !flags.create {
                return Err(error);
            }
            check_parent_write(&vfs, abs)?;
            vfs.create_file(abs, 0o644, LASH_UID, LASH_GID)?
        }
    };
    let cap = vfs.max_file_size;
    if flags.append {
        let held = vfs.read_file(ino)?.len();
        if cap > 0 && held >= cap {
            return Err(io::Error::other("file size limit exceeded"));
        }
    } else {
        vfs.write_file(ino, Vec::new())?;
    }
    drop(vfs);
    let (tx, rx) = strands_shell::os::pipe(WRITER_DEPTH);
    let failed = Arc::new(AtomicBool::new(false));
    let fd = proc.alloc_fd(FdKind::ChannelWriter {
        tx,
        error_flag: Some(Arc::clone(&failed)),
    })?;
    tokio::task::spawn_local(drain(
        Arc::clone(&memory.vfs),
        ino,
        rx,
        failed,
        flags.append,
    ));
    Ok(fd)
}

/// Write each chunk as it arrives at this writer's own position, or at the end for an append,
/// keeping the prefix that fits under the cap.
async fn drain(
    vfs: Arc<tokio::sync::Mutex<Vfs>>,
    ino: strands_shell::vfs::Ino,
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    failed: Arc<AtomicBool>,
    append: bool,
) {
    let mut position = 0;
    while let Some(chunk) = rx.recv().await {
        let mut vfs = match vfs.try_lock() {
            Ok(vfs) => vfs,
            Err(_) => vfs.lock().await,
        };
        let cap = vfs.max_file_size;
        let Ok(inode) = vfs.get_mut(ino) else {
            failed.store(true, Ordering::Relaxed);
            return;
        };
        let InodeData::File(data) = &mut inode.data else {
            failed.store(true, Ordering::Relaxed);
            return;
        };
        if append {
            position = data.len();
        }
        let fits = if cap > 0 {
            cap.saturating_sub(position).min(chunk.len())
        } else {
            chunk.len()
        };
        let end = position + fits;
        if data.len() < position {
            data.resize(position, 0);
        }
        let overlap = data.len().min(end);
        data[position..overlap].copy_from_slice(&chunk[..overlap - position]);
        data.extend_from_slice(&chunk[overlap - position..fits]);
        inode.mtime = std::time::SystemTime::now();
        position = end;
        if fits < chunk.len() {
            failed.store(true, Ordering::Relaxed);
            return;
        }
    }
}
