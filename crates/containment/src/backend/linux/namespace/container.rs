//! Preconditions for a container-provided PID namespace.

use super::apply_failure;
use crate::error::ContainmentError;

pub(super) fn require_private_init() -> Result<(), ContainmentError> {
    // SAFETY: these calls only read this process's identity.
    let (pid, parent, uid, euid) = unsafe {
        (
            libc::getpid(),
            libc::getppid(),
            libc::getuid(),
            libc::geteuid(),
        )
    };
    if pid != 1 || parent != 0 || uid == 0 || uid != euid {
        return Err(apply_failure(
            "container launcher must be non-root, private PID 1".into(),
        ));
    }
    let read_error = |error| apply_failure(format!("checking container PID boundary: {error}"));
    let own = std::fs::read_link("/proc/self").map_err(read_error)?;
    if own != std::path::Path::new("1") {
        return Err(apply_failure(
            "procfs does not describe the launcher's PID namespace".into(),
        ));
    }
    let processes = std::fs::read_dir("/proc").map_err(read_error)?;
    for entry in processes {
        let name = entry.map_err(read_error)?.file_name();
        if let Some(name) = name.to_str()
            && name.parse::<u32>().is_ok()
            && name != "1"
        {
            return Err(apply_failure(
                "container PID namespace contains another process".into(),
            ));
        }
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(read_error)?;
    for (field, expected) in [
        ("Threads:", "1"),
        ("NoNewPrivs:", "1"),
        ("CapInh:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapEff:", "0000000000000000"),
        ("CapBnd:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        if status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map(str::trim)
            != Some(expected)
        {
            return Err(apply_failure(format!(
                "container launcher requires {field} {expected}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ordinary_process_cannot_borrow_procfs() {
        assert!(super::require_private_init().is_err());
    }
}
