//! The box's half of a masked-`/proc` refusal: name the `box.toml` key that opts in.
//!
//! The containment crate names the cause in its own vocabulary (`ProcessInfoMode::AllowAll`), and
//! its message is the evidence: a host that masks `/proc` also carries unrelated mounts under it
//! (`binfmt_misc`), so a mount table alone would point every refusal at the key. The agent's
//! message reaches the operator's terminal and never the box, so for the agent the box asks the
//! kernel the same question containment did. The mount-table parser is a deliberate copy of
//! `masked_proc_points` in the containment crate's Linux view, and [`CONTAINMENT_MARKER`] of its
//! wording: both are private to a module this crate cannot reach.

use std::path::Path;

use crate::error::SetupStage;

/// The words containment's masked-`/proc` refusal carries (`MASKED_PROC_MARKER` there).
const CONTAINMENT_MARKER: &str = "masks parts of /proc";

/// What a masked-`/proc` refusal gains on the box's side.
pub(crate) const HINT: &str = "set [containment] private_proc = false in box.toml to reuse this \
                               container's /proc; the workload can then list the container's \
                               processes";

/// The detail an `Apply` failure should carry, with the hint added when this box asked for a
/// private `/proc` and was refused one because the host masks it. Every other failure passes
/// through unchanged.
pub(crate) fn hint(stage: SetupStage, detail: Option<String>, shares_proc: bool) -> Option<String> {
    if !cfg!(target_os = "linux") {
        return detail;
    }
    let table = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    hint_with(stage, detail, shares_proc, &table, fresh_procfs_refused)
}

fn hint_with(
    stage: SetupStage,
    detail: Option<String>,
    shares_proc: bool,
    table: &str,
    fresh_procfs_refused: impl FnOnce() -> bool,
) -> Option<String> {
    if stage != SetupStage::Apply || shares_proc || !host_masks_proc(table) {
        return detail;
    }
    let refused_for_the_masks = match &detail {
        Some(detail) => detail.contains(CONTAINMENT_MARKER),
        None => fresh_procfs_refused(),
    };
    if !refused_for_the_masks {
        return detail;
    }
    Some(match detail {
        Some(detail) => format!("{detail}; {HINT}"),
        None => HINT.to_string(),
    })
}

/// Whether the kernel refuses this process a fresh procfs in a new user and PID namespace: the
/// refusal containment met. It forks twice, because the kernel refuses a procfs for a PID namespace
/// the caller is not in, and `unshare` of a user namespace refuses a threaded caller.
#[cfg(target_os = "linux")]
fn fresh_procfs_refused() -> bool {
    // SAFETY: the child makes raw syscalls and `_exit`s only, so the parent's other threads and
    // their locks are never touched in it.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        // SAFETY: syscall-only child, as above.
        unsafe {
            let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if libc::unshare(namespaces) != 0 {
                libc::_exit(1);
            }
            let inner = libc::fork();
            if inner < 0 {
                libc::_exit(1);
            }
            if inner == 0 {
                let fstype = c"proc".as_ptr();
                let refused = libc::mount(fstype, c"/proc".as_ptr(), fstype, 0, std::ptr::null())
                    != 0
                    && *libc::__errno_location() == libc::EPERM;
                libc::_exit(if refused { 0 } else { 1 });
            }
            let mut status = 0;
            libc::waitpid(inner, &mut status, 0);
            libc::_exit(
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    0
                } else {
                    1
                },
            );
        }
    }
    let mut status = 0;
    // SAFETY: waiting on this process's own child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[cfg(not(target_os = "linux"))]
fn fresh_procfs_refused() -> bool {
    false
}

/// Whether a mount table carries a mount strictly under `/proc`: a container runtime's masks.
fn host_masks_proc(table: &str) -> bool {
    table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(Path::new)
        .any(|point| point != Path::new("/proc") && point.starts_with("/proc"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASKED: &str = "proc /proc proc rw 0 0\ntmpfs /proc/kcore tmpfs rw 0 0\n";
    const CLEAN: &str = "proc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n";

    #[test]
    fn a_masked_table_is_recognised_and_a_clean_one_is_not() {
        assert!(host_masks_proc(MASKED));
        assert!(!host_masks_proc(CLEAN));
        assert!(!host_masks_proc("tmpfs /procfoo tmpfs rw 0 0\n"));
    }

    const REFUSAL: &str = "view: this host masks parts of /proc (/proc/kcore), so ...";

    #[test]
    fn the_hint_is_added_only_to_an_apply_failure_of_a_private_proc_box_on_a_masked_host() {
        let with = |stage, detail: Option<&str>, shares, table| {
            hint_with(stage, detail.map(str::to_string), shares, table, || true)
        };
        let added = with(SetupStage::Apply, Some(REFUSAL), false, MASKED).unwrap();
        assert!(added.starts_with(&format!("{REFUSAL}; ")), "{added}");
        assert!(added.ends_with(HINT), "{added}");
        assert_eq!(
            with(SetupStage::Apply, None, false, MASKED).as_deref(),
            Some(HINT)
        );
        assert_eq!(
            with(SetupStage::Apply, Some(REFUSAL), true, MASKED).as_deref(),
            Some(REFUSAL)
        );
        assert_eq!(
            with(SetupStage::Apply, Some(REFUSAL), false, CLEAN).as_deref(),
            Some(REFUSAL)
        );
        assert_eq!(
            with(SetupStage::Exec, Some(REFUSAL), false, MASKED).as_deref(),
            Some(REFUSAL)
        );
    }

    /// A masked host also has unrelated mounts under `/proc` (`binfmt_misc`), so a refusal that is
    /// not containment's masked-`/proc` one must not be pointed at the key.
    #[test]
    fn an_unrelated_apply_failure_on_a_masked_host_gets_no_hint() {
        let other = Some("view: grant /opt/tool: No such file or directory".to_string());
        assert_eq!(
            hint_with(SetupStage::Apply, other.clone(), false, MASKED, || true),
            other
        );
    }

    /// The agent's refusal reached the terminal, not the box, so the box asks the kernel itself.
    #[test]
    fn a_detailless_failure_gets_the_hint_only_when_a_fresh_procfs_is_refused() {
        assert_eq!(
            hint_with(SetupStage::Apply, None, false, MASKED, || false),
            None
        );
        assert_eq!(
            hint_with(SetupStage::Apply, None, false, MASKED, || true).as_deref(),
            Some(HINT)
        );
    }

    #[test]
    fn the_marker_is_the_containment_crate_wording() {
        assert_eq!(CONTAINMENT_MARKER, "masks parts of /proc");
    }

    #[test]
    fn the_hint_names_the_key_exactly() {
        assert_eq!(
            HINT,
            "set [containment] private_proc = false in box.toml to reuse this container's /proc; \
             the workload can then list the container's processes"
        );
    }
}
