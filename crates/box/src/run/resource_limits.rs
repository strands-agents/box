//! The box workload's cgroup: one cgroup v2 leaf that caps every process the box starts.
//!
//! | Kernel setting | Set from |
//! |---|---|
//! | `pids.max` | `limits.processes` |
//! | `memory.max` | `limits.memory` |
//! | `memory.swap.max = 0` | Box, whenever `limits.memory` is set |
//! | `memory.oom.group = 1` | Box, whenever `limits.memory` is set |

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::ConfigError;
use crate::record::config::filesystem::DirectGrant;
use crate::record::config::limits::ResourceLimits;

/// Where Box looks for the cgroup v2 hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The prefix of each leaf Box creates; the trusted process's own pid follows it.
const LEAF_PREFIX: &str = "strands-box-";

/// The open `cgroup.procs` of this process's box leaf, which every contained spawn joins.
static JOIN: Mutex<Option<Arc<File>>> = Mutex::new(None);

/// Why this host cannot enforce the box's resource limits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unenforceable {
    #[error(
        "{CGROUP_ROOT} is not a cgroup v2 file system. Box enforces resource limits only with \
         cgroup v2, the default on current Linux distributions; remove the key on this host"
    )]
    NotCgroupV2,
    #[error(
        "{CGROUP_ROOT} is mounted read-only, as a container usually mounts it. Give the box a \
         writable, delegated cgroup v2 tree, or remove the key and rely on the container's own limits"
    )]
    ReadOnly,
    #[error(
        "this process's cgroup `{own}` is not inside a cgroup subtree that systemd delegates to \
         user {uid} (no `user@{uid}.service` ancestor), as in an SSH or service session. Start the \
         box in a delegated scope, for example `systemd-run --user --scope -- strands-box run ...`, \
         or remove the key"
    )]
    NotDelegated { own: String, uid: u32 },
    #[error(
        "the delegated cgroup `{base}` does not enable the `{controller}` controller for its \
         children (its cgroup.subtree_control holds `{enabled}`). Ask the administrator to \
         delegate `{controller}` to user sessions, or remove the key"
    )]
    Controller {
        base: String,
        controller: &'static str,
        enabled: String,
    },
    #[error(
        "this host has active swap but no `memory.swap.max`, so the memory cap could be passed \
         through swap. Enable swap accounting, turn swap off, or remove `limits.memory`"
    )]
    NoSwapControl,
    #[error("{action} `{path}` failed: {cause}")]
    Io {
        action: &'static str,
        path: String,
        cause: String,
    },
}

impl Unenforceable {
    fn io(action: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.display().to_string(),
            cause: source.to_string(),
        }
    }
}

/// One box's cgroup, created before its workload starts and removed after the workload ends.
#[derive(Debug)]
pub(crate) struct WorkloadCgroup {
    path: PathBuf,
    limits: ResourceLimits,
}

impl WorkloadCgroup {
    /// Create this box's cgroup and make every later contained spawn join it.
    pub(crate) fn create(limits: ResourceLimits) -> Result<Self, Unenforceable> {
        let root = Path::new(CGROUP_ROOT);
        mounted_writable_cgroup2(root)?;
        let own = std::fs::read_to_string("/proc/self/cgroup").map_err(|source| {
            Unenforceable::io("reading", Path::new("/proc/self/cgroup"), source)
        })?;
        // SAFETY: getuid has no failure mode and touches no memory.
        let uid = unsafe { libc::getuid() };
        let base = delegated_base(root, &own, uid, &limits)?;
        sweep_stale_leaves(&base);
        let path = base.join(format!("{LEAF_PREFIX}{}", std::process::id()));
        std::fs::create_dir(&path)
            .map_err(|source| Unenforceable::io("creating", &path, source))?;
        let cgroup = Self { path, limits };
        cgroup.write_limits()?;
        let procs = cgroup.path.join("cgroup.procs");
        let join = std::fs::OpenOptions::new()
            .write(true)
            .open(&procs)
            .map_err(|source| Unenforceable::io("opening", &procs, source))?;
        *JOIN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(join));
        Ok(cgroup)
    }

    fn write_limits(&self) -> Result<(), Unenforceable> {
        if let Some(memory) = self.limits.memory {
            match self.write("memory.swap.max", "0") {
                Err(Unenforceable::Io { .. }) if !self.path.join("memory.swap.max").exists() => {
                    if swap_is_active() {
                        return Err(Unenforceable::NoSwapControl);
                    }
                }
                result => result?,
            }
            self.write("memory.max", &memory.to_string())?;
            self.write("memory.oom.group", "1")?;
        }
        if let Some(processes) = self.limits.processes {
            self.write("pids.max", &processes.to_string())?;
        }
        Ok(())
    }

    fn write(&self, knob: &str, value: &str) -> Result<(), Unenforceable> {
        let path = self.path.join(knob);
        std::fs::write(&path, value).map_err(|source| Unenforceable::io("writing", &path, source))
    }

    /// The startup disclosure line.
    pub(crate) fn disclosure(&self) -> String {
        format!(
            "resource limits for the agent, its tools, and its MCP servers together: {} \
             (cgroup {}); the trusted process is outside them",
            self.limits.summary(),
            self.path.display()
        )
    }

    /// Say which cap the workload reached, once it has ended.
    pub(crate) fn report(&self) {
        let counter = |file: &str, key: &str| {
            std::fs::read_to_string(self.path.join(file))
                .ok()
                .and_then(|events| event_count(&events, key))
                .unwrap_or(0)
        };
        if let Some(memory) = self.limits.memory
            && counter("memory.events", "oom_kill") > 0
        {
            ::diagnostics::diag!(
                B1004,
                "the workload reached its memory limit ({}), so the kernel ended the agent, its \
                 tools, and its MCP servers together; raise `limits.memory` if the work needs more",
                crate::record::config::limits::format_bytes(memory.get())
            );
        }
        if let Some(processes) = self.limits.processes {
            let refused = counter("pids.events", "max");
            if refused > 0 {
                ::diagnostics::diag!(
                    B1005,
                    "the workload reached its process limit ({processes}); a process or thread \
                     start failed there {refused} {}. Raise `limits.processes` if the work needs \
                     more",
                    if refused == 1 { "time" } else { "times" }
                );
            }
        }
    }
}

impl Drop for WorkloadCgroup {
    fn drop(&mut self) {
        JOIN.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Every member is the box's own workload, which has already been told to stop. A kernel
        // before 5.14 has no `cgroup.kill`, so each member is killed by its process ID instead.
        if std::fs::write(self.path.join("cgroup.kill"), "1").is_err() {
            for pid in std::fs::read_to_string(self.path.join("cgroup.procs"))
                .unwrap_or_default()
                .lines()
                .filter_map(|pid| pid.parse::<libc::pid_t>().ok())
            {
                // SAFETY: kill takes no pointer; each pid is a member of this box's own cgroup.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        let events = self.path.join("cgroup.events");
        for _ in 0..100 {
            match std::fs::read_to_string(&events) {
                Ok(text) if event_count(&text, "populated") == Some(1) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        if let Err(error) = std::fs::remove_dir(&self.path) {
            ::diagnostics::diag!(
                B1001,
                "could not remove the workload cgroup {}: {error}",
                self.path.display()
            );
        }
    }
}

/// Make `command`'s child join this box's cgroup before it executes, when the box has one.
pub(crate) fn join_in_child(command: &mut tokio::process::Command) {
    use std::os::fd::AsRawFd as _;

    let Some(join) = JOIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    else {
        return;
    };
    // SAFETY: the hook makes one `write` of a static buffer to a descriptor that the closure itself
    // keeps open. Writing `0` moves the writing process, so the child joins before it can start
    // anything.
    unsafe {
        command.pre_exec(move || {
            if libc::write(join.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Refuse a grant through which the workload could leave its cgroup: a write grant on the cgroup
/// file system, or a socket grant on the user's service manager, which starts processes elsewhere.
pub(crate) fn refuse_escaping_grants<'a>(
    mut grants: impl Iterator<Item = (&'a str, &'a DirectGrant)>,
) -> Result<(), ConfigError> {
    // SAFETY: getuid has no failure mode and touches no memory.
    let runtime = PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }));
    match grants.find_map(|(table, grant)| {
        escape(grant.operation, grant.scope, &grant.resolved, &runtime)
            .map(|reason| (table, grant, reason))
    }) {
        Some((table, grant, reason)) => Err(ConfigError::Filesystem {
            table: table.to_string(),
            entry: grant.authored.clone(),
            reason: format!(
                "{reason}, so the workload could move itself out of the cgroup that `[limits]` \
                 caps. Remove the grant, or remove `limits.processes` and `limits.memory`"
            ),
        }),
        None => Ok(()),
    }
}

/// Why a grant of `operation` at `resolved` lets the workload leave its cgroup, if it does.
fn escape(
    operation: containment::Operation,
    scope: containment::Scope,
    resolved: &Path,
    runtime: &Path,
) -> Option<String> {
    let reaches = |target: &Path| {
        resolved.starts_with(target)
            || (scope == containment::Scope::Root && target.starts_with(resolved))
    };
    match operation {
        containment::Operation::Write => reaches(Path::new(CGROUP_ROOT))
            .then(|| format!("it can write the cgroup file system at {CGROUP_ROOT}")),
        containment::Operation::Connect => [runtime.join("systemd"), runtime.join("bus")]
            .iter()
            .any(|socket| reaches(socket))
            .then(|| {
                format!(
                    "it can reach the user's service manager under {}, which starts processes \
                     outside the box's cgroup",
                    runtime.display()
                )
            }),
        _ => None,
    }
}

/// Refuse a cgroup mount Box cannot create a cgroup in.
fn mounted_writable_cgroup2(root: &Path) -> Result<(), Unenforceable> {
    use std::os::unix::ffi::OsStrExt as _;

    const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    let path = std::ffi::CString::new(root.as_os_str().as_bytes())
        .map_err(|_| Unenforceable::NotCgroupV2)?;
    // SAFETY: statfs writes one zeroed local through a valid C string.
    let mut status: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut status) } != 0 {
        return Err(Unenforceable::NotCgroupV2);
    }
    #[allow(clippy::unnecessary_cast)]
    if status.f_type as i64 != CGROUP2_SUPER_MAGIC {
        return Err(Unenforceable::NotCgroupV2);
    }
    // SAFETY: statvfs writes one zeroed local through a valid C string.
    let mut flags: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut flags) } != 0 {
        return Err(Unenforceable::io(
            "inspecting",
            root,
            std::io::Error::last_os_error(),
        ));
    }
    if flags.f_flag & libc::ST_RDONLY != 0 {
        return Err(Unenforceable::ReadOnly);
    }
    Ok(())
}

/// The cgroup that systemd delegates to `uid`, above this process's own, with the controllers the
/// limits need.
fn delegated_base(
    root: &Path,
    proc_self_cgroup: &str,
    uid: u32,
    limits: &ResourceLimits,
) -> Result<PathBuf, Unenforceable> {
    let own = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(Unenforceable::NotCgroupV2)?
        .trim();
    let marker = format!("user@{uid}.service");
    let mut base = root.to_path_buf();
    let mut delegated = false;
    for segment in own.split('/').filter(|segment| !segment.is_empty()) {
        base.push(segment);
        if segment == marker {
            delegated = true;
            break;
        }
    }
    if !delegated {
        return Err(Unenforceable::NotDelegated {
            own: own.to_string(),
            uid,
        });
    }
    let subtree = base.join("cgroup.subtree_control");
    let enabled = std::fs::read_to_string(&subtree)
        .map_err(|source| Unenforceable::io("reading", &subtree, source))?;
    let needed = [
        limits.processes.map(|_| "pids"),
        limits.memory.map(|_| "memory"),
    ];
    if let Some(controller) = needed
        .into_iter()
        .flatten()
        .find(|controller| !enabled.split_whitespace().any(|name| name == *controller))
    {
        return Err(Unenforceable::Controller {
            base: base.display().to_string(),
            controller,
            enabled: enabled.trim().to_string(),
        });
    }
    Ok(base)
}

/// Remove each empty leaf a box that is no longer running left behind.
fn sweep_stale_leaves(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix(LEAF_PREFIX))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != std::process::id() && !Path::new("/proc").join(pid.to_string()).exists() {
            // Only an empty cgroup can be removed, so a leaf with members stays.
            let _ = std::fs::remove_dir(entry.path());
        }
    }
}

/// Whether any swap device or file is in use.
fn swap_is_active() -> bool {
    std::fs::read_to_string("/proc/swaps").map_or(true, |swaps| swaps.lines().count() > 1)
}

/// The value of one `key value` line of a cgroup events file.
fn event_count(events: &str, key: &str) -> Option<u64> {
    events.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == key).then(|| value.trim().parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;

    fn limits(processes: Option<u64>, memory: Option<u64>) -> ResourceLimits {
        ResourceLimits {
            processes: processes.and_then(NonZeroU64::new),
            memory: memory.and_then(NonZeroU64::new),
        }
    }

    /// A cgroup tree whose `user@1000.service` enables `controllers`.
    fn tree(controllers: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let base = root
            .path()
            .join("user.slice/user-1000.slice/user@1000.service");
        std::fs::create_dir_all(base.join("app.slice/run-1.scope")).unwrap();
        std::fs::write(base.join("cgroup.subtree_control"), controllers).unwrap();
        (root, base)
    }

    const IN_A_SCOPE: &str =
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-1.scope\n";

    #[test]
    fn a_delegated_session_resolves_to_its_user_service() {
        let (root, base) = tree("cpu memory pids\n");
        for own in [
            IN_A_SCOPE,
            "0::/user.slice/user-1000.slice/user@1000.service\n",
        ] {
            assert_eq!(
                delegated_base(root.path(), own, 1000, &limits(Some(64), Some(1 << 30))),
                Ok(base.clone()),
                "{own}"
            );
        }
    }

    #[test]
    fn a_session_outside_the_users_delegated_subtree_is_refused_with_the_scope_fix() {
        let (root, _) = tree("memory pids\n");
        for own in [
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/system.slice/amazon-ssm-agent.service\n",
            "0::/\n",
            // Another user's delegated subtree is not this user's.
            "0::/user.slice/user-1001.slice/user@1001.service/app.slice\n",
            // A segment only resembling the marker is not the marker.
            "0::/user.slice/user-1000.slice/xuser@1000.service/app.slice\n",
        ] {
            let refusal =
                delegated_base(root.path(), own, 1000, &limits(Some(64), None)).unwrap_err();
            assert!(
                matches!(refusal, Unenforceable::NotDelegated { .. }),
                "{own}: {refusal}"
            );
            assert!(
                refusal.to_string().contains("systemd-run --user --scope"),
                "{refusal}"
            );
        }
    }

    #[test]
    fn a_cgroup_v1_process_is_refused() {
        let (root, _) = tree("memory pids\n");
        let refusal = delegated_base(
            root.path(),
            "12:pids:/user.slice\n1:name=systemd:/user.slice/session-2.scope\n",
            1000,
            &limits(Some(64), None),
        )
        .unwrap_err();
        assert_eq!(refusal, Unenforceable::NotCgroupV2);
    }

    #[test]
    fn a_missing_controller_names_the_one_the_limit_needs() {
        let (root, _) = tree("cpu memory\n");
        let refusal =
            delegated_base(root.path(), IN_A_SCOPE, 1000, &limits(Some(64), None)).unwrap_err();
        assert!(
            matches!(
                refusal,
                Unenforceable::Controller {
                    controller: "pids",
                    ..
                }
            ),
            "{refusal}"
        );
        // The memory cap alone needs only the memory controller.
        assert!(
            delegated_base(root.path(), IN_A_SCOPE, 1000, &limits(None, Some(1 << 30))).is_ok()
        );
        let (root, _) = tree("pids\n");
        let refusal = delegated_base(
            root.path(),
            IN_A_SCOPE,
            1000,
            &limits(Some(64), Some(1 << 30)),
        )
        .unwrap_err();
        assert!(
            matches!(
                refusal,
                Unenforceable::Controller {
                    controller: "memory",
                    ..
                }
            ),
            "{refusal}"
        );
    }

    #[test]
    fn only_empty_leaves_of_ended_boxes_are_swept() {
        let base = tempfile::tempdir().unwrap();
        // A pid above the kernel's maximum is never alive.
        let stale = base.path().join(format!("{LEAF_PREFIX}4194305"));
        let alive = base
            .path()
            .join(format!("{LEAF_PREFIX}{}", std::process::id()));
        let foreign = base.path().join("app.slice");
        // pid 1 is always alive, so its leaf belongs to a box that may still be running.
        let other_alive = base.path().join(format!("{LEAF_PREFIX}1"));
        std::fs::create_dir(&other_alive).unwrap();
        let stale_with_members = base.path().join(format!("{LEAF_PREFIX}4194306"));
        for directory in [&stale, &alive, &foreign, &stale_with_members] {
            std::fs::create_dir(directory).unwrap();
        }
        // A regular directory that is not empty stands in for a cgroup that still has members.
        std::fs::write(stale_with_members.join("member"), "").unwrap();
        sweep_stale_leaves(base.path());
        assert!(!stale.exists());
        assert!(alive.exists() && foreign.exists() && stale_with_members.exists());
        assert!(other_alive.exists(), "a live box's empty leaf stays");
    }

    #[test]
    fn a_grant_that_reaches_the_cgroup_tree_or_the_service_manager_is_an_escape() {
        use containment::{Operation, Scope};
        let runtime = Path::new("/run/user/1000");
        let escapes = |operation, scope, path: &str| {
            escape(operation, scope, Path::new(path), runtime).is_some()
        };
        // Writing the cgroup tree, inside it or through a directory grant that encloses it.
        assert!(escapes(Operation::Write, Scope::Root, "/sys/fs/cgroup"));
        assert!(escapes(
            Operation::Write,
            Scope::File,
            "/sys/fs/cgroup/user.slice/cgroup.procs"
        ));
        assert!(escapes(Operation::Write, Scope::Root, "/sys"));
        assert!(escapes(Operation::Write, Scope::Root, "/"));
        // A file grant above the tree names only that file, and reading the tree moves nothing.
        assert!(!escapes(Operation::Write, Scope::File, "/sys/fs"));
        assert!(!escapes(Operation::Read, Scope::Root, "/sys/fs/cgroup"));
        assert!(!escapes(Operation::Write, Scope::Root, "/sys/fs/cgroupx"));
        // Connecting to the user's service manager, which starts processes in its own cgroups.
        assert!(escapes(
            Operation::Connect,
            Scope::File,
            "/run/user/1000/bus"
        ));
        assert!(escapes(
            Operation::Connect,
            Scope::File,
            "/run/user/1000/systemd/private"
        ));
        assert!(escapes(Operation::Connect, Scope::Root, "/run/user/1000"));
        assert!(!escapes(
            Operation::Connect,
            Scope::File,
            "/run/user/1000/app.sock"
        ));
        assert!(!escapes(
            Operation::Connect,
            Scope::File,
            "/run/user/1001/bus"
        ));
    }

    #[test]
    fn a_file_system_that_is_not_cgroup_v2_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            mounted_writable_cgroup2(directory.path()),
            Err(Unenforceable::NotCgroupV2)
        );
    }

    #[test]
    fn event_counts_read_whole_keys_only() {
        let events = "low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 1\n";
        assert_eq!(event_count(events, "oom_kill"), Some(2));
        assert_eq!(event_count(events, "max"), Some(12));
        assert_eq!(event_count(events, "oom_killer"), None);
        assert_eq!(event_count("oom_group_kill 1\n", "oom"), None);
        assert_eq!(event_count("max_depth 3\n", "max"), None);
        assert_eq!(event_count("populated 1\nfrozen 0\n", "populated"), Some(1));
    }
}
