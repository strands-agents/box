//! The Linux namespace launcher backend.

pub(crate) mod authority;
pub(crate) mod netns;
pub(crate) mod probe;
pub(crate) mod reaper;
pub(crate) mod refusal;
pub(crate) mod syscall;
pub(crate) mod view;

use crate::ContainmentConfig;
use crate::backend::{ContainmentBackend, SupportInfo};
use crate::error::ContainmentError;
use crate::floors::require_bounded_grant;
use crate::model::{
    BackendOverride, IpcMode, Network, Operation, ProcessInfoMode, Scope, SignalMode,
};
use crate::platform::Platform;

/// This backend's mechanism name, as reported by `SupportInfo` and carried in
/// every `ApplyFailed` it produces.
pub(crate) const MECHANISM: &str = "namespace";

/// Contains a process using Linux namespaces plus a static seccomp filter.
#[derive(Debug)]
pub(crate) struct NamespaceBackend {
    /// Whether this identity may create a user namespace, measured at
    /// construction so `support_info` reports a fact rather than a hope.
    user_namespace_permitted: bool,
}

impl NamespaceBackend {
    /// Measure the host once and build the backend.
    pub(crate) fn new() -> Self {
        Self {
            user_namespace_permitted: probe::user_namespace_is_permitted(),
        }
    }

    /// Build a backend with the probe result supplied, for tests that need to
    /// exercise the unsupported arm on a host that happens to permit namespaces.
    #[cfg(test)]
    fn with_probe_result(user_namespace_permitted: bool) -> Self {
        Self {
            user_namespace_permitted,
        }
    }
}

impl ContainmentBackend for NamespaceBackend {
    fn validate_config(&self, config: &ContainmentConfig) -> Result<(), ContainmentError> {
        // A wrong-mechanism override is a caller error, not a hint: it names a
        // backend whose semantics this one does not implement.
        match config.backend_override() {
            BackendOverride::None => {}
            other => {
                return Err(ContainmentError::UnsupportedCapability {
                    capability: format!("backend override {other:?}"),
                    backend: MECHANISM.to_string(),
                });
            }
        }

        // The namespaces this backend creates deliver isolation unconditionally, so a request for
        // unrestricted reach cannot be honoured -- it would be over-enforced, and the caller would
        // never learn.
        if config.signal_mode() != SignalMode::Isolated {
            return Err(unenforceable(
                "SignalMode::AllowAll: a PID namespace isolates signal delivery \
                 unconditionally, so unrestricted signalling cannot be delivered",
            ));
        }
        if config.process_info_mode() != ProcessInfoMode::Isolated {
            return Err(unenforceable(
                "ProcessInfoMode::AllowAll: the view mounts a fresh /proc, so \
                 host process visibility cannot be delivered",
            ));
        }
        if config.ipc_mode() != IpcMode::SharedMemoryOnly {
            return Err(unenforceable(
                "IpcMode::Full: an IPC namespace separates SysV objects and POSIX \
                 message queues unconditionally",
            ));
        }

        // `AllowAll` is the operator's `contain_egress = false` trust grant: this leaf joins the host
        // network namespace (see `enter_namespaces`) rather than a private, routeless one, so the
        // host's routes are already present and there is nothing to lower here. `Blocked` and
        // `Localhost` are set up in `apply`. The listen-port refusal below still applies to
        // `Localhost`; `AllowAll` carries no listen ports.

        if let Network::Localhost { listen, .. } = config.network()
            && !listen.is_empty()
        {
            return Err(unenforceable(
                "Localhost listen ports: this backend passes one listening \
                 descriptor into the namespace and has no lowering for an \
                 inbound bind",
            ));
        }

        // Breadth before cell.
        for granted in config.authorizations() {
            require_bounded_grant(
                granted,
                config.operator_home(),
                config.credential_store_exempts(granted),
            )?;
        }

        // After breadth, and unreachable through the vocabulary, which refuses the pair: kept as
        // this backend's own last safe point.
        for granted in config.authorizations() {
            if granted.operation == Operation::Exec && granted.scope == Scope::Dir {
                return Err(ContainmentError::UnsupportedCapability {
                    capability: format!(
                        "execute grant on the directory entry '{}': a directory has no bytes to \
                         execute; grant the tree at Root scope or each program at File scope",
                        granted.resolved.display()
                    ),
                    backend: MECHANISM.to_string(),
                });
            }
        }

        require_no_configured_devices(config)?;

        // Refuse a plan that cannot be built before any irreversible step runs.
        view::MountView::plan(config)?;

        // Same for the filter: a request whose filter will not compile must fail
        // here, not after the mount view is live.
        syscall::SyscallPolicy::for_config(config.network()).compile()?;

        Ok(())
    }

    fn apply(
        &self,
        config: &ContainmentConfig,
        egress_handoff: Option<&std::os::unix::net::UnixStream>,
        confirm_fd: Option<std::os::fd::RawFd>,
    ) -> Result<(), ContainmentError> {
        // Repeat live pathname validation at this backend's last safe point, per the
        // `ContainmentBackend` contract.
        config.require_live_path_identities()?;
        require_no_configured_devices(config)?;

        // Build the plan and compile both filters before anything irreversible.
        let view = view::MountView::plan(config)?;
        let filters = syscall::SyscallPolicy::for_config(config.network()).compile()?;

        // --- From here every step is irreversible for this process.

        // `AllowAll` (contain_egress = false) joins the host network namespace; every other mode gets
        // a private, routeless one. Decided before the unshare, which cannot be undone.
        let join_host_network = matches!(config.network(), Network::AllowAll);
        enter_namespaces(join_host_network)?;

        // The egress listener is created *before* the mount view, while the network namespace is
        // new and nothing else has run.
        //
        // One descriptor per granted port, in grant order, because one `recvmsg` carries one
        // descriptor and that order is the wire contract. A socket's network namespace is fixed
        // when the socket is created, so none of them can be bound anywhere else.
        let mut listeners = Vec::new();
        match config.network() {
            Network::Localhost { connect, .. } => {
                // Without a handoff the endpoint would be bound and unreachable: the box could
                // never accept on it, so every request would hang rather than fail.
                let handoff = egress_handoff.ok_or_else(|| {
                    apply_failure(
                        "Network::Localhost needs an egress handoff socket: the \
                         proxy endpoint can only be bound inside the workload's \
                         network namespace, so the listening descriptor has to reach \
                         the box for anything to accept on it"
                            .to_string(),
                    )
                })?;
                netns::bring_up_loopback()?;
                for port in connect {
                    let listener = netns::listen_on_loopback(*port)?;
                    netns::send_descriptor(handoff, &listener)?;
                    listeners.push(listener);
                }
            }
            // `Blocked` gets the namespace and no listener, so there is no route.
            Network::Blocked => {}
            // `AllowAll` joined the host network namespace in `enter_namespaces` (no `CLONE_NEWNET`),
            // so the host's routes are already present: no loopback to bring up and no descriptor to
            // hand off. The mount view and the other namespaces below still apply.
            Network::AllowAll => {}
        };

        // The PID namespace must exist *before* the view is built, because mounting a fresh `/proc`
        // requires the caller to be inside the PID namespace that procfs will describe.
        let mut keep = vec![0, 1, 2];
        let handoff = {
            use std::os::fd::AsRawFd as _;
            keep.extend(listeners.iter().map(|listener| listener.as_raw_fd()));
            // PID 1 sends the seccomp listener over this socket after the workload installs its
            // filter, so it survives PID 1's close; the original caller and the workload close
            // their own copies.
            let handoff = egress_handoff.map(|handoff| handoff.as_raw_fd());
            keep.extend(handoff);
            handoff
        };
        let sync = establish_pid_namespace_and_reaper(&view, &keep, handoff, confirm_fd)?;

        // Only the workload process reaches here, in the pivoted view.
        authority::drop_all_capabilities()?;
        authority::set_no_new_privileges()?;
        install_syscall_filters(&filters, sync)?;

        // Every listener belongs to a relay, and each relay lives in the box.
        drop(listeners);

        Ok(())
    }

    fn support_info(&self) -> SupportInfo {
        let details = if self.user_namespace_permitted {
            "Linux namespaces available (user namespace creation measured)"
        } else {
            "Linux namespace launcher unavailable: this identity may not create a \
             user namespace"
        };

        SupportInfo {
            is_supported: self.user_namespace_permitted,
            platform: Platform::Linux,
            mechanism: MECHANISM.to_string(),
            details: details.to_string(),
        }
    }
}

fn require_no_configured_devices(config: &ContainmentConfig) -> Result<(), ContainmentError> {
    use std::os::unix::fs::MetadataExt as _;

    for granted in config.authorizations() {
        let mode = std::fs::metadata(&granted.resolved)
            .map_err(|source| {
                apply_failure(format!(
                    "reading configured path '{}': {source}",
                    granted.resolved.display()
                ))
            })?
            .mode();
        if is_device_mode(mode) && !is_fixed_device_grant(granted) {
            return Err(ContainmentError::UnsupportedCapability {
                capability: format!(
                    "configured device grant on '{}'",
                    granted.original.display()
                ),
                backend: MECHANISM.to_string(),
            });
        }
    }
    Ok(())
}

fn is_fixed_device_grant(granted: &crate::model::PathGrant) -> bool {
    const FIXED_DEVICES: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];

    granted.original == granted.resolved
        && FIXED_DEVICES
            .iter()
            .any(|device| granted.resolved == std::path::Path::new(device))
}

fn is_device_mode(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFCHR || mode & libc::S_IFMT == libc::S_IFBLK
}

/// Install the observed filter and have PID 1 hand its listener to the box, or fall back to the
/// refusing pair. Either way every refused call is refused; only whether the box sees it differs.
fn install_syscall_filters(
    filters: &syscall::SyscallFilters,
    sync: Option<std::os::fd::OwnedFd>,
) -> Result<(), ContainmentError> {
    let Some(sync) = sync else {
        return install_refusing_filters(filters);
    };
    match refusal::await_plan(&sync) {
        refusal::Plan::Observe => {}
        refusal::Plan::Refuse => return install_refusing_filters(filters),
        refusal::Plan::Broken => {
            return Err(apply_failure(
                "the namespace reaper did not answer the seccomp listener check".to_string(),
            ));
        }
    }
    match attach_with_listener(&filters.observed) {
        Ok(listener) => {
            let forwarded = refusal::announce_listener(&sync, &listener);
            // P1: the workload never keeps the listener; a workload that held it could answer its
            // own refusals.
            drop(listener);
            if forwarded {
                Ok(())
            } else {
                // The observed filter refuses `seccomp`, so nothing can be stacked over it, and with
                // no listener its refusals would answer ENOSYS: refuse the apply rather than start a
                // workload whose refusals differ from the boundary's.
                Err(apply_failure(
                    "the seccomp listener did not reach the box".to_string(),
                ))
            }
        }
        Err(errno) => {
            install_refusing_filters(filters)?;
            refusal::announce_unobserved(&sync, errno);
            Ok(())
        }
    }
}

/// Today's two refusing filters, unchanged.
fn install_refusing_filters(filters: &syscall::SyscallFilters) -> Result<(), ContainmentError> {
    seccompiler::apply_filter(&filters.permit).map_err(|source| {
        apply_failure(format!("installing the namespace permit filter: {source}"))
    })?;
    seccompiler::apply_filter(&filters.restrictions).map_err(|source| {
        apply_failure(format!(
            "installing the namespace restriction filter: {source}"
        ))
    })
}

/// Attach `program` with a listener, or the errno the kernel refused it with. No version probe:
/// the result of the install this needs anyway selects the fallback.
fn attach_with_listener(program: &[seccompiler::sock_filter]) -> Result<std::os::fd::OwnedFd, i32> {
    use std::os::fd::FromRawFd as _;
    let Ok(len) = u16::try_from(program.len()) else {
        return Err(libc::EINVAL);
    };
    // seccompiler's `sock_filter` is `repr(C)` with libc's layout.
    let fprog = libc::sock_fprog {
        len,
        filter: program.as_ptr().cast_mut().cast(),
    };
    // SAFETY: `fprog` points at `program`, which outlives the call. NO_NEW_PRIVS is already set.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }
    // SAFETY: the kernel returned a new descriptor this process owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor as i32) })
}

/// A refusal naming a request this backend cannot lower exactly.
fn unenforceable(capability: &str) -> ContainmentError {
    ContainmentError::UnsupportedCapability {
        capability: capability.to_string(),
        backend: MECHANISM.to_string(),
    }
}

/// Enter the user namespace, then the mount, network, IPC, and UTS namespaces.
fn enter_namespaces(join_host_network: bool) -> Result<(), ContainmentError> {
    // Read the credentials BEFORE the unshare.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    // SAFETY: a single syscall with a constant argument. Irreversible for this
    // process, which is the intent.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(apply_failure(format!(
            "creating a user namespace: {}; this backend reported support, so a \
             failure here means the host's policy changed since the probe",
            std::io::Error::last_os_error()
        )));
    }

    std::fs::write("/proc/self/setgroups", "deny").map_err(|source| {
        apply_failure(format!(
            "denying setgroups: {source}; supplementary-group expansion must be \
             refused before the GID map is written"
        ))
    })?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .map_err(|source| apply_failure(format!("writing the UID map: {source}")))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .map_err(|source| apply_failure(format!("writing the GID map: {source}")))?;

    // One `unshare` for the rest: the kernel applies them atomically, so a partial
    // set is not a state this process can be left in. `CLONE_NEWNET` gives a private, routeless
    // network namespace; `join_host_network` (the operator's `contain_egress = false` trust grant)
    // omits it so the leaf shares the host's network namespace and its routes. Every other namespace
    // still applies, so the grant is network-only.
    let mut remaining = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    if !join_host_network {
        remaining |= libc::CLONE_NEWNET;
    }
    // SAFETY: a single syscall with a constant argument.
    if unsafe { libc::unshare(remaining) } != 0 {
        return Err(apply_failure(format!(
            "creating the mount, IPC, UTS{} namespaces: {}",
            if join_host_network {
                ""
            } else {
                ", and network"
            },
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Enter a PID namespace as its second process, with a reaper at PID 1.
/// The status byte the reaper writes to `confirm_fd` once the mount view is up and the workload is
/// about to run — the explicit "reached exec" signal for a long-lived leaf whose status pipe never
/// EOFs during setup. Must match the supervisor's `SETUP_SUCCESS_BYTE`, and stay distinct from every
/// `SetupStage` failure byte (`1..=5`).
const EXEC_CONFIRM_BYTE: u8 = 0;
/// The failure byte for a mount-view build failure, matching the supervisor's `SetupStage::Apply`.
const APPLY_FAILURE_BYTE: u8 = 3;

/// Write one status byte to `confirm_fd`, ignoring `EINTR`. Best-effort: a lost byte only costs the
/// supervisor its early signal, and the process's own exit still reports the outcome.
fn write_confirm_byte(confirm_fd: Option<std::os::fd::RawFd>, byte: u8) {
    let Some(fd) = confirm_fd else { return };
    loop {
        // SAFETY: `byte` is one readable byte; `fd` is the inherited status writer.
        let written = unsafe { libc::write(fd, (&byte as *const u8).cast::<libc::c_void>(), 1) };
        if written == -1
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        return;
    }
}

/// Returns, in the workload only, the workload's end of the socket it tells PID 1 about its
/// seccomp listener on — `None` when this launch has no box to hand the listener to.
fn establish_pid_namespace_and_reaper(
    view: &view::MountView,
    keep: &[libc::c_int],
    handoff: Option<libc::c_int>,
    confirm_fd: Option<std::os::fd::RawFd>,
) -> Result<Option<std::os::fd::OwnedFd>, ContainmentError> {
    // SAFETY: a single syscall with a constant argument. Affects children only.
    if unsafe { libc::unshare(libc::CLONE_NEWPID) } != 0 {
        return Err(apply_failure(format!(
            "creating a PID namespace: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: forking a process that will become namespace PID 1. The child does
    // only syscall-level work before it either execs the workload or supervises.
    let reaper = unsafe { libc::fork() };
    if reaper == -1 {
        return Err(apply_failure(format!(
            "forking the namespace reaper: {}",
            std::io::Error::last_os_error()
        )));
    }

    if reaper > 0 {
        // The original caller.
        if let Some(descriptor) = handoff {
            // SAFETY: this process only waits from here; the descriptor is PID 1's to send on.
            unsafe { libc::close(descriptor) };
        }
        let mut status: libc::c_int = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(reaper, &mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            125
        };
        // SAFETY: exiting the launcher process with the run's status.
        unsafe { libc::_exit(code) };
    }

    // Namespace PID 1.
    if let Err(error) = view.materialize() {
        // Printed because the reaper cannot return a `Result`: without this, a
        // failure here is only exit 127 and the cause is invisible.
        eprintln!("strands-box: namespace reaper could not build the view: {error}");
        // Signal the failure to the supervisor rather than leaving it to read a bare EOF, which it
        // treats as success. Best-effort, before PID 1 exits and tears down the namespace.
        write_confirm_byte(confirm_fd, APPLY_FAILURE_BYTE);
        // SAFETY: PID 1 exiting kills the namespace, which is the right response to
        // being unable to build the boundary at all.
        unsafe { libc::_exit(127) };
    }

    // The mount view is up and the workload is about to run: signal "reached exec" now. A long-lived
    // leaf (a streaming MCP server) never lets the status pipe EOF during its life — the reaper and
    // the waiter both hold the writer — so the supervisor must be told explicitly, not by EOF.
    write_confirm_byte(confirm_fd, EXEC_CONFIRM_BYTE);

    // Close the reaper's inherited descriptors before forking, so the workload does
    // not inherit them a second time through PID 1.
    if let Err(error) = authority::close_inherited_descriptors(keep) {
        eprintln!("strands-box: namespace reaper could not close descriptors: {error}");
        // SAFETY: as above.
        unsafe { libc::_exit(127) };
    }

    // The socket the workload names its seccomp listener on. PID 1 runs unfiltered and holds the
    // box's end of the relay; the workload, under its own filter, may not `sendmsg`.
    let sync = match handoff {
        Some(_) => match refusal::sync_pair() {
            Ok(pair) => Some(pair),
            Err(error) => {
                eprintln!(
                    "strands-box: namespace reaper could not create the listener socket: {error}"
                );
                // SAFETY: as above.
                unsafe { libc::_exit(127) };
            }
        },
        None => None,
    };

    // Fork the workload.
    let workload = unsafe { libc::fork() };
    if workload == -1 {
        // SAFETY: PID 1 exiting kills the namespace, which is the correct
        // response to being unable to start the workload at all.
        unsafe { libc::_exit(126) };
    }

    if workload > 0 {
        // Still PID 1.
        let reaper_sync = sync.map(|(reaper_end, workload_end)| {
            use std::os::fd::AsRawFd as _;
            // The number stays valid in the workload, which holds its own copy.
            (reaper_end, workload_end.as_raw_fd())
        });
        let dropped = authority::drop_all_capabilities();
        let locked = authority::set_no_new_privileges();
        if dropped.is_err() || locked.is_err() {
            eprintln!(
                "strands-box: namespace reaper could not drop its own authority \
                 ({dropped:?}, {locked:?}); killing the namespace rather than \
                 supervising from a privileged PID 1"
            );
            // The workload is already running with the view, but PID 1 would keep capabilities —
            // the exact escape this closes.
            unsafe { libc::_exit(127) };
        }

        // Hand the workload's seccomp listener to the box, then let go of both sockets: PID 1
        // never answers a notification.
        if let (Some((reaper_end, workload_end)), Some(descriptor)) = (&reaper_sync, handoff) {
            refusal::forward_listener(workload, reaper_end, *workload_end, descriptor);
            // SAFETY: closing PID 1's copy of the relay, which nothing else here uses.
            unsafe { libc::close(descriptor) };
        }

        // Supervise, then exit. Exiting is what makes the kernel terminate every
        // survivor in the namespace.
        let code = reaper::supervise(workload);
        // SAFETY: terminating namespace PID 1.
        unsafe { libc::_exit(code) };
    }

    // The workload process — the only one that returns `Ok`. It holds no copy of the relay: P5.
    if let Some(descriptor) = handoff {
        // SAFETY: closing the workload's inherited copy, which it never uses.
        unsafe { libc::close(descriptor) };
    }
    Ok(sync.map(|(reaper_end, workload_end)| {
        drop(reaper_end);
        workload_end
    }))
}

/// An apply failure carrying this backend's mechanism name.
fn apply_failure(reason: String) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The most `/proc` entries a fresh PID namespace shows before host processes count as visible.
    const MAX_VISIBLE_PIDS_IN_FRESH_NAMESPACE: usize = 8;

    /// The default request shape this backend accepts: every reach mode isolated,
    /// which is also `ContainmentConfig::new`'s default.
    fn acceptable() -> ContainmentConfig {
        ContainmentConfig::new()
    }

    #[test]
    fn support_info_names_the_namespace_mechanism() {
        let info = NamespaceBackend::new().support_info();
        assert_eq!(info.mechanism, "namespace");
        assert_eq!(info.platform, Platform::Linux);
    }

    /// A host that forbids user namespaces must report unsupported, so
    /// `checked_backend` refuses before `apply` can be reached.
    #[test]
    fn a_host_that_forbids_user_namespaces_reports_unsupported() {
        let backend = NamespaceBackend::with_probe_result(false);
        let info = backend.support_info();

        assert!(!info.is_supported);
        assert!(
            info.details.contains("may not create"),
            "the refusal must name its cause: {}",
            info.details
        );
    }

    #[test]
    fn a_host_that_permits_user_namespaces_reports_supported() {
        let info = NamespaceBackend::with_probe_result(true).support_info();
        assert!(info.is_supported);
    }

    /// The default config is exactly what the box builds, minus its grants, so
    /// this is the shape that must validate.
    #[test]
    fn the_default_isolated_request_validates() {
        let backend = NamespaceBackend::with_probe_result(true);
        backend
            .validate_config(&acceptable())
            .expect("the default all-isolated request must validate");
    }

    /// Each unrestricted reach mode is refused rather than over-enforced.
    #[test]
    fn every_unrestricted_reach_mode_is_refused() {
        let backend = NamespaceBackend::with_probe_result(true);

        for (label, config) in [
            ("signal", acceptable().set_signal_mode(SignalMode::AllowAll)),
            (
                "process info",
                acceptable().set_process_info_mode(ProcessInfoMode::AllowAll),
            ),
            ("ipc", acceptable().set_ipc_mode(IpcMode::Full)),
        ] {
            let error = backend.validate_config(&config).expect_err(label);

            assert!(
                matches!(error, ContainmentError::UnsupportedCapability { .. }),
                "{label}: expected an unsupported-capability refusal, got {error:?}"
            );
        }
    }

    /// `AllowAll` is the operator's `contain_egress = false` trust grant: the leaf joins the host
    /// network namespace (no `CLONE_NEWNET`) instead of a private routeless one, so the host's routes
    /// are already present. It validates rather than being refused.
    #[test]
    fn host_network_grant_validates() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .set_network(Network::AllowAll)
            .expect("AllowAll is a valid network to request");

        backend
            .validate_config(&config)
            .expect("AllowAll joins the host network namespace and must validate");
    }

    /// `Localhost` is the network the box actually uses, and it must validate.
    #[test]
    fn proxy_only_validates() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .set_network(Network::localhost().connect(33085))
            .expect("one served localhost port");

        backend
            .validate_config(&config)
            .expect("Localhost is this backend's supported network");
    }

    /// An inbound bind has no lowering, so asking for one is refused rather than silently dropped
    /// -- a dropped bind port would look like a working listener that no one can reach.
    #[test]
    fn a_requested_bind_port_is_refused_rather_than_dropped() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .set_network(Network::localhost().connect(33085).listen(8080))
            .expect("a listen port is a valid request to make");

        let error = backend
            .validate_config(&config)
            .expect_err("a bind port must be refused, not dropped");

        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. }),
            "got {error:?}"
        );
    }

    /// A wrong-mechanism override names a backend whose semantics this one does
    /// not implement.
    #[test]
    fn a_wrong_mechanism_override_is_refused() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable().with_backend_override(BackendOverride::Seatbelt {
            extensions_enabled: false,
        });

        let error = backend
            .validate_config(&config)
            .expect_err("a Seatbelt override must not be accepted here");

        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. }),
            "got {error:?}"
        );
    }

    /// Validation refuses an unbuildable view *before* any irreversible step, so a missing
    /// dependency is a readable refusal rather than a failed `execve` inside an already-pivoted
    /// namespace.
    #[test]
    fn a_grant_whose_view_cannot_be_planned_is_refused_during_validation() {
        let backend = NamespaceBackend::with_probe_result(true);
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("target");
        std::fs::write(&path, b"file").expect("write");

        let config = acceptable()
            .allow(&path, Operation::Read, Scope::File)
            .expect("file grant");

        std::fs::remove_file(&path).expect("remove");
        std::fs::create_dir(&path).expect("mkdir");

        let error = backend
            .validate_config(&config)
            .expect_err("an unplannable view must be refused during validation");

        assert!(
            matches!(error, ContainmentError::ApplyFailed { .. }),
            "got {error:?}"
        );
    }

    /// A directory grant on a system root is refused before anything irreversible.
    #[test]
    fn a_directory_grant_on_a_system_root_is_refused() {
        let backend = NamespaceBackend::with_probe_result(true);

        for root in ["/", "/etc", "/usr", "/home", "/var"] {
            let config = acceptable()
                .allow(root, Operation::Read, Scope::Root)
                .expect("the grant itself is well-formed — that is the point")
                .allow(root, Operation::Write, Scope::Root)
                .expect("the grant itself is well-formed — that is the point");

            let error = backend.validate_config(&config).expect_err(&format!(
                "a read-write subtree grant on '{root}' must be refused"
            ));

            assert!(
                matches!(error, ContainmentError::GrantTooBroad { .. }),
                "'{root}': expected a too-broad refusal, got {error:?}"
            );
        }
    }

    /// A *file* inside a system root is still grantable — the floor bounds subtrees, not individual
    /// files.
    #[test]
    fn a_file_inside_a_system_root_is_still_grantable() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .allow("/bin/sh", Operation::Read, Scope::File)
            .expect("file read grant")
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("file exec grant");

        backend
            .validate_config(&config)
            .expect("a single file inside a system root must remain grantable");
    }

    #[test]
    fn fixed_character_device_grants_are_accepted() {
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .allow("/dev/null", Operation::Read, Scope::File)
            .expect("the vocabulary permits a file grant");
        backend
            .validate_config(&config)
            .expect("the fixed utility device must remain available");
    }

    #[test]
    fn other_configured_character_device_grants_are_refused() {
        let device = std::path::Path::new("/dev/full");
        if !device.exists() {
            println!("skipping: {} is absent on this host", device.display());
            return;
        }
        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .allow(device, Operation::Read, Scope::File)
            .expect("the vocabulary permits a file grant");
        let error = backend
            .validate_config(&config)
            .expect_err("a configured non-scaffold device must fail");
        assert!(matches!(
            error,
            ContainmentError::UnsupportedCapability { .. }
        ));
    }

    #[test]
    fn fixed_utility_devices_remain_in_the_scaffold() {
        let view = view::MountView::plan(&acceptable()).expect("the view plans");
        for device in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"] {
            assert!(view.entries().iter().any(|entry| {
                entry.target == std::path::Path::new(device)
                    && entry.origin == view::MountOrigin::Scaffold
            }));
        }
    }

    #[test]
    fn character_and_block_device_modes_are_classified_as_devices() {
        assert!(is_device_mode(libc::S_IFCHR));
        assert!(is_device_mode(libc::S_IFBLK));
        assert!(!is_device_mode(libc::S_IFREG));
        assert!(!is_device_mode(libc::S_IFDIR));
    }

    /// **An execute grant on a directory entry is refused, and an exec tree validates.** The
    /// vocabulary refuses `Dir`, so this backend's own check never sees one; `Root` plans one
    /// executable read-only bind.
    #[test]
    fn an_execute_grant_at_dir_scope_is_refused_and_an_exec_tree_validates() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("tools");
        std::fs::create_dir(&tree).expect("an exec tree");

        let error = acceptable()
            .allow(&tree, Operation::Exec, Scope::Dir)
            .expect_err("a directory entry has no bytes to execute");
        let text = error.to_string();
        assert!(
            text.contains("Exec at Dir") && text.contains(&tree.display().to_string()),
            "the refusal must name the cell it rejected: {text}"
        );

        let backend = NamespaceBackend::with_probe_result(true);
        let config = acceptable()
            .allow(&tree, Operation::Exec, Scope::Root)
            .expect("an exec tree is a legal cell");
        backend
            .validate_config(&config)
            .expect("an exec tree validates on this backend");
        let view = view::MountView::plan(&config).expect("and plans");
        let entry = view
            .entries()
            .iter()
            .find(|entry| entry.target == tree.canonicalize().expect("canonical"))
            .expect("the tree is bound");
        assert!(entry.executable && !entry.writable);
    }

    /// **`List` and a future-file refusal are refused by name at validation**, before anything
    /// irreversible runs, because this backend has no lowering for either.
    #[test]
    fn the_cells_without_a_lowering_are_refused_by_name_at_validation() {
        let backend = NamespaceBackend::with_probe_result(true);
        let directory = tempfile::tempdir().expect("tempdir");

        let listed = acceptable()
            .allow(directory.path(), Operation::List, Scope::Root)
            .expect("the vocabulary accepts List at Root");
        let error = backend
            .validate_config(&listed)
            .expect_err("List has no lowering in a mount view");
        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. })
                && error.to_string().contains("list grant"),
            "got {error:?}"
        );

        let future = directory.path().join("not-yet-written.env");
        let refused = acceptable()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("a read tree")
            .refuse(&future, Scope::File)
            .expect("the vocabulary accepts a future file");
        let error = backend
            .validate_config(&refused)
            .expect_err("a future file has no overmount target");
        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. })
                && error.to_string().contains("file refusal"),
            "got {error:?}"
        );
    }

    /// The errno `execve` answers for `path` inside the calling process, or 0 when it ran.
    ///
    /// **A file that is not a program tells the mount flag apart.** A no-exec mount answers `EACCES`
    /// before the bytes are looked at; a runnable mount answers `ENOEXEC` after. So no runnable
    /// image has to be in the view for the probe to measure the flag.
    fn execve_errno(path: &std::path::Path) -> i32 {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL");
        let argv = [path.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: every pointer is NUL-terminated and outlives the call; on success the process is
        // replaced, which the file's contents make impossible.
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// **A read tree confers no exec and an exec tree does**, at the kernel.
    #[test]
    fn a_read_tree_confers_no_exec_and_an_exec_tree_does() {
        use std::os::unix::fs::PermissionsExt as _;

        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let read_tree = directory.path().join("read");
        let exec_tree = directory.path().join("exec");
        for tree in [&read_tree, &exec_tree] {
            std::fs::create_dir(tree).expect("a tree");
            let program = tree.join("prog");
            std::fs::write(&program, "not a program").expect("a file that is not a program");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("the execute bits, so only the mount can refuse");
        }
        let config = ContainmentConfig::new()
            .allow(&read_tree, Operation::Read, Scope::Root)
            .expect("a read tree")
            .allow(&exec_tree, Operation::Exec, Scope::Root)
            .expect("an exec tree");
        let read_program = read_tree.join("prog");
        let exec_program = exec_tree.join("prog");

        // SAFETY: the child applies containment and exits; it never returns into test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");
        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if let Err(error) = backend.apply(&config, None, None) {
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }
            let read_answer = execve_errno(&read_program);
            let exec_answer = execve_errno(&exec_program);
            let code = if read_answer != libc::EACCES {
                21
            } else if exec_answer != libc::ENOEXEC {
                22
            } else {
                0
            };
            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "20 = apply failed, 21 = A FILE UNDER A READ TREE WAS NOT REFUSED WITH EACCES, \
             22 = a file under an exec tree was not reached (ENOEXEC expected)"
        );
    }

    /// **A workload marks its own output executable inside the box, and the mount decides whether it
    /// runs.** The sequence is a linker's own: read the file-creation mask, then add the execute bits
    /// that mask leaves. `execve` still answers `EACCES` under a plain writable bind, and reaches the
    /// bytes only where an `exec` list also granted the tree. That pair is what a compiled language's
    /// test step needs: it writes a binary and then runs it.
    ///
    /// `umask` has no failing return, so a refused call reads as a mask of every bit and the mode
    /// change then adds nothing. This test measures the bits, not the call's answer, because that is
    /// the only way the refusal shows.
    #[test]
    fn a_workload_marks_its_own_output_executable_and_only_an_exec_grant_runs_it() {
        use std::os::unix::fs::PermissionsExt as _;

        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let built = directory.path().join("built");
        let runnable = directory.path().join("runnable");
        for tree in [&built, &runnable] {
            std::fs::create_dir(tree).expect("a tree");
            // No execute bit: the workload adds it inside the box, which is the point.
            std::fs::write(tree.join("output"), "not a program").expect("build output");
            std::fs::set_permissions(tree.join("output"), std::fs::Permissions::from_mode(0o644))
                .expect("a plain output file");
        }
        let config = ContainmentConfig::new()
            .allow(&built, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow(&runnable, Operation::Write, Scope::Root)
            .expect("a write root")
            .allow(&runnable, Operation::Exec, Scope::Root)
            .expect("the warned pair");
        let built_output = built.join("output");
        let runnable_output = runnable.join("output");

        // SAFETY: the child applies containment and exits; it never returns into test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");
        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if let Err(error) = backend.apply(&config, None, None) {
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }
            // `fchmodat` by path rather than `fchmod` on a descriptor: a sibling test forks while a
            // write descriptor of this file is open, its child inherits the descriptor, and `execve`
            // then answers `ETXTBSY` instead of the mount's own answer. A path-based `chmod(2)` has
            // no ARM64 number, so `fchmodat` is the spelling the permit table names on both.
            let mark = |path: &std::path::Path| {
                // SAFETY: reading the mask by setting it and setting it back, which is the only way
                // to read it and is what a linker does.
                let mask = unsafe { libc::umask(0) };
                // SAFETY: restoring the value just read.
                unsafe { libc::umask(mask) };
                let current = match std::fs::metadata(path) {
                    Ok(metadata) => metadata.permissions().mode(),
                    Err(error) => {
                        eprintln!("metadata {}: {error}", path.display());
                        return false;
                    }
                };
                let marked = current | (0o111 & !mask);
                let spelled = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                    path.as_os_str(),
                ))
                .expect("no NUL");
                // SAFETY: the pointer is a NUL-terminated string that outlives the call.
                let answered = unsafe {
                    libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, spelled.as_ptr(), marked)
                };
                if answered != 0 {
                    eprintln!(
                        "fchmodat {}: {}",
                        path.display(),
                        std::io::Error::last_os_error()
                    );
                    return false;
                }
                match std::fs::metadata(path) {
                    Ok(meta) => meta.permissions().mode() & 0o111 == 0o111,
                    Err(error) => {
                        eprintln!("metadata {}: {error}", path.display());
                        false
                    }
                }
            };
            // A sibling test in this module forks while a write descriptor of one of these files is
            // briefly open, its child inherits the descriptor, and `execve` then answers `ETXTBSY`
            // rather than the mount's own answer. That is the harness, not containment, so the probe
            // waits for the descriptor to go rather than reading it as a verdict.
            let settled = |path: &std::path::Path| {
                for _ in 0..200 {
                    let answered = execve_errno(path);
                    if answered != libc::ETXTBSY {
                        return answered;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                libc::ETXTBSY
            };
            let code = if !mark(&built_output) {
                21
            } else if settled(&built_output) != libc::EACCES {
                22
            } else if !mark(&runnable_output) {
                23
            } else if settled(&runnable_output) != libc::ENOEXEC {
                24
            } else {
                0
            };
            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "20 = apply failed, 21 = MARKING A WRITABLE BIND'S OUTPUT EXECUTABLE WAS REFUSED, \
             22 = A WRITABLE BIND RAN A FILE IT MUST REFUSE, 23 = marking the exec tree's output \
             executable was refused, 24 = an exec tree did not reach the bytes (ENOEXEC expected)"
        );
    }

    /// **The warned pair holds at the kernel in both nestings.** A write root inside an exec tree
    /// stays writable and runnable; an exec tree inside a write root is writable and runnable while
    /// the rest of the write root stays no-exec.
    #[test]
    fn the_warned_pair_is_writable_and_runnable_at_the_kernel_in_both_nestings() {
        use std::os::unix::fs::PermissionsExt as _;

        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let not_a_program = |path: &std::path::Path| {
            std::fs::write(path, "not a program").expect("a file that is not a program");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("the execute bits, so only the mount can refuse");
        };
        // Shape one: the exec tree encloses the write root.
        let tree = directory.path().join("tools");
        let corner = tree.join("cache");
        std::fs::create_dir_all(&corner).expect("an exec tree with a writable corner");
        not_a_program(&tree.join("prog"));
        not_a_program(&corner.join("prog"));
        // Shape two: the write root encloses the exec tree.
        let project = directory.path().join("project");
        let output = project.join("target");
        std::fs::create_dir_all(&output).expect("a write root with build output");
        not_a_program(&project.join("prog"));
        not_a_program(&output.join("prog"));
        let config = ContainmentConfig::new()
            .allow(&tree, Operation::Exec, Scope::Root)
            .expect("the exec tree")
            .allow(&corner, Operation::Write, Scope::Root)
            .expect("the write root inside it")
            .allow(&project, Operation::Write, Scope::Root)
            .expect("the write root")
            .allow(&output, Operation::Exec, Scope::Root)
            .expect("the exec tree inside it");

        // SAFETY: the child applies containment and exits; it never returns into test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");
        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if let Err(error) = backend.apply(&config, None, None) {
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }
            let writes = |path: &std::path::Path| std::fs::write(path, "written").is_ok();
            let code = if !writes(&corner.join("written")) {
                21
            } else if execve_errno(&corner.join("prog")) != libc::ENOEXEC {
                22
            } else if execve_errno(&tree.join("prog")) != libc::ENOEXEC {
                23
            } else if !writes(&output.join("written")) {
                24
            } else if execve_errno(&output.join("prog")) != libc::ENOEXEC {
                25
            } else if execve_errno(&project.join("prog")) != libc::EACCES {
                26
            } else if !writes(&project.join("written")) {
                27
            } else {
                0
            };
            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "20 = apply failed, 21 = THE WRITE ROOT INSIDE THE EXEC TREE WAS NOT WRITABLE, \
             22 = a file in that write root was not runnable, 23 = a file in the exec tree was not \
             runnable, 24 = THE EXEC TREE INSIDE THE WRITE ROOT WAS NOT WRITABLE, 25 = a file in \
             that exec tree was not runnable, 26 = A FILE IN THE WRITE ROOT OUTSIDE THE EXEC TREE \
             WAS RUNNABLE, 27 = the write root lost its write"
        );
    }

    /// **A refused file reads empty and refuses a write**, while its sibling keeps the tree's reach.
    #[test]
    fn a_refused_file_reads_empty_and_refuses_a_write() {
        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("project");
        std::fs::create_dir(&tree).expect("a project");
        let secret = tree.join(".env");
        let sibling = tree.join("notes.txt");
        std::fs::write(&secret, "TOKEN=1").expect("the refused file");
        std::fs::write(&sibling, "notes").expect("its sibling");
        let config = ContainmentConfig::new()
            .allow(&tree, Operation::Read, Scope::Root)
            .expect("the tree reads")
            .allow(&tree, Operation::Write, Scope::Root)
            .expect("and writes")
            .refuse(&secret, Scope::File)
            .expect("one file refused inside it");

        // SAFETY: the child applies containment and exits; it never returns into test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");
        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if let Err(error) = backend.apply(&config, None, None) {
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }
            let secret_bytes = std::fs::read(&secret);
            let secret_writable = std::fs::OpenOptions::new()
                .write(true)
                .open(&secret)
                .is_ok();
            let sibling_bytes = std::fs::read(&sibling).unwrap_or_default();
            let sibling_writable = std::fs::OpenOptions::new()
                .append(true)
                .open(&sibling)
                .is_ok();
            let code = match secret_bytes {
                Ok(bytes) if !bytes.is_empty() => 21,
                Err(_) => 22,
                Ok(_) if secret_writable => 23,
                Ok(_) if sibling_bytes != b"notes" => 24,
                Ok(_) if !sibling_writable => 25,
                Ok(_) => 0,
            };
            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "20 = apply failed, 21 = THE REFUSED FILE'S BYTES WERE READABLE, 22 = the refused file \
             was absent rather than empty, 23 = THE REFUSED FILE WAS WRITABLE, 24 = the sibling lost \
             its bytes, 25 = the sibling lost its write"
        );
    }

    /// Run `probe` in a forked child with `filter` installed, and answer its exit code.
    fn in_filtered_child(filters: &syscall::SyscallFilters, probe: impl FnOnce() -> i32) -> i32 {
        // SAFETY: the child installs a filter, runs the probe, and `_exit`s; it never
        // returns into test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            if install_syscall_filters(filters, None).is_err() {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(40) };
            }
            let code = probe();
            // SAFETY: terminating the child with the verdict.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "the probe child must exit normally rather than be signalled"
        );
        libc::WEXITSTATUS(status)
    }

    #[test]
    fn the_event_loop_timer_call_is_permitted_under_the_filters() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || {
            // SAFETY: timerfd_create only answers with a descriptor, and the child exits next.
            let fd = unsafe { libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, 0) };
            if fd < 0 {
                return match std::io::Error::last_os_error().raw_os_error() {
                    Some(errno) if errno == libc::EPERM => 10,
                    Some(_) => 11,
                    None => 12,
                };
            }
            // SAFETY: closing the descriptor this child just opened.
            unsafe { libc::close(fd as libc::c_int) };
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = TIMERFD_CREATE WAS REFUSED WITH EPERM, so uSockets' us_create_timer returns \
             null and Bun panics before the agent runs, 11 = refused with another errno, \
             12 = refused with no errno, 40 = installing the filters failed"
        );
    }

    #[test]
    fn permit_and_restriction_filters_refuse_unapproved_calls() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            if libc::syscall(0x7fff_ffff_i64) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 10;
            }
            if libc::syscall(
                libc::SYS_pkey_mprotect,
                std::ptr::null_mut::<libc::c_void>(),
                0,
                libc::PROT_EXEC,
                0,
            ) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 11;
            }
            if libc::syscall(
                libc::SYS_seccomp,
                u32::MAX,
                0,
                std::ptr::null_mut::<libc::c_void>(),
            ) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 12;
            }
            if libc::syscall(libc::SYS_memfd_create, c"w2-probe".as_ptr(), 0) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 13;
            }
            if libc::syscall(
                libc::SYS_execveat,
                -1,
                c"".as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                libc::AT_EMPTY_PATH,
            ) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 14;
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = unnamed call passed, 11 = pkey_mprotect passed, 12 = seccomp passed, \
             13 = memfd_create passed, 14 = execveat AT_EMPTY_PATH passed"
        );
    }

    #[test]
    fn scoped_workload_permits_accept_only_approved_arguments() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            let mut pipe = [-1; 2];
            if libc::pipe2(pipe.as_mut_ptr(), 0) != 0 {
                return 10;
            }
            libc::close(pipe[0]);
            libc::close(pipe[1]);

            if libc::setresgid(!0, !0, !0) != 0 {
                return 11;
            }
            if libc::setresgid(!0, 0, !0) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 12;
            }
            if libc::setresuid(0, 1, 0) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 13;
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = pipe2 refused, 11 = approved setresgid refused, \
             12 = unapproved setresgid passed, 13 = unapproved setresuid passed"
        );
    }

    #[test]
    fn vectored_stdio_write_is_permitted_without_permitting_vectored_read() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            let mut pipe = [-1; 2];
            if libc::pipe2(pipe.as_mut_ptr(), 0) != 0 {
                return 10;
            }
            let first = b"{";
            let second = b"}\n";
            let buffers = [
                libc::iovec {
                    iov_base: first.as_ptr().cast_mut().cast(),
                    iov_len: first.len(),
                },
                libc::iovec {
                    iov_base: second.as_ptr().cast_mut().cast(),
                    iov_len: second.len(),
                },
            ];
            if libc::writev(pipe[1], buffers.as_ptr(), buffers.len() as libc::c_int) != 3 {
                return 11;
            }

            let mut vectored_byte = 0_u8;
            let read_buffer = libc::iovec {
                iov_base: (&raw mut vectored_byte).cast(),
                iov_len: 1,
            };
            if libc::readv(pipe[0], &raw const read_buffer, 1) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 12;
            }

            let mut received = [0_u8; 3];
            if libc::read(pipe[0], received.as_mut_ptr().cast(), received.len()) != 3
                || received != *b"{}\n"
            {
                return 13;
            }
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = pipe2 failed, 11 = writev failed, 12 = readv did not return EPERM, \
             13 = scalar read did not receive the complete payload"
        );
    }

    #[test]
    fn resource_usage_of_self_and_children_passes_both_filters() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) != 0 {
                return 10;
            }
            if usage.ru_maxrss <= 0 {
                return 11;
            }
            if libc::getrusage(libc::RUSAGE_CHILDREN, &raw mut usage) != 0 {
                return 12;
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = getrusage(RUSAGE_SELF) refused, 11 = the usage record was not filled, \
             12 = getrusage(RUSAGE_CHILDREN) refused"
        );
    }

    #[test]
    fn duplicating_a_standard_stream_passes_both_filters() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                let duplicate = libc::dup(descriptor);
                if duplicate < 0 {
                    return 10 + descriptor;
                }
                libc::close(duplicate);
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10, 11, 12 = dup refused on stdin, stdout, stderr; CPython's is_valid_fd() is \
             that call on Linux, and a refusal leaves sys.stdout None"
        );
    }

    #[test]
    fn setting_the_file_mode_mask_passes_both_filters() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            let previous = libc::umask(0);
            if previous == libc::mode_t::MAX {
                return 10;
            }
            if libc::umask(previous) != 0 {
                return 11;
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = umask(0) refused, 11 = the mask read back was not the one just set; pip's \
             current_umask() is that pair, and a refusal fails every wheel install"
        );
    }

    #[test]
    fn setpgid_permits_only_self_group_creation() {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");
        let outcome = in_filtered_child(&filters, || unsafe {
            let inherited_group = libc::getpgid(0);
            if inherited_group == -1 {
                return 10;
            }
            if libc::setpgid(0, inherited_group) != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            {
                return 11;
            }
            if libc::setpgid(0, 0) != 0 {
                return 12;
            }

            let mut pipe = [-1; 2];
            if libc::pipe2(pipe.as_mut_ptr(), 0) != 0 {
                return 13;
            }
            let child = libc::fork();
            if child == -1 {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                return 14;
            }
            if child == 0 {
                libc::close(pipe[1]);
                let mut byte = 0_u8;
                libc::read(pipe[0], (&raw mut byte).cast(), 1);
                libc::close(pipe[0]);
                libc::_exit(0);
            }

            libc::close(pipe[0]);
            let child_process_refused = libc::setpgid(child, 0) == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            libc::close(pipe[1]);
            let mut status = 0;
            let reaped = libc::waitpid(child, &mut status, 0) == child
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0;
            if !reaped {
                return 15;
            }
            if !child_process_refused {
                return 16;
            }
            0
        });
        assert_eq!(
            outcome, 0,
            "10 = getpgid failed, 11 = nonzero group passed, 12 = self group refused, \
             13 = pipe2 failed, 14 = fork failed, 15 = child cleanup failed, \
             16 = child process-group change passed"
        );
    }

    #[test]
    fn every_network_mode_refuses_other_socket_families() {
        for network in [
            Network::Blocked,
            Network::Localhost {
                connect: vec![8080],
                listen: Vec::new(),
            },
            Network::AllowAll,
        ] {
            let filters = syscall::SyscallPolicy::for_config(&network)
                .compile()
                .expect("the filters compile");
            let outcome = in_filtered_child(&filters, || unsafe {
                for family in [libc::AF_UNIX, libc::AF_INET] {
                    let socket = libc::socket(family, libc::SOCK_STREAM, 0);
                    if socket == -1 {
                        return 10;
                    }
                    libc::close(socket);
                }
                if libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                {
                    return 11;
                }
                let mut pair = [-1; 2];
                if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) != 0 {
                    return 12;
                }
                libc::close(pair[0]);
                libc::close(pair[1]);
                for family in [libc::AF_INET, libc::AF_TIPC] {
                    if libc::socketpair(family, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        return 13;
                    }
                }
                0
            });
            assert_eq!(
                outcome, 0,
                "10 = AF_UNIX or AF_INET refused, 11 = another socket family passed, \
                 12 = AF_UNIX socketpair refused, 13 = AF_INET or AF_TIPC socketpair passed"
            );
        }
    }

    /// Whether this host lets the launcher build a mount view at all, measured once.
    fn the_host_can_build_a_view() -> bool {
        static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *USABLE.get_or_init(|| {
            // SAFETY: the child makes syscalls and `_exit`s only — no allocation, no
            // formatting, no panic — per this module's post-fork rule.
            let child = unsafe { libc::fork() };
            if child < 0 {
                // Unmeasurable rather than refused. Let the test run and report its own
                // failure instead of skipping on a probe that never happened.
                return true;
            }

            if child == 0 {
                // SAFETY: syscall-only child.
                unsafe {
                    let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
                    if libc::unshare(namespaces) != 0 {
                        libc::_exit(10);
                    }
                    let inner = libc::fork();
                    if inner < 0 {
                        libc::_exit(12);
                    }
                    if inner == 0 {
                        let fstype = c"proc".as_ptr();
                        let target = c"/proc".as_ptr();
                        if libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0 {
                            libc::_exit(11);
                        }
                        libc::_exit(0);
                    }
                    let mut inner_status = 0;
                    libc::waitpid(inner, &mut inner_status, 0);
                    let mounted =
                        libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
                    libc::_exit(if mounted { 0 } else { 11 });
                }
            }

            let mut status = 0;
            // SAFETY: waiting on this process's own child.
            unsafe { libc::waitpid(child, &mut status, 0) };
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        })
    }

    /// **Route 3 of W^X is closed: writable memory cannot become executable.** A kernel-level
    /// check, because the filter's *effect* is the claim — a rule that compiles but matches the
    /// wrong argument would leave this open while the table still listed the entry.
    #[test]
    fn route_three_write_then_execute_is_refused() {
        if !probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");

        let outcome = in_filtered_child(&filters, || {
            // SAFETY: both calls are plain memory-management syscalls on this child's own
            // address space, and the child `_exit`s without touching the parent's state.
            unsafe {
                let one_call = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if one_call != libc::MAP_FAILED {
                    return 10; // W+X in one call succeeded
                }
                let writable = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if writable == libc::MAP_FAILED {
                    return 11; // a plain writable mapping must still work
                }
                if libc::mprotect(writable, 4096, libc::PROT_READ | libc::PROT_EXEC) == 0 {
                    return 12; // the JIT spelling succeeded
                }
            }
            0
        });

        assert_eq!(
            outcome, 0,
            "route 3 must be refused: 10 = mmap(W|X) succeeded, 11 = a plain writable \
             mapping was refused (the rule is too broad), 12 = mprotect(PROT_EXEC) succeeded"
        );
    }

    /// **A read-execute mapping with no write is still permitted.** The bound on the rule above.
    #[test]
    fn a_read_execute_mapping_is_still_permitted() {
        if !probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("the filters compile");

        let outcome = in_filtered_child(&filters, || {
            // SAFETY: an anonymous read-execute mapping in the child's own address space.
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED { 20 } else { 0 }
        });

        assert_eq!(
            outcome, 0,
            "a read-execute mapping must remain permitted, or the dynamic loader cannot \
             map a shared library and no workload starts"
        );
    }

    /// `Blocked` — the DEFAULT network mode — actually blocks, at the kernel.
    #[test]
    fn blocked_mode_leaves_no_route_at_all() {
        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }

        // A listener in the HOST namespace.
        let host_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener");
        let host_port = host_listener.local_addr().expect("addr").port();

        let directory = tempfile::tempdir().expect("tempdir");
        // `Blocked` is the default, stated explicitly here so the test does not
        // silently become a `Localhost` test if the default ever changes.
        let config = ContainmentConfig::new()
            .set_network(Network::Blocked)
            .expect("Blocked is a valid request")
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("grant a directory");

        // SAFETY: the child applies containment and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if backend.apply(&config, None, None).is_err() {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(30) };
            }

            // Only the workload process reaches here, already contained.
            let host_reachable = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], host_port)),
                std::time::Duration::from_secs(2),
            )
            .is_ok();
            let external_reachable = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([169, 254, 169, 254], 80)),
                std::time::Duration::from_secs(2),
            )
            .is_ok();

            // SAFETY: terminating the workload with the verdict.
            unsafe {
                libc::_exit(match (host_reachable, external_reachable) {
                    (false, false) => 0,
                    (true, _) => 31,
                    (_, true) => 32,
                })
            };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "Blocked did not block (30=apply failed,              31=THE HOST'S OWN LOOPBACK LISTENER WAS REACHABLE,              32=an external address was reachable)"
        );
    }

    /// `AllowAll` joins the host network namespace and keeps the PID, mount, IPC, UTS, and user namespaces.
    #[test]
    fn allow_all_joins_the_host_network_and_keeps_the_other_namespaces() {
        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }

        let host_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener");
        let host_port = host_listener.local_addr().expect("addr").port();

        let host_namespaces: Vec<(&str, std::path::PathBuf)> =
            ["net", "pid", "mnt", "ipc", "uts", "user"]
                .into_iter()
                .map(|kind| {
                    let link = std::fs::read_link(format!("/proc/self/ns/{kind}"))
                        .expect("read a host namespace link");
                    (kind, link)
                })
                .collect();

        let directory = tempfile::tempdir().expect("tempdir");
        let granted = directory.path().join("granted.txt");
        std::fs::write(&granted, b"granted").expect("write granted");
        let ungranted = directory.path().join("ungranted.txt");
        std::fs::write(&ungranted, b"ungranted").expect("write ungranted");
        let config = ContainmentConfig::new()
            .set_network(Network::AllowAll)
            .expect("AllowAll is a valid request")
            .allow(&granted, Operation::Read, Scope::File)
            .expect("read grant");

        // SAFETY: the child applies containment and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if let Err(error) = backend.apply(&config, None, None) {
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(40) };
            }

            // Only the workload process reaches here, already contained.
            let code = {
                let host_reachable = std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], host_port)),
                    std::time::Duration::from_secs(2),
                )
                .is_ok();
                let mut namespace_code = 0;
                for (kind, host_link) in &host_namespaces {
                    let Ok(link) = std::fs::read_link(format!("/proc/self/ns/{kind}")) else {
                        namespace_code = 42;
                        break;
                    };
                    let shared = link == *host_link;
                    if shared != (*kind == "net") {
                        namespace_code = if *kind == "net" { 43 } else { 44 };
                        break;
                    }
                }
                let visible = std::fs::read_dir("/proc")
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter(|entry| {
                                entry
                                    .file_name()
                                    .to_str()
                                    .is_some_and(|name| name.parse::<u32>().is_ok())
                            })
                            .count()
                    })
                    .unwrap_or(usize::MAX);
                let granted_readable = std::fs::read(&granted).is_ok();
                let ungranted_readable = std::fs::read(&ungranted).is_ok();
                let host_readable = std::fs::read("/etc/passwd").is_ok();

                if !host_reachable {
                    41
                } else if namespace_code != 0 {
                    namespace_code
                } else if visible > MAX_VISIBLE_PIDS_IN_FRESH_NAMESPACE {
                    45
                } else if !granted_readable {
                    46
                } else if ungranted_readable || host_readable {
                    47
                } else {
                    0
                }
            };

            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        drop(host_listener);
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "AllowAll did not deliver its shape (40=apply failed, \
             41=the host's loopback listener was unreachable, 42=a namespace link was unreadable, \
             43=the network namespace was not the host's, \
             44=ANOTHER NAMESPACE WAS SHARED WITH THE HOST, 45=HOST PROCESSES WERE VISIBLE, \
             46=the granted path was unreachable, 47=AN UNGRANTED PATH WAS READABLE)"
        );
    }

    #[test]
    fn one_object_cannot_execute_after_a_separate_write_mapping() {
        use std::os::fd::AsRawFd as _;

        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }

        let file = tempfile::NamedTempFile::new().expect("temporary file");
        file.as_file().set_len(4096).expect("size temporary file");
        let path = file.path().to_path_buf();
        let config = ContainmentConfig::new()
            .allow(&path, Operation::Write, Scope::File)
            .expect("grant the writable file");

        // SAFETY: the child applies containment, maps its granted file, and exits.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            if backend.apply(&config, None, None).is_err() {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }

            let opened = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open granted file");
            // SAFETY: both mappings use one valid file descriptor and one page.
            let code = unsafe {
                let writable = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    opened.as_raw_fd(),
                    0,
                );
                if writable == libc::MAP_FAILED {
                    21
                } else {
                    std::ptr::write_volatile(writable.cast::<u8>(), 0xc3);
                    let executable = libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_SHARED,
                        opened.as_raw_fd(),
                        0,
                    );
                    if executable != libc::MAP_FAILED {
                        22
                    } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                        23
                    } else {
                        0
                    }
                }
            };
            // SAFETY: terminating the child with the verdict.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "20 = apply failed, 21 = write mapping failed, \
             22 = executable mapping succeeded, 23 = refusal was not EPERM"
        );
    }

    /// The whole sequence, at the kernel, in one test.
    #[test]
    fn apply_delivers_every_property_it_claims() {
        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }

        // A granted file the workload must be able to read, and an ungranted one it must not reach.
        let directory = tempfile::tempdir().expect("tempdir");
        let granted = directory.path().join("granted.txt");
        std::fs::write(&granted, b"granted").expect("write granted");
        let ungranted = directory.path().join("ungranted.txt");
        std::fs::write(&ungranted, b"ungranted").expect("write ungranted");

        let config = ContainmentConfig::new()
            .allow(&granted, Operation::Read, Scope::File)
            .expect("read grant");

        let granted_path = granted.clone();
        let ungranted_path = ungranted.clone();

        // SAFETY: the child applies containment and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            let backend = NamespaceBackend::with_probe_result(true);
            // No handoff: this test asserts the filesystem, process, and authority properties, and
            // the request below is `Blocked` by default so no egress endpoint is created.
            if let Err(error) = backend.apply(&config, None, None) {
                // Printed rather than swallowed: exit code 20 says "apply failed" and this says
                // why, which is the difference between a five-minute diagnosis and an afternoon of
                // bisecting namespaces.
                eprintln!("apply failed: {error}");
                // SAFETY: terminating the child.
                unsafe { libc::_exit(20) };
            }

            // Only the workload process reaches here, already contained.
            let code = {
                let granted_readable = std::fs::read(&granted_path).is_ok();
                let ungranted_readable = std::fs::read(&ungranted_path).is_ok();
                let host_readable = std::fs::read("/etc/passwd").is_ok();

                let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                let capabilities_clear = ["CapEff:", "CapBnd:", "CapAmb:"].iter().all(|field| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix(field))
                        .map(|value| value.trim().chars().all(|c| c == '0'))
                        .unwrap_or(false)
                });

                // A fresh /proc in a fresh PID namespace holds only this namespace's processes, so
                // the count is tiny.
                let visible = std::fs::read_dir("/proc")
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter(|entry| {
                                entry
                                    .file_name()
                                    .to_str()
                                    .is_some_and(|name| name.parse::<u32>().is_ok())
                            })
                            .count()
                    })
                    .unwrap_or(usize::MAX);

                // SAFETY: these calls only reassert or probe identities inside this user namespace.
                let credential_reassertions_work =
                    unsafe { libc::setresuid(0, 0, 0) == 0 && libc::setresgid(!0, !0, !0) == 0 };
                // SAFETY: the filter must refuse each unapproved identity form before the kernel
                // can apply it.
                let credential_widening_refused = unsafe {
                    let uid_refused = libc::setresuid(0, 1, 0) == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                    let gid_refused = libc::setresgid(!0, 0, !0) == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                    uid_refused && gid_refused
                };

                // SAFETY: probing that a nested namespace remains available.
                let can_unshare = unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0;

                if !granted_readable {
                    21 // a granted path must be present
                } else if ungranted_readable {
                    22 // an ungranted path must not be
                } else if host_readable {
                    23 // the host root must be gone
                } else if !capabilities_clear {
                    24 // setup authority must not survive
                } else if visible > MAX_VISIBLE_PIDS_IN_FRESH_NAMESPACE {
                    25 // host processes must not be visible
                } else if !credential_reassertions_work {
                    26 // approved credential forms must work
                } else if !credential_widening_refused {
                    27 // unapproved credential forms must fail
                } else if !can_unshare {
                    28 // the workload must be able to create a nested namespace
                } else {
                    0
                }
            };

            // SAFETY: terminating the workload with the verdict.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "containment did not deliver a claimed property \
             (20=apply failed, 21=granted path unreachable, \
             22=UNGRANTED PATH READABLE, 23=HOST FILESYSTEM READABLE, \
             24=capabilities survived, 25=host processes visible, \
             26=approved credential form failed, 27=unapproved credential form passed, \
             28=nested namespace creation failed)"
        );
    }

    /// The four macOS-only leaf fields validate on Linux and change neither the view nor the filters.
    #[test]
    fn linux_validate_states_its_handling_of_macos_only_leaf_fields() {
        let home = tempfile::tempdir().expect("home");
        let workspace = home.path().join("workspace");
        let state = workspace.join(".strands-box");
        std::fs::create_dir_all(&state).expect("box state");
        let agent_shaped = ContainmentConfig::new()
            .anchored_at(home.path())
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("write grant");
        let leaf = agent_shaped
            .clone()
            .allow_discovery(home.path())
            .deny_discovery(&state)
            .allow_broad_exec()
            .allow_runtime_services();

        NamespaceBackend::with_probe_result(true)
            .validate_config(&leaf)
            .expect("a leaf with every macOS-only field must validate on Linux");

        let leaf_view = view::MountView::plan(&leaf).expect("the leaf view plans");
        let agent_view = view::MountView::plan(&agent_shaped).expect("the agent view plans");
        assert_eq!(
            leaf_view.entries(),
            agent_view.entries(),
            "a macOS-only leaf field changed the Linux mount view"
        );
        assert!(
            leaf_view
                .entries()
                .iter()
                .filter(|entry| entry.writable && entry.origin == view::MountOrigin::Grant)
                .all(|entry| !entry.executable),
            "broad exec made a writable grant executable on Linux"
        );
        syscall::SyscallPolicy::for_config(leaf.network())
            .compile()
            .expect("the leaf filters compile from the network alone");
    }

    /// The reaper writes the exec-confirm byte before the workload runs, and the apply-failure byte when the view fails.
    #[test]
    fn the_reaper_writes_the_exec_confirm_byte_and_a_failure_byte() {
        if !the_host_can_build_a_view() {
            println!("skipping: this host cannot build a namespace mount view");
            return;
        }
        assert_eq!(EXEC_CONFIRM_BYTE, 0, "this crate's exec-confirm byte value");
        assert_eq!(
            APPLY_FAILURE_BYTE, 3,
            "this crate's apply-failure byte value"
        );

        let directory = tempfile::tempdir().expect("tempdir");
        let granted = directory.path().join("granted.txt");
        std::fs::write(&granted, b"granted").expect("write granted");
        let builds = ContainmentConfig::new()
            .allow(&granted, Operation::Read, Scope::File)
            .expect("read grant");
        // A write protection outside every grant has no mountpoint in the view. The trigger relies on
        // `validate_config` accepting it; if validation refuses it, pick another materialize failure.
        let protected = directory.path().join("protected.txt");
        std::fs::write(&protected, b"protected").expect("write protected");
        let opened = std::fs::File::open(&protected).expect("open protected");
        let fails = builds
            .clone()
            .protect_write(&protected, &opened)
            .expect("write protection");

        for (label, config, expected_bytes, expected_status) in [
            ("view built", &builds, vec![EXEC_CONFIRM_BYTE], 0),
            ("view failed", &fails, vec![APPLY_FAILURE_BYTE], 127),
        ] {
            let mut pipe = [-1; 2];
            // SAFETY: a plain pipe for this test's own status bytes.
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0,
                "pipe2"
            );
            let [reader, writer] = pipe;

            // SAFETY: the child applies containment and exits; it never returns into
            // test-harness code.
            let child = unsafe { libc::fork() };
            assert_ne!(child, -1, "fork failed");

            if child == 0 {
                // SAFETY: closing the child's copy of the read end.
                unsafe { libc::close(reader) };
                let backend = NamespaceBackend::with_probe_result(true);
                if let Err(error) = backend.apply(config, None, Some(writer)) {
                    eprintln!("apply failed: {error}");
                    // SAFETY: terminating the child.
                    unsafe { libc::_exit(50) };
                }
                // SAFETY: the workload exits at once.
                unsafe { libc::_exit(0) };
            }

            // SAFETY: closing the parent's copy of the write end, so the read below meets EOF.
            unsafe { libc::close(writer) };
            let mut received = Vec::new();
            {
                use std::io::Read as _;
                use std::os::fd::FromRawFd as _;
                // SAFETY: `reader` is this test's own read end, and the `File` takes ownership.
                let mut reader = unsafe { std::fs::File::from_raw_fd(reader) };
                reader
                    .read_to_end(&mut received)
                    .expect("read status bytes");
            }
            let mut status = 0;
            // SAFETY: waiting on this process's own child.
            unsafe { libc::waitpid(child, &mut status, 0) };
            assert!(
                libc::WIFEXITED(status),
                "{label}: the child must exit normally"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                expected_status,
                "{label}: wrong exit status (50 = apply returned an error before the reaper ran)"
            );
            assert_eq!(received, expected_bytes, "{label}: wrong status bytes");
        }
    }
}
