//! The accept loop and per-connection handler.

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use crate::audit::RequestId;

use super::BackendDial;
use super::SharedState;
use super::connect::ConnectRequest;
use super::l7::{self, WorkloadResponse};
use super::resolve::PinnedDestination;
use crate::audit::Decision as AuditDecision;
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome};
use crate::transport::socket::{Socket, SocketShutdown};

/// The bounded set of client sockets whose connection workers have not finished.
pub(super) struct Connections {
    max: usize,
    state: Mutex<ConnectionState>,
    freed: Condvar,
}

struct ConnectionState {
    stopped: bool,
    sockets: Vec<Arc<SocketShutdown>>,
}

impl Connections {
    pub(super) fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            state: Mutex::new(ConnectionState {
                stopped: false,
                sockets: Vec::new(),
            }),
            freed: Condvar::new(),
        }
    }

    pub(super) fn is_stopped(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).stopped
    }

    pub(super) fn shutdown(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.stopped {
            return false;
        }
        state.stopped = true;
        for socket in &state.sockets {
            socket.shutdown();
        }
        self.freed.notify_all();
        true
    }

    fn acquire(self: &Arc<Self>, socket: SocketShutdown) -> Option<Permit> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while !state.stopped && state.sockets.len() == self.max {
            state = self.freed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        if state.stopped {
            return None;
        }
        let socket = Arc::new(socket);
        state.sockets.push(socket.clone());
        Some(Permit {
            connections: self.clone(),
            socket,
        })
    }
}

/// A registered connection whose slot remains held through terminal outcome recording.
struct Permit {
    connections: Arc<Connections>,
    socket: Arc<SocketShutdown>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self
            .connections
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state
            .sockets
            .retain(|socket| !Arc::ptr_eq(socket, &self.socket));
        self.connections.freed.notify_one();
    }
}

/// The connection threads owned and joined by the accept loop.
struct WorkerThreads {
    connections: Arc<Connections>,
    threads: Vec<JoinHandle<()>>,
}

impl WorkerThreads {
    fn reap_finished(&mut self) {
        let mut index = 0;
        while index < self.threads.len() {
            if self.threads[index].is_finished() {
                let _ = self.threads.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }
}

impl Drop for WorkerThreads {
    fn drop(&mut self) {
        self.connections.shutdown();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Accept bounded connections, then interrupt clients and join their workers on shutdown.
pub(super) fn accept_loop<S: Socket + Send + 'static>(
    incoming: impl Iterator<Item = io::Result<S>>,
    state: Arc<SharedState>,
    connections: Arc<Connections>,
    connect_only: bool,
) {
    let mut workers = WorkerThreads {
        connections: connections.clone(),
        threads: Vec::new(),
    };
    for incoming in incoming {
        if connections.is_stopped() {
            break;
        }
        workers.reap_finished();
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Ok(shutdown) = stream.shutdown_handle() else {
            continue;
        };
        let Some(permit) = connections.acquire(shutdown) else {
            break;
        };
        let state = state.clone();
        if let Ok(thread) = std::thread::Builder::new().spawn(move || {
            let _permit = permit;
            let _ = crate::proxy::server::serve_connection(stream, &state, connect_only);
        }) {
            workers.threads.push(thread);
        }
    }
}

/// A failure before CONNECT can be acknowledged.
pub(crate) enum OpenUpstreamError {
    /// The effect interceptor explicitly denied the socket open.
    Denied(io::Error),
    /// The interceptor, socket open, peer lookup, or outcome sink failed.
    Failed,
}

impl OpenUpstreamError {
    pub(crate) fn response(&self) -> WorkloadResponse {
        match self {
            Self::Denied(error) => l7::interceptor_error(error, None),
            Self::Failed => WorkloadResponse::bare(502),
        }
    }
}

/// Run the connect decisions for one destination, for every transport and request shape, and
/// open the pinned upstream socket. On refusal, return the refusal for the caller to answer.
///
/// When the destination re-routes to a backend, the returned [`BackendDial`] names the host the
/// upstream leg must present (SNI, certificate, `Host`); `None` leaves the upstream leg on the
/// original destination.
pub(crate) fn open_governed_upstream(
    state: &SharedState,
    connect: &ConnectRequest,
    correlation: &RequestId,
) -> std::result::Result<(TcpStream, Option<BackendDial>), OpenUpstreamError> {
    // Policy decides the host before it is resolved, so a denied destination sends no DNS query: a
    // workload cannot carry data out in the labels of a name the gateway looks up and then refuses.
    // The host decision is the ORIGINAL destination — the agent's intent — even when a backend
    // re-routes the dial; the per-address `net:connect` below decides every resolved BACKEND address.
    let resolve = EffectAttempt::Resolve {
        host: &connect.host,
        port: connect.port,
    };
    match state.effect_interceptor.intercept(&resolve) {
        Ok(_decided) => {}
        Err(error) => {
            emit_connect_decision(
                state,
                connect,
                AuditDecision::Deny,
                &error.to_string(),
                correlation.clone(),
            );
            let refusal = if error.kind() == io::ErrorKind::PermissionDenied {
                OpenUpstreamError::Denied(error)
            } else {
                OpenUpstreamError::Failed
            };
            return Err(refusal);
        }
    }

    // A backend re-routes the dial to a different host and port. Box resolves and dials only the
    // backend; it never resolves or dials the original destination. The host decision above already
    // ran on the original, so the agent's intent is authorized exactly once
    // (docs/design/decisions.md#a-re-route-is-authorized-on-the-original-destination). The
    // supervisor DNS override applies to whichever host is actually resolved.
    let backend = state.backend_for(&connect.host, connect.port).cloned();
    // Fail closed when the host re-routes to a backend but this PORT matches no backend entry. A
    // bare-host backend pattern covers only 443/80, so without this guard a `CONNECT host:8443` would
    // fall through and dial the ORIGINAL destination directly — the one thing a re-route must never do
    // (docs/design/decisions.md#a-re-route-is-authorized-on-the-original-destination).
    if backend.is_none() && state.host_reroutes(&connect.host) {
        let reason = format!(
            "{}:{} re-routes to a backend, but no backend entry matches this port; refused rather \
             than dial the original destination",
            connect.host, connect.port
        );
        emit_connect_decision(
            state,
            connect,
            AuditDecision::Deny,
            &reason,
            correlation.clone(),
        );
        return Err(OpenUpstreamError::Denied(io::Error::new(
            io::ErrorKind::PermissionDenied,
            reason,
        )));
    }
    let (resolve_host, resolve_port) = match &backend {
        Some(dial) => (dial.host.as_str(), dial.port),
        None => (connect.host.as_str(), connect.port),
    };

    // Resolve-once + pin, honoring any supervisor DNS override. A resolution failure
    // is a hard 502, never a retry — and never a fallback to the original destination.
    let override_ip = state.dns_override(resolve_host);
    let pinned =
        match PinnedDestination::resolve_with_override(resolve_host, resolve_port, override_ip) {
            Ok(pinned) => pinned,
            Err(error) => {
                emit_connect_decision(
                    state,
                    connect,
                    AuditDecision::Deny,
                    &error.to_string(),
                    correlation.clone(),
                );
                return Err(OpenUpstreamError::Failed);
            }
        };

    // Authorization is Cedar's, enforced inside `open_upstream` through the `EffectInterceptor` seam
    // (`EffectAttempt::Connect`) before the socket opens — there is no allow/deny authority in this
    // crate. The Connect carries the ORIGINAL host and port; the backend address and port appear only
    // in the dialled `address`. Every connection is terminated and inspected; see `open_upstream`'s
    // `http_visibility` for why no route is an opaque tunnel.
    let upstream = open_upstream(state, connect, &pinned, correlation)?;
    Ok((upstream, backend))
}

/// Claim and perform pinned upstream socket attempts shared by TLS and opaque paths.
fn open_upstream(
    state: &SharedState,
    connect: &ConnectRequest,
    pinned: &PinnedDestination,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, OpenUpstreamError> {
    for address in pinned.pinned_addrs() {
        // A deny-only floor beneath policy, not a destination list: a dial to the gateway's own
        // listener connects the gateway to itself, so the request meets the gateway in place of a
        // service and holds a second connection slot. Decided before policy, so no permit can open
        // it (docs/design/decisions.md#the-gateway-never-dials-its-own-listener).
        if state.is_own_listener(address) {
            let reason = format!(
                "{}:{} dials {address}, the gateway's own listener; refused so the gateway does \
                 not connect to itself",
                connect.host, connect.port
            );
            emit_connect_decision(
                state,
                connect,
                AuditDecision::Deny,
                &reason,
                correlation.clone(),
            );
            return Err(OpenUpstreamError::Denied(io::Error::new(
                io::ErrorKind::PermissionDenied,
                reason,
            )));
        }
        // Each pinned address is its own authorization: the address authorized is the address
        // dialed, so a fallback cannot ride the first address's permit.
        let attempt = EffectAttempt::Connect {
            host: &connect.host,
            port: connect.port,
            address,
            // **Unconditionally true, so TLS termination is never selective.** Every connection is
            // terminated and inspected; no opaque-tunnel path exists.
            //
            // This arrived through three layers — a `SharedState::route_needs_http` that returned
            // `true` for every route, a `needs_http` local at each caller, and a parameter on this
            // function. All three are gone. A maintainer reading them went looking for the selective
            // path they implied, and there was none to find.
            //
            // The field stays because `EffectAttempt` is in this crate's frozen `lib.rs` `pub use`
            // set, and it is an attribute a policy adapter could expose to a rule. Its one production
            // consumer, `policy`'s egress adapter, discards it today.
            http_visibility: true,
        };
        let permit = match state.effect_interceptor.intercept(&attempt) {
            Ok(permit) => ClaimedEffectPermit::new(permit),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                emit_connect_decision(
                    state,
                    connect,
                    AuditDecision::Deny,
                    &error.to_string(),
                    correlation.clone(),
                );
                return Err(OpenUpstreamError::Denied(error));
            }
            Err(error) => {
                emit_connect_decision(
                    state,
                    connect,
                    AuditDecision::Deny,
                    &error.to_string(),
                    correlation.clone(),
                );
                return Err(OpenUpstreamError::Failed);
            }
        };
        emit_connect_decision(
            state,
            connect,
            AuditDecision::Allow,
            "",
            correlation.clone(),
        );

        let upstream = match TcpStream::connect(address) {
            Ok(upstream) => upstream,
            Err(error) => {
                permit
                    .record_outcome(EffectOutcome::ConnectFailed(error.kind()))
                    .map_err(|_| OpenUpstreamError::Failed)?;
                continue;
            }
        };
        // Best-effort: Nagle's algorithm off. The crate's `AGENTS.md` records the measurement.
        let _ = upstream.set_nodelay(true);

        let peer = upstream
            .peer_addr()
            .map_err(|_| OpenUpstreamError::Failed)?;
        permit
            .record_outcome(EffectOutcome::Connected(peer))
            .map_err(|_| OpenUpstreamError::Failed)?;
        return Ok(upstream);
    }

    Err(OpenUpstreamError::Failed)
}

/// Emit the connection decision for `connect`: no method, and the all-paths `/`.
fn emit_connect_decision(
    state: &SharedState,
    connect: &ConnectRequest,
    decision: AuditDecision,
    reason: &str,
    correlation: RequestId,
) {
    l7::emit_decision(state, connect, ("", "/"), decision, reason, correlation);
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod shutdown_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn idle_socket() -> SocketShutdown {
        let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
        SocketShutdown::Unix(socket)
    }

    #[test]
    fn limiter_caps_and_releases() {
        let limiter = Arc::new(Connections::new(2));
        let a = limiter.acquire(idle_socket()).unwrap();
        let b = limiter.acquire(idle_socket()).unwrap();
        assert_eq!(limiter.state.lock().unwrap().sockets.len(), 2);

        let limiter2 = limiter.clone();
        let handle = std::thread::spawn(move || {
            let _c = limiter2.acquire(idle_socket()).unwrap();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!handle.is_finished(), "third acquire must block while full");

        drop(a);
        handle.join().unwrap();
        drop(b);
        assert!(limiter.state.lock().unwrap().sockets.is_empty());
    }

    #[test]
    fn zero_cap_is_clamped_to_one() {
        let limiter = Arc::new(Connections::new(0));
        assert_eq!(limiter.max, 1);
        let _permit = limiter.acquire(idle_socket()).unwrap();
    }

    #[test]
    fn shutdown_closes_a_socket_before_its_worker_starts() {
        use std::io::Read;
        use std::time::Duration;

        let (mut worker_socket, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        worker_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connections = Arc::new(Connections::new(1));
        let permit = connections
            .acquire(worker_socket.shutdown_handle().unwrap())
            .unwrap();
        assert!(connections.shutdown());
        let mut byte = [0; 1];
        assert_eq!(worker_socket.read(&mut byte).unwrap(), 0);
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        drop(permit);
        assert!(connections.state.lock().unwrap().sockets.is_empty());
    }

    #[test]
    fn shutdown_refuses_later_registration() {
        let connections = Arc::new(Connections::new(1));
        assert!(connections.shutdown());
        assert!(connections.acquire(idle_socket()).is_none());
        assert!(connections.state.lock().unwrap().sockets.is_empty());
        assert!(!connections.shutdown());
    }

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::capability::CapabilitySet;
    use crate::effect::{EffectAttempt, EffectInterceptor, EffectPermit};
    use crate::seams::StubEmitter;

    /// An authority that permits one address and refuses every other, recording what it saw.
    struct AddressPolicy {
        permitted: Option<IpAddr>,
        seen: Mutex<Vec<(SocketAddr, bool)>>,
    }

    impl AddressPolicy {
        fn permitting(ip: IpAddr) -> Arc<Self> {
            Arc::new(Self {
                permitted: Some(ip),
                seen: Mutex::new(Vec::new()),
            })
        }
        fn permit_all() -> Arc<Self> {
            Arc::new(Self {
                permitted: None,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn seen(&self) -> Vec<(SocketAddr, bool)> {
            self.seen.lock().unwrap().clone()
        }
    }

    struct NoopPermit;
    impl EffectPermit for NoopPermit {
        fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
            Ok(())
        }
        fn mark_indeterminate(self: Box<Self>) {}
    }

    impl EffectInterceptor for AddressPolicy {
        fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            if let EffectAttempt::Connect { address, .. } = attempt {
                let permitted = self.permitted.is_none_or(|ip| address.ip() == ip);
                self.seen.lock().unwrap().push((*address, permitted));
                if !permitted {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "address refused by test policy",
                    ));
                }
            }
            Ok(Box::new(NoopPermit))
        }
    }

    /// A loopback listener counting the connections it accepts, measured behind a drain barrier
    /// (ticket taken before the sweep, acknowledged after it) and stopped by joining.
    struct Recorder {
        addr: SocketAddr,
        accepted: Arc<AtomicUsize>,
        accept_error: Arc<Mutex<Option<String>>>,
        drain_requested: Arc<std::sync::atomic::AtomicU64>,
        drain_acknowledged: Arc<std::sync::atomic::AtomicU64>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Recorder {
        fn bind(addr: SocketAddr) -> io::Result<Self> {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            Ok(Self::from_accept(addr, move || listener.accept()))
        }

        fn from_accept(
            addr: SocketAddr,
            mut accept: impl FnMut() -> io::Result<(TcpStream, SocketAddr)> + Send + 'static,
        ) -> Self {
            let accepted = Arc::new(AtomicUsize::new(0));
            let accept_error = Arc::new(Mutex::new(None));
            let drain_requested = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let drain_acknowledged = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (count, failure, requested, acknowledged, stopping) = (
                accepted.clone(),
                accept_error.clone(),
                drain_requested.clone(),
                drain_acknowledged.clone(),
                stop.clone(),
            );
            let thread = std::thread::spawn(move || {
                while !stopping.load(Ordering::SeqCst) {
                    let ticket = requested.load(Ordering::SeqCst);
                    while !stopping.load(Ordering::SeqCst) {
                        match accept() {
                            Ok((stream, _)) => {
                                count.fetch_add(1, Ordering::SeqCst);
                                drop(stream);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                *failure.lock().unwrap() = Some(error.to_string());
                                return;
                            }
                        }
                    }
                    if acknowledged.load(Ordering::SeqCst) < ticket {
                        acknowledged.store(ticket, Ordering::SeqCst);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            });
            Self {
                addr,
                accepted,
                accept_error,
                drain_requested,
                drain_acknowledged,
                stop,
                thread: Some(thread),
            }
        }

        /// The accept count after the loop has swept every connection queued before this call.
        fn accepted(&self) -> usize {
            let wanted = self.drain_requested.fetch_add(1, Ordering::SeqCst) + 1;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while self.drain_acknowledged.load(Ordering::SeqCst) < wanted {
                self.assert_healthy();
                assert!(
                    std::time::Instant::now() < deadline,
                    "the recorder's accept loop did not acknowledge a drain"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            self.assert_healthy();
            self.accepted.load(Ordering::SeqCst)
        }

        fn assert_healthy(&self) {
            let error = self.accept_error.lock().unwrap().clone();
            if let Some(error) = error {
                panic!("the recorder's accept failed: {error}");
            }
        }

        /// Independent endpoint control: the host itself reaches this recorder and is counted.
        fn assert_live(&self) {
            let before = self.accepted();
            drop(
                TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(2))
                    .expect("the host reaches the recorder"),
            );
            assert_eq!(
                self.accepted(),
                before + 1,
                "the recorder counts a direct connection"
            );
        }
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    #[should_panic(expected = "accept failed: injected accept failure")]
    fn an_accept_error_cannot_be_read_as_a_clean_zero() {
        let recorder =
            Recorder::from_accept(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), || {
                Err(io::Error::other("injected accept failure"))
            });
        recorder.accepted();
    }

    /// A second loopback address on `port`, distinct from `127.0.0.1`. Required setup: its absence
    /// fails the test by name rather than skipping the body.
    fn second_loopback_recorder(port: u16) -> Recorder {
        let candidates = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let mut errors = Vec::new();
        for ip in candidates {
            match Recorder::bind(SocketAddr::new(ip, port)) {
                Ok(recorder) => return recorder,
                Err(error) => errors.push(format!("{ip}: {error}")),
            }
        }
        panic!(
            "required setup: no second loopback address could be bound on port {port}: {errors:?}"
        );
    }

    fn state(policy: Arc<dyn EffectInterceptor>) -> SharedState {
        SharedState {
            controls: CapabilitySet::default(),
            config: super::super::MitmConfig::default(),
            ca: super::super::ca::EphemeralCa::generate(None, None).unwrap(),
            upstream_config: Arc::new(
                super::super::tls::upstream_client_config(&[], false)
                    .unwrap()
                    .0,
            ),
            emitter: Box::new(StubEmitter::new()),
            effect_interceptor: policy,
            reply_copies: Arc::new(super::super::body::CopyBudget::for_limit(1024)),
            listening: None,
        }
    }

    fn connect_to(host: &str, port: u16) -> ConnectRequest {
        ConnectRequest {
            host: host.to_string(),
            port,
        }
    }

    /// A resolver answer of two addresses, one the authority permits and one it refuses, against
    /// live recorders at both: the refused address is never dialed whatever its position, and a
    /// refusal aborts the connect rather than falling through to the permitted one.
    #[test]
    fn a_pinned_address_the_authority_refused_is_never_dialed_whatever_its_position() {
        let permitted =
            Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = permitted.addr.port();
        let refused = second_loopback_recorder(port);
        permitted.assert_live();
        refused.assert_live();
        let (permitted_before, refused_before) = (permitted.accepted(), refused.accepted());
        let (a, b) = (permitted.addr.ip(), refused.addr.ip());
        let host = "two-answers.test";
        let correlation = RequestId::new("test");

        // Refused address first: the connect is refused outright; neither recorder is contacted.
        let policy = AddressPolicy::permitting(a);
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![b, a]);
        assert!(
            matches!(
                open_upstream(&shared, &connect_to(host, port), &pinned, &correlation),
                Err(OpenUpstreamError::Denied(_))
            ),
            "a refused first address aborts the connect"
        );
        assert_eq!(policy.seen(), vec![(SocketAddr::new(b, port), false)]);
        assert_eq!(
            refused.accepted(),
            refused_before,
            "the refused address was never dialed"
        );
        assert_eq!(
            permitted.accepted(),
            permitted_before,
            "the permitted address does not ride the refusal as a fallback"
        );

        // Permitted address first: it is dialed, and the refused one is never asked about.
        let policy = AddressPolicy::permitting(a);
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![a, b]);
        let upstream = open_upstream(&shared, &connect_to(host, port), &pinned, &correlation)
            .ok()
            .expect("the permitted address connects");
        assert_eq!(upstream.peer_addr().unwrap(), SocketAddr::new(a, port));
        assert_eq!(policy.seen(), vec![(SocketAddr::new(a, port), true)]);
        assert_eq!(permitted.accepted(), permitted_before + 1);
        assert_eq!(refused.accepted(), refused_before);
        drop(upstream);
    }

    /// A dial to the gateway's own listener, bound to one address or to every address, is refused
    /// before policy sees the address, and no socket opens.
    #[test]
    fn own_listener_refused() {
        let own = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        own.assert_live();
        let before = own.accepted();
        let port = own.addr.port();
        let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let cases = [
            (own.addr, own.addr.ip()),
            (own.addr, mapped),
            (own.addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            (own.addr, IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped())),
            (unspecified, own.addr.ip()),
            (unspecified, mapped),
        ];
        for (listening, dialed) in cases {
            let policy = AddressPolicy::permit_all();
            let mut shared = state(policy.clone());
            shared.listening = Some(listening);
            let pinned = PinnedDestination::from_ips(port, vec![dialed]);
            assert!(
                matches!(
                    open_upstream(
                        &shared,
                        &connect_to("host.box.internal", port),
                        &pinned,
                        &RequestId::new("test"),
                    ),
                    Err(OpenUpstreamError::Denied(_))
                ),
                "listening on {listening}, dialing {dialed}"
            );
            assert!(policy.seen().is_empty(), "policy never sees the address");
        }
        assert_eq!(own.accepted(), before, "the gateway never dials itself");
    }

    #[test]
    fn an_opened_upstream_socket_has_tcp_nodelay_set() {
        let origin = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = origin.addr.port();
        let shared = state(AddressPolicy::permit_all());
        let pinned = PinnedDestination::from_ips(port, vec![origin.addr.ip()]);
        let upstream = open_upstream(
            &shared,
            &connect_to("origin.test", port),
            &pinned,
            &RequestId::new("test"),
        )
        .ok()
        .expect("the origin connects");
        assert!(
            upstream.nodelay().unwrap(),
            "Nagle's algorithm is off on the upstream socket"
        );
    }

    /// A dead endpoint plus a live refused recorder that share one port, on two loopback addresses
    /// every supported host has: the recorder on a second loopback address (`[::1]`, or `127.0.0.2`
    /// where IPv6 loopback is absent) chooses an ephemeral port, and `127.0.0.1` on that same port
    /// is left unbound. No port is bound and released, so no freed port can be reused; the dead
    /// endpoint is confirmed closed from the host by a bounded connect before it is trusted, and a
    /// port that is already in use on `127.0.0.1` is retried with a fresh recorder.
    struct DeadAndRefused {
        dead: SocketAddr,
        refused: Recorder,
    }

    const DEAD_ENDPOINT_ATTEMPTS: usize = 8;

    fn dead_and_refused_endpoints() -> Result<DeadAndRefused, Vec<String>> {
        let mut rejected = Vec::new();
        for _ in 0..DEAD_ENDPOINT_ATTEMPTS {
            let refused = second_loopback_recorder(0);
            let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), refused.addr.port());
            match confirm_closed(dead) {
                Ok(()) => return Ok(DeadAndRefused { dead, refused }),
                Err(error) => rejected.push(error),
            }
        }
        Err(rejected)
    }

    /// The host-side control: a bounded connect to `endpoint` must be refused at once. Anything
    /// else (an accepted connection, a timeout, another error) is reported by name so the endpoint
    /// is never trusted as dead.
    fn confirm_closed(endpoint: SocketAddr) -> Result<(), String> {
        match TcpStream::connect_timeout(&endpoint, std::time::Duration::from_secs(2)) {
            Ok(_) => Err(format!("{endpoint}: something accepted the connection")),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(format!(
                "{endpoint}: {error} ({:?}), not ConnectionRefused",
                error.kind()
            )),
        }
    }

    /// The fall-through exists only across permitted addresses: a permitted address that is dead
    /// moves on to the next answer, and a refused next answer still stops it. `dead` must already
    /// be confirmed closed and `refused` live; both halves run against the same pinned order.
    fn assert_dead_permitted_address_does_not_open_refused(dead: SocketAddr, refused: &Recorder) {
        let port = dead.port();
        assert_eq!(refused.addr.port(), port, "both endpoints share the port");
        refused.assert_live();
        let refused_before = refused.accepted();
        let b = refused.addr.ip();
        let host = "two-answers.test";
        let correlation = RequestId::new("test");

        // Positive control: with every address permitted the dial falls through to the live
        // recorder, so the refusal below is the authority's and not a dead dial path.
        let permissive = AddressPolicy::permit_all();
        let shared = state(permissive.clone());
        let pinned = PinnedDestination::from_ips(port, vec![dead.ip(), b]);
        let upstream = open_upstream(&shared, &connect_to(host, port), &pinned, &correlation)
            .ok()
            .expect("a permissive authority lets the dial fall through to the second answer");
        assert_eq!(upstream.peer_addr().unwrap(), SocketAddr::new(b, port));
        assert_eq!(
            permissive.seen(),
            vec![(dead, true), (SocketAddr::new(b, port), true)]
        );
        assert_eq!(
            refused.accepted(),
            refused_before + 1,
            "the recorder at the second answer is live"
        );
        drop(upstream);

        let policy = AddressPolicy::permitting(dead.ip());
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![dead.ip(), b]);
        assert!(
            matches!(
                open_upstream(&shared, &connect_to(host, port), &pinned, &correlation),
                Err(OpenUpstreamError::Denied(_))
            ),
            "a dead permitted address does not open the refused one"
        );
        assert_eq!(
            policy.seen(),
            vec![(dead, true), (SocketAddr::new(b, port), false)]
        );
        assert_eq!(
            refused.accepted(),
            refused_before + 1,
            "the refused address saw no second connection"
        );
        // The dead endpoint stayed closed across both dials: nothing else bound it meanwhile.
        confirm_closed(dead).expect("required setup held: the dead endpoint is still closed");
    }

    /// Portable form of the no-fallthrough regression: the dead permitted endpoint is `127.0.0.1`
    /// on the port the refused recorder holds at a second loopback address, so it needs no third
    /// loopback address and runs on Linux and macOS alike.
    #[test]
    fn a_dead_permitted_address_does_not_open_a_refused_one() {
        let fixture = dead_and_refused_endpoints().unwrap_or_else(|rejected| {
            panic!(
                "required setup: no port was closed on 127.0.0.1 in {DEAD_ENDPOINT_ATTEMPTS} \
                 attempts: {rejected:?}"
            )
        });
        assert_dead_permitted_address_does_not_open_refused(fixture.dead, &fixture.refused);
    }

    /// Same-family variant kept where the host provides a third loopback address: the dead
    /// endpoint `127.0.0.3` has no socket of this process on any port and the live recorder is
    /// IPv4 as well, so the fall-through is exercised between two IPv4 answers.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_third_loopback_address_does_not_open_a_refused_one() {
        let refused = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), refused.addr.port());
        confirm_closed(dead).unwrap_or_else(|error| panic!("required setup: {error}"));
        assert_dead_permitted_address_does_not_open_refused(dead, &refused);
    }

    /// Setup-failure control: an endpoint something listens at is rejected by name, so the fixture
    /// cannot hand out a live address as the dead one.
    #[test]
    fn a_live_endpoint_is_not_accepted_as_dead() {
        let live = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let error = confirm_closed(live.addr).expect_err("a listening endpoint is not closed");
        assert!(
            error.contains("accepted the connection"),
            "the rejection names the live endpoint: {error}"
        );
        live.assert_live();
    }

    /// The fixture's dead endpoint is closed from the host and its recorder is live on the same
    /// port at another loopback address.
    #[test]
    fn the_dead_and_refused_fixture_shares_one_port_across_two_loopback_addresses() {
        let fixture = dead_and_refused_endpoints()
            .unwrap_or_else(|rejected| panic!("required setup: {rejected:?}"));
        assert_eq!(fixture.dead.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(fixture.refused.addr.ip(), fixture.dead.ip());
        assert_eq!(fixture.refused.addr.port(), fixture.dead.port());
        confirm_closed(fixture.dead).unwrap();
        fixture.refused.assert_live();
    }

    /// A [`SharedState`] whose config carries the given backend re-routes.
    fn state_with_backends(
        policy: Arc<dyn EffectInterceptor>,
        backends: Vec<(credentials::DestinationPattern, BackendDial)>,
    ) -> SharedState {
        let config = super::super::MitmConfig {
            backends,
            ..super::super::MitmConfig::default()
        };
        SharedState {
            controls: CapabilitySet::default(),
            config,
            ca: super::super::ca::EphemeralCa::generate(None, None).unwrap(),
            upstream_config: Arc::new(
                super::super::tls::upstream_client_config(&[], false)
                    .unwrap()
                    .0,
            ),
            emitter: Box::new(StubEmitter::new()),
            effect_interceptor: policy,
            reply_copies: Arc::new(super::super::body::CopyBudget::for_limit(1024)),
            listening: None,
        }
    }

    /// A destination with a backend dials ONLY the backend address, and the per-address decision runs
    /// on the backend address while the host decision stays on the original destination. The original
    /// destination is never resolved or dialled.
    #[test]
    fn a_backend_reroutes_the_dial_to_the_backend_address() {
        let backend = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        backend.assert_live();
        let before = backend.accepted();
        let backend_ip = backend.addr.ip();
        let backend_port = backend.addr.port();

        // The backend host is a literal IP, so it resolves to itself with no DNS — the dial lands on
        // the recorder. The original destination is a name that MUST NOT be resolved; if it were, the
        // test would hit the network. The policy permits only the backend IP.
        let policy = AddressPolicy::permitting(backend_ip);
        let dial = BackendDial {
            host: backend_ip.to_string(),
            port: backend_port,
            tls: false,
            path_prefix: String::new(),
        };
        let pattern = credentials::DestinationPattern::parse("api.github.com").unwrap();
        let shared = state_with_backends(policy.clone(), vec![(pattern, dial)]);

        let correlation = RequestId::new("test");
        let (upstream, backend_leg) =
            open_governed_upstream(&shared, &connect_to("api.github.com", 443), &correlation)
                .ok()
                .expect("the backend address connects");

        // The dial landed on the backend recorder, not the original destination.
        assert_eq!(
            upstream.peer_addr().unwrap(),
            SocketAddr::new(backend_ip, backend_port)
        );
        assert_eq!(
            backend.accepted(),
            before + 1,
            "the backend was dialled once"
        );
        // The per-address decision saw the BACKEND address, never the original destination's.
        assert_eq!(
            policy.seen(),
            vec![(SocketAddr::new(backend_ip, backend_port), true)],
            "the address check runs on the backend address"
        );
        // The returned leg names the backend the upstream must present.
        let leg = backend_leg.expect("a re-routed destination returns its backend leg");
        assert_eq!(leg.host, backend_ip.to_string());
        assert_eq!(leg.port, backend_port);
        drop(upstream);
    }

    /// A backend whose address the policy denies is refused, with no dial and no fallback to the
    /// original destination. This is how the metadata and private-range floor refuses a backend that
    /// resolves to a forbidden address.
    #[test]
    fn a_backend_whose_address_is_denied_is_refused_with_no_dial() {
        let backend = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        backend.assert_live();
        let before = backend.accepted();
        let backend_ip = backend.addr.ip();
        let backend_port = backend.addr.port();

        // The policy permits some OTHER address, so the backend's own address is denied.
        let permitted_elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let policy = AddressPolicy::permitting(permitted_elsewhere);
        let dial = BackendDial {
            host: backend_ip.to_string(),
            port: backend_port,
            tls: false,
            path_prefix: String::new(),
        };
        let pattern = credentials::DestinationPattern::parse("api.github.com").unwrap();
        let shared = state_with_backends(policy.clone(), vec![(pattern, dial)]);

        let result = open_governed_upstream(
            &shared,
            &connect_to("api.github.com", 443),
            &RequestId::new("t"),
        );
        assert!(
            matches!(result, Err(OpenUpstreamError::Denied(_))),
            "a denied backend address refuses the connect"
        );
        assert_eq!(
            policy.seen(),
            vec![(SocketAddr::new(backend_ip, backend_port), false)],
            "the address check ran on the backend address and denied it"
        );
        assert_eq!(
            backend.accepted(),
            before,
            "the denied backend was never dialled"
        );
    }

    /// A backend that resolves to nothing fails closed, with no fallback to the original destination.
    #[test]
    fn a_backend_that_resolves_to_nothing_fails_closed() {
        // `.invalid` is reserved to never resolve (RFC 2606), so this is deterministic and offline.
        let dial = BackendDial {
            host: "no-such-host.invalid".to_string(),
            port: 443,
            tls: true,
            path_prefix: String::new(),
        };
        let pattern = credentials::DestinationPattern::parse("api.github.com").unwrap();
        let shared = state_with_backends(AddressPolicy::permit_all(), vec![(pattern, dial)]);
        let result = open_governed_upstream(
            &shared,
            &connect_to("api.github.com", 443),
            &RequestId::new("t"),
        );
        assert!(
            matches!(result, Err(OpenUpstreamError::Failed)),
            "a backend that resolves to nothing fails closed"
        );
    }

    /// A CONNECT to a backend host on a port no backend entry covers fails closed, rather than fall
    /// through and dial the ORIGINAL destination. A bare-host pattern covers only 443/80, so `:8443`
    /// matches no backend; without the guard the box would reach `api.github.com:8443` directly.
    #[test]
    fn a_backend_host_on_a_non_backend_port_fails_closed() {
        let backend = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        backend.assert_live();
        let before = backend.accepted();
        let dial = BackendDial {
            host: backend.addr.ip().to_string(),
            port: backend.addr.port(),
            tls: false,
            path_prefix: String::new(),
        };
        // The pattern has no explicit port, so it re-routes `api.github.com` on 443/80 only.
        let pattern = credentials::DestinationPattern::parse("api.github.com").unwrap();
        let shared = state_with_backends(AddressPolicy::permit_all(), vec![(pattern, dial)]);

        // The refusal is reached BEFORE any resolution, so the original host is never looked up.
        let result = open_governed_upstream(
            &shared,
            &connect_to("api.github.com", 8443),
            &RequestId::new("t"),
        );
        assert!(
            matches!(result, Err(OpenUpstreamError::Denied(_))),
            "a re-routed host on a non-backend port is refused, not dialled directly"
        );
        assert_eq!(
            backend.accepted(),
            before,
            "the backend was not dialled either — the port matched no entry"
        );
    }

    #[test]
    fn a_host_a_non_canonical_backend_pattern_names_fails_closed() {
        for written in ["api.github.com.", ".api.github.com", "API.GitHub.com.."] {
            let backend =
                Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
            backend.assert_live();
            let before = backend.accepted();
            let dial = BackendDial {
                host: backend.addr.ip().to_string(),
                port: backend.addr.port(),
                tls: false,
                path_prefix: String::new(),
            };
            let pattern = credentials::DestinationPattern::parse(written).unwrap();
            let shared = state_with_backends(AddressPolicy::permit_all(), vec![(pattern, dial)]);
            assert!(shared.host_reroutes("api.github.com"), "{written:?}");
            assert!(shared.host_reroutes("API.github.com."), "{written:?}");
            assert!(!shared.host_reroutes("github.com"), "{written:?}");

            let result = open_governed_upstream(
                &shared,
                &connect_to("api.github.com", 443),
                &RequestId::new("t"),
            );
            assert!(
                matches!(result, Err(OpenUpstreamError::Denied(_))),
                "{written:?}: the host is refused, not dialled directly"
            );
            assert_eq!(backend.accepted(), before, "{written:?}");
        }
    }

    #[test]
    fn a_remote_mcp_server_classifies_in_any_case_and_with_a_trailing_dot() {
        let mut shared = state(AddressPolicy::permit_all());
        shared.config.mcp_servers = vec![("mcp.example.com".to_string(), "tools".to_string())];
        for host in ["mcp.example.com", "MCP.Example.com", "mcp.example.com."] {
            assert_eq!(shared.mcp_server_for(host), Some("tools"), "{host:?}");
        }
        assert_eq!(shared.mcp_server_for("example.com"), None);
    }

    /// A destination with no backend returns no backend leg, so the upstream leg stays on the
    /// original destination (today's behaviour).
    #[test]
    fn no_backend_returns_no_leg() {
        let recorder = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = recorder.addr.port();
        let ip = recorder.addr.ip();
        let policy = AddressPolicy::permitting(ip);
        let shared = state(policy);
        let correlation = RequestId::new("test");
        // A literal-IP destination resolves to itself, so no DNS and no network.
        let (upstream, backend_leg) =
            open_governed_upstream(&shared, &connect_to(&ip.to_string(), port), &correlation)
                .ok()
                .expect("the destination connects directly");
        assert!(backend_leg.is_none(), "no backend means no re-route leg");
        drop(upstream);
    }
}
