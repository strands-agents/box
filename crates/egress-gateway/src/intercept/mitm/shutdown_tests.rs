//! Shutdown coverage for live connection workers and their terminal records.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{Connections, accept_loop};
use crate::capability::CapabilitySet;
use crate::effect::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit};
use crate::intercept::mitm::handle::BoundTransport;
use crate::intercept::mitm::{MitmConfig, MitmHandle, SharedState, body, ca, tls};
use crate::seams::StubEmitter;

const WAIT: Duration = Duration::from_secs(5);

trait Client: Read + Write {}
impl<T: Read + Write> Client for T {}

struct Allow;
struct Allowed;

impl EffectInterceptor for Allow {
    fn intercept(&self, _: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        Ok(Box::new(Allowed))
    }
}

impl EffectPermit for Allowed {
    fn record_outcome(self: Box<Self>, _: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

struct Gateway {
    handle: Option<MitmHandle>,
    connections: Arc<Connections>,
    accepted: mpsc::Receiver<()>,
    unix_path: Option<PathBuf>,
    client_config: Arc<rustls::ClientConfig>,
}

impl Gateway {
    fn start(unix: bool, max: usize, policy: Arc<dyn EffectInterceptor>) -> Self {
        Self::start_with_deadline(unix, max, policy, Duration::from_secs(2), &[])
    }

    fn start_with_deadline(
        unix: bool,
        max: usize,
        policy: Arc<dyn EffectInterceptor>,
        upstream_read_deadline: Duration,
        upstream_ca_pems: &[String],
    ) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let config = MitmConfig {
            max_connections: max,
            upstream_read_deadline,
            ..MitmConfig::default()
        };
        let ca = ca::EphemeralCa::generate(None, None).unwrap();
        let client_config =
            Arc::new(tls::upstream_client_config(&[ca.ca_cert_pem().to_string()]).unwrap());
        let state = Arc::new(SharedState {
            controls: CapabilitySet::default(),
            config,
            ca,
            upstream_config: Arc::new(tls::upstream_client_config(upstream_ca_pems).unwrap()),
            emitter: Box::new(StubEmitter::new()),
            effect_interceptor: policy,
            reply_copies: Arc::new(body::CopyBudget::for_limit(1024)),
        });
        let connections = Arc::new(Connections::new(max));
        let worker_connections = connections.clone();
        let (arrived, accepted) = mpsc::channel();
        let (transport, worker, unix_path) = if unix {
            let path = std::env::temp_dir().join(format!(
                "gw-drain-{}-{}.sock",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let listener = UnixListener::bind(&path).unwrap();
            let worker = thread::spawn(move || {
                let incoming = listener.incoming().inspect(|connection| {
                    if connection.is_ok() {
                        let _ = arrived.send(());
                    }
                });
                accept_loop(incoming, state, worker_connections, true);
            });
            (BoundTransport::Unix(path.clone()), worker, Some(path))
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let worker = thread::spawn(move || {
                let incoming = listener.incoming().inspect(|connection| {
                    if connection.is_ok() {
                        let _ = arrived.send(());
                    }
                });
                accept_loop(incoming, state, worker_connections, false);
            });
            (BoundTransport::Tcp(port), worker, None)
        };
        Self {
            handle: Some(MitmHandle::new(
                transport,
                None,
                connections.clone(),
                worker,
            )),
            connections,
            accepted,
            unix_path,
            client_config,
        }
    }

    fn connect(&self) -> Box<dyn Client> {
        let handle = self.handle.as_ref().unwrap();
        if let Some(port) = handle.port() {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(WAIT)).unwrap();
            socket.set_write_timeout(Some(WAIT)).unwrap();
            Box::new(socket)
        } else {
            let socket = UnixStream::connect(handle.unix_socket_path().unwrap()).unwrap();
            socket.set_read_timeout(Some(WAIT)).unwrap();
            socket.set_write_timeout(Some(WAIT)).unwrap();
            Box::new(socket)
        }
    }

    fn wait_registered(&self, count: usize) {
        let deadline = Instant::now() + WAIT;
        loop {
            if self.connections.state.lock().unwrap().sockets.len() == count {
                return;
            }
            assert!(Instant::now() < deadline, "connection was not registered");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn drop_in_background(&mut self) -> (JoinHandle<()>, mpsc::Receiver<()>) {
        let handle = self.handle.take().unwrap();
        let (began, started) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let worker = thread::spawn(move || {
            handle.shutdown();
            began.send(()).unwrap();
            drop(handle);
            finished.send(()).unwrap();
        });
        started.recv_timeout(WAIT).expect("shutdown did not start");
        (worker, done)
    }

    fn stop(&mut self) {
        let (worker, done) = self.drop_in_background();
        done.recv_timeout(WAIT)
            .expect("gateway did not finish shutdown");
        worker.join().unwrap();
        assert!(self.connections.state.lock().unwrap().sockets.is_empty());
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        drop(self.handle.take());
        if let Some(path) = &self.unix_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn assert_closed(client: &mut dyn Client) {
    let mut byte = [0; 1];
    match client.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("client remained open after shutdown: {result:?}"),
    }
}

fn read_head(client: &mut dyn Client) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() <= 4096, "unexpected response head");
    }
    head
}

#[test]
fn shutdown_joins_idle_and_partial_header_clients_on_both_transports() {
    for unix in [false, true] {
        for prefix in [
            b"".as_slice(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: ",
        ] {
            let mut gateway = Gateway::start(unix, 1, Arc::new(Allow));
            let mut client = gateway.connect();
            client.write_all(prefix).unwrap();
            gateway.accepted.recv_timeout(WAIT).unwrap();
            gateway.wait_registered(1);
            gateway.stop();
            assert_closed(client.as_mut());
        }
    }
}

#[test]
fn shutdown_wakes_full_capacity_admission_on_both_transports() {
    for unix in [false, true] {
        let mut gateway = Gateway::start(unix, 1, Arc::new(Allow));
        let mut first = gateway.connect();
        gateway.accepted.recv_timeout(WAIT).unwrap();
        gateway.wait_registered(1);
        let mut second = gateway.connect();
        gateway.accepted.recv_timeout(WAIT).unwrap();
        assert_eq!(gateway.connections.state.lock().unwrap().sockets.len(), 1);
        gateway.stop();
        assert_closed(first.as_mut());
        assert_closed(second.as_mut());
    }
}

#[test]
fn shutdown_joins_an_incomplete_tls_handshake_on_both_transports() {
    for unix in [false, true] {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let mut gateway = Gateway::start(unix, 1, Arc::new(Allow));
        let mut client = gateway.connect();
        write!(
            client,
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        let head = read_head(client.as_mut());
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "CONNECT was not admitted"
        );
        let (mut origin, _) = upstream.accept().unwrap();
        origin.set_read_timeout(Some(WAIT)).unwrap();
        client.write_all(&[0x16, 0x03, 0x01]).unwrap();
        gateway.wait_registered(1);
        gateway.stop();
        assert_closed(client.as_mut());
        let mut byte = [0; 1];
        assert_eq!(
            origin.read(&mut byte).unwrap(),
            0,
            "upstream survived its worker"
        );
    }
}

struct OutcomeBarrier {
    entered: mpsc::Sender<EffectOutcome>,
    release: Arc<(Mutex<bool>, Condvar)>,
    completed: Arc<AtomicBool>,
}

impl EffectInterceptor for OutcomeBarrier {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if matches!(attempt, EffectAttempt::HttpRequest { .. }) {
            Ok(Box::new(OutcomeBarrier {
                entered: self.entered.clone(),
                release: self.release.clone(),
                completed: self.completed.clone(),
            }))
        } else {
            Ok(Box::new(Allowed))
        }
    }
}

impl EffectPermit for OutcomeBarrier {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        self.entered.send(outcome).unwrap();
        let (lock, ready) = &*self.release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = ready.wait(released).unwrap();
        }
        self.completed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        let _ = self
            .entered
            .send(EffectOutcome::Indeterminate { accepted_bytes: 0 });
    }
}

struct ReleaseOutcome(Arc<(Mutex<bool>, Condvar)>);

impl ReleaseOutcome {
    fn release(&self) {
        let (lock, ready) = &*self.0;
        *lock.lock().unwrap() = true;
        ready.notify_all();
    }
}

impl Drop for ReleaseOutcome {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
fn handle_drop_waits_for_the_terminal_request_record() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    let origin = thread::spawn(move || {
        let (mut socket, _) = upstream.accept().unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        read_head(&mut socket);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let (entered, recording) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let completed = Arc::new(AtomicBool::new(false));
    let mut gateway = Gateway::start(
        false,
        1,
        Arc::new(OutcomeBarrier {
            entered,
            release: release.clone(),
            completed: completed.clone(),
        }),
    );
    let release = ReleaseOutcome(release);
    let mut client = gateway.connect();
    write!(client, "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
    let outcome = recording
        .recv_timeout(WAIT)
        .expect("request outcome was not reached");
    assert!(
        matches!(outcome, EffectOutcome::Replied { status: 200, .. }),
        "wrong terminal outcome: {outcome:?}"
    );
    let (worker, done) = gateway.drop_in_background();
    let returned_early = done.recv_timeout(Duration::from_millis(100)).is_ok();
    release.release();
    if !returned_early {
        done.recv_timeout(WAIT)
            .expect("gateway did not join the released recorder");
    }
    worker.join().unwrap();
    origin.join().unwrap();
    assert!(
        !returned_early,
        "handle returned while its terminal recorder was blocked"
    );
    assert!(
        completed.load(Ordering::SeqCst),
        "terminal record did not finish"
    );
    assert!(gateway.connections.state.lock().unwrap().sockets.is_empty());
}

struct ReleaseRecorder(mpsc::Sender<EffectOutcome>);

impl EffectInterceptor for ReleaseRecorder {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if matches!(attempt, EffectAttempt::ResponseRelease { .. }) {
            Ok(Box::new(Self(self.0.clone())))
        } else {
            Ok(Box::new(Allowed))
        }
    }
}

impl EffectPermit for ReleaseRecorder {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        self.0.send(outcome).unwrap();
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        let _ = self
            .0
            .send(EffectOutcome::Indeterminate { accepted_bytes: 0 });
    }
}

#[test]
fn shutdown_finishes_a_stalled_upstream_body_before_returning_on_both_transports() {
    for unix in [false, true] {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let origin_ca = ca::EphemeralCa::generate(None, None).unwrap();
        let origin_config = Arc::new(tls::server_config_for_host(&origin_ca, "127.0.0.1").unwrap());
        let origin_pem = origin_ca.ca_cert_pem().to_string();
        let (close_origin, held_open) = mpsc::channel();
        let origin = thread::spawn(move || {
            let (socket, _) = upstream.accept().unwrap();
            socket.set_read_timeout(Some(WAIT)).unwrap();
            socket.set_write_timeout(Some(WAIT)).unwrap();
            let mut stream: Box<dyn Client> = if unix {
                Box::new(rustls::StreamOwned::new(
                    rustls::ServerConnection::new(origin_config).unwrap(),
                    socket,
                ))
            } else {
                Box::new(socket)
            };
            read_head(stream.as_mut());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx")
                .unwrap();
            stream.flush().unwrap();
            // Keep the final byte and EOF unavailable until after gateway shutdown.
            // Dropping the sender also releases this thread if an assertion fails.
            let _ = held_open.recv();
        });
        let (recorded, recording) = mpsc::channel();
        let mut gateway = Gateway::start_with_deadline(
            unix,
            1,
            Arc::new(ReleaseRecorder(recorded)),
            Duration::from_millis(700),
            &[origin_pem],
        );
        let mut client = gateway.connect();
        if unix {
            write!(
                client,
                "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
            )
            .unwrap();
            let connected = read_head(client.as_mut());
            assert!(
                connected.starts_with(b"HTTP/1.1 200"),
                "Unix CONNECT was not admitted: {}",
                String::from_utf8_lossy(&connected)
            );
            client = Box::new(rustls::StreamOwned::new(
                rustls::ClientConnection::new(
                    gateway.client_config.clone(),
                    rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                )
                .unwrap(),
                client,
            ));
            write!(
                client,
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        } else {
            write!(client, "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
        }
        client.flush().unwrap();
        let head = read_head(client.as_mut());
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "the upstream response must reach the client before shutdown (unix={unix}): {}",
            String::from_utf8_lossy(&head)
        );
        gateway.wait_registered(1);
        assert!(
            matches!(recording.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "the stalled response must still be awaiting its terminal record"
        );
        let started = Instant::now();
        let (worker, done) = gateway.drop_in_background();
        done.recv_timeout(WAIT)
            .expect("the upstream deadline must let gateway shutdown finish");
        worker.join().unwrap();
        assert!(started.elapsed() < WAIT, "shutdown exceeded its test bound");
        let outcome = recording
            .try_recv()
            .expect("gateway returned before recording the response outcome");
        assert!(
            matches!(
                outcome,
                EffectOutcome::Partial { accepted_bytes, .. }
                    | EffectOutcome::Indeterminate { accepted_bytes }
                    if accepted_bytes > 0
            ),
            "the incomplete response needs an observed terminal record: {outcome:?}"
        );
        let extra = recording.try_recv();
        assert!(
            matches!(
                extra,
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected)
            ),
            "the response must have exactly one terminal record: {extra:?}"
        );
        assert!(gateway.connections.state.lock().unwrap().sockets.is_empty());
        assert!(
            !origin.is_finished(),
            "the origin must not supply EOF first"
        );
        close_origin.send(()).unwrap();
        origin.join().unwrap();
    }
}
