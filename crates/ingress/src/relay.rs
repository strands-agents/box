use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::workload::ConnectError;
use crate::{IngressConfig, IngressError};

/// A running inbound relay. Dropping it stops accepting.
#[derive(Debug)]
pub struct Ingress {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// How long the relay waits after an `accept` error, such as no descriptor left, before it accepts
/// again.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

impl Ingress {
    /// Relay each caller to the workload, on the current Tokio runtime, until dropped.
    pub fn start(config: IngressConfig) -> Result<Self, IngressError> {
        let IngressConfig {
            source,
            workload,
            connection_limit,
        } = config;
        let mut callers = source.open()?;
        let workload = Arc::new(workload);
        let permits = Arc::new(tokio::sync::Semaphore::new(connection_limit));
        let refusing = Arc::new(AtomicBool::new(false));
        let (shutdown, mut cancelled) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let permit = tokio::select! {
                    biased;
                    _ = &mut cancelled => return,
                    permit = Arc::clone(&permits).acquire_owned() => permit,
                };
                let Ok(permit) = permit else { return };
                let accepted = tokio::select! {
                    biased;
                    _ = &mut cancelled => return,
                    accepted = callers.next() => accepted,
                };
                let mut caller = match accepted {
                    Ok(caller) => caller,
                    Err(error) => {
                        drop(permit);
                        eprintln!(
                            "strands-box: [ingress] accepting a caller failed: {error}; retrying in {} s",
                            ACCEPT_BACKOFF.as_secs()
                        );
                        tokio::select! {
                            biased;
                            _ = &mut cancelled => return,
                            () = tokio::time::sleep(ACCEPT_BACKOFF) => continue,
                        }
                    }
                };
                let workload = Arc::clone(&workload);
                let refusing = Arc::clone(&refusing);
                tokio::spawn(async move {
                    let _permit = permit;
                    // A caller the workload cannot take sees a closed connection, and retries.
                    let mut connection = match workload.connect().await {
                        Ok(connection) => {
                            refusing.store(false, Ordering::Relaxed);
                            connection
                        }
                        Err(error) => {
                            if !refusing.swap(true, Ordering::Relaxed) {
                                eprintln!(
                                    "strands-box: [ingress] {}",
                                    refusal(&error, workload.port())
                                );
                            }
                            return;
                        }
                    };
                    let _ = tokio::io::copy_bidirectional(&mut caller, &mut connection).await;
                });
            }
        });
        Ok(Self {
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
}

/// What a caller's closed connection means, said once until a caller is served again.
fn refusal(error: &ConnectError, port: u16) -> String {
    match error {
        ConnectError::NotReady => format!(
            "nothing accepts on the agent's port {port} on 127.0.0.1; callers are closed until \
             it does"
        ),
        ConnectError::Fatal => {
            "the channel to the agent's sandbox is closed; every caller is closed".to_string()
        }
    }
}

impl Drop for Ingress {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::{IngressConfig, Source, Workload};

    use super::Ingress;

    /// A workload that answers each connection with its request, uppercased.
    fn uppercase_server() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind workload");
        let port = listener.local_addr().expect("address").port();
        std::thread::spawn(move || serve_uppercase(listener));
        port
    }

    fn serve_uppercase(listener: std::net::TcpListener) {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            let mut buffer = [0u8; 64];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let reply = String::from_utf8_lossy(&buffer[..read]).to_uppercase();
            let _ = stream.write_all(reply.as_bytes());
        }
    }

    #[cfg(target_os = "linux")]
    fn workload_at(port: u16, refusals: usize) -> Workload {
        use crate::workload::fake_pid_one::{Answer, fake_pid_one};
        let mut answers = vec![Answer::Refuse; refusals];
        answers.extend([Answer::Socket; 8]);
        Workload::in_namespace(fake_pid_one(answers), port).expect("workload")
    }

    #[cfg(target_os = "macos")]
    fn workload_at(port: u16, _refusals: usize) -> Workload {
        Workload::loopback(port)
    }

    fn start(workload: Workload) -> (Ingress, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind source");
        let port = listener.local_addr().expect("address").port();
        let ingress =
            Ingress::start(IngressConfig::new(Source::tcp(listener), workload)).expect("start");
        (ingress, port)
    }

    /// Send `request` as a caller, and return what came back before the relay closed.
    async fn call(port: u16, request: &'static [u8]) -> Vec<u8> {
        let exchange = tokio::task::spawn_blocking(move || {
            let mut caller = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
            caller.write_all(request).expect("write");
            let mut reply = Vec::new();
            let _ = caller.read_to_end(&mut reply);
            reply
        });
        tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .expect("the relay answers rather than hangs")
            .expect("the caller thread does not panic")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_reaches_the_workload_and_its_reply_comes_back() {
        let (_ingress, port) = start(workload_at(uppercase_server(), 0));
        assert_eq!(call(port, b"ping").await, b"PING");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_the_workload_cannot_take_is_closed_and_the_next_one_is_served() {
        let (_ingress, port) = start(workload_at(uppercase_server(), 1));
        assert_eq!(
            call(port, b"early").await,
            b"",
            "the refused caller sees a close"
        );
        assert_eq!(call(port, b"later").await, b"LATER");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_the_workload_cannot_take_is_closed_and_the_next_one_is_served() {
        let unused = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let workload_port = unused.local_addr().expect("address").port();
        drop(unused);
        let (_ingress, port) = start(workload_at(workload_port, 0));
        assert_eq!(
            call(port, b"early").await,
            b"",
            "the refused caller sees a close"
        );

        let listener = std::net::TcpListener::bind(("127.0.0.1", workload_port)).expect("rebind");
        std::thread::spawn(move || serve_uppercase(listener));
        assert_eq!(call(port, b"later").await, b"LATER");
    }

    /// A workload that holds each connection open until the caller closes it.
    fn holding_server() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind workload");
        let port = listener.local_addr().expect("address").port();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                std::thread::spawn(move || {
                    let mut sink = [0u8; 64];
                    while stream.read(&mut sink).is_ok_and(|read| read > 0) {}
                });
            }
        });
        port
    }

    /// A workload that serves each connection on its own thread, and counts the connections that
    /// reach it.
    fn counting_server() -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind workload");
        let port = listener.local_addr().expect("address").port();
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reached);
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 64];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    let reply = String::from_utf8_lossy(&buffer[..read]).to_uppercase();
                    let _ = stream.write_all(reply.as_bytes());
                });
            }
        });
        (port, reached)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_beyond_the_limit_waits_until_one_closes() {
        let (workload_port, reached) = counting_server();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind source");
        let port = listener.local_addr().expect("address").port();
        let config = IngressConfig::new(Source::tcp(listener), workload_at(workload_port, 0))
            .connection_limit(1);
        let _ingress = Ingress::start(config).expect("start");
        let holder = std::net::TcpStream::connect(("127.0.0.1", port)).expect("first caller");
        tokio::time::timeout(Duration::from_secs(5), async {
            while reached.load(Ordering::SeqCst) < 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the first caller reaches the workload");

        let second = tokio::spawn(call(port, b"next"));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            reached.load(Ordering::SeqCst),
            1,
            "a caller beyond the limit does not reach the workload"
        );
        assert!(
            !second.is_finished(),
            "a caller beyond the limit is not served yet"
        );
        drop(holder);
        assert_eq!(second.await.expect("the second caller"), b"NEXT");
        assert_eq!(reached.load(Ordering::SeqCst), 2);
    }

    /// The CPU time this process has used.
    fn cpu_time() -> Duration {
        // SAFETY: `getrusage` writes one `rusage` into the local.
        let usage = unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
            usage
        };
        let time = |value: libc::timeval| {
            Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64)
        };
        time(usage.ru_utime) + time(usage.ru_stime)
    }

    /// The workload port the parent passes to `exhausted_descriptor_limit_child`.
    const WORKLOAD_PORT: &str = "INGRESS_TEST_WORKLOAD_PORT";

    /// Run in a child process with a low descriptor limit, while the parent holds more callers open
    /// than that limit allows: the relay must not spin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "run by an_exhausted_descriptor_limit_does_not_spin, in its own process"]
    async fn exhausted_descriptor_limit_child() {
        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        // SAFETY: `setrlimit` reads one `rlimit` from the local; this process is the test's child.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind source");
        let port = listener.local_addr().expect("address").port();
        let workload_port = std::env::var(WORKLOAD_PORT)
            .expect("the parent passes the workload port")
            .parse()
            .expect("a port");
        let config = IngressConfig::new(Source::tcp(listener), workload_at(workload_port, 0))
            .connection_limit(1_000);
        let _ingress = Ingress::start(config).expect("start");
        // Every descriptor left is taken, so `accept` fails while the parent's callers wait in the
        // queue.
        let mut taken = Vec::new();
        while let Ok(file) = std::fs::File::open("/dev/null") {
            taken.push(file);
        }
        println!("PORT={port}");
        std::io::Write::flush(&mut std::io::stdout()).expect("flush");
        tokio::time::sleep(Duration::from_secs(1)).await;
        let before = cpu_time();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let used = cpu_time() - before;
        drop(taken);
        assert!(
            used < Duration::from_millis(500),
            "the relay used {used:?} of CPU in 3 s"
        );
    }

    #[test]
    fn an_exhausted_descriptor_limit_does_not_spin() {
        use std::io::BufRead as _;
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "relay::tests::exhausted_descriptor_limit_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(WORKLOAD_PORT, holding_server().to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the child runs");
        let mut lines = std::io::BufReader::new(child.stdout.take().expect("stdout")).lines();
        let port = lines
            .by_ref()
            .map_while(Result::ok)
            .find_map(|line| {
                line.split_once("PORT=")
                    .map(|(_, port)| port.trim().parse::<u16>())
            })
            .expect("the child prints its port")
            .expect("a port");
        let callers = (0..20)
            .filter_map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).ok())
            .collect::<Vec<_>>();
        assert!(!callers.is_empty(), "no caller connected");
        let rest = lines.map_while(Result::ok).collect::<Vec<_>>().join("\n");
        let output = child.wait_with_output().expect("the child exits");
        drop(callers);
        assert!(
            output.status.success(),
            "{rest}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_relay_closes_its_source() {
        let (ingress, port) = start(workload_at(uppercase_server(), 0));
        drop(ingress);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the source still accepts after the relay is dropped"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
