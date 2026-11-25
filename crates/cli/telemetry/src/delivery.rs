use std::ffi::OsStr;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::Event;

const ENDPOINT: &str = "https://telemetry.strandsagents.com/box/ping";
const PAYLOAD_LIMIT: usize = 12_288;
const BATCH_LIMIT: usize = 32 * 1024;

/// HTTP delivery for one invocation.
pub(crate) struct Delivery {
    client: reqwest::blocking::Client,
    /// Keeps no idle connection, so a batch never rides one that died during the run.
    fresh: reqwest::blocking::Client,
    endpoint: String,
}

pub(crate) fn configured_endpoint() -> Option<String> {
    if cfg!(test) && !cfg!(feature = "test-transport") {
        return None;
    }
    let configured = std::env::var_os("BOX_TEST_TELEMETRY_ENDPOINT");
    destination(cfg!(feature = "test-transport"), configured.as_deref())
}

fn destination(test_transport: bool, configured: Option<&OsStr>) -> Option<String> {
    let Some(configured) = configured else {
        return (!test_transport).then(|| ENDPOINT.to_owned());
    };
    let url = reqwest::Url::parse(configured.to_str()?).ok()?;
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let address: IpAddr = host.parse().ok()?;
    (url.scheme() == "http"
        && address.is_loopback()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}

impl Delivery {
    pub(crate) fn new(
        endpoint: String,
        request_timeout: Duration,
        user_agent: &str,
    ) -> Option<Self> {
        let builder = || {
            let builder = reqwest::blocking::Client::builder()
                .user_agent(user_agent)
                .timeout(request_timeout)
                .connect_timeout(request_timeout)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never());
            if endpoint.starts_with("http://") {
                builder.no_proxy()
            } else {
                builder
            }
        };
        Some(Self {
            client: builder().build().ok()?,
            fresh: builder().pool_max_idle_per_host(0).build().ok()?,
            endpoint,
        })
    }

    /// Send the events once in one request: on the pooled connection during the run, and on a new
    /// connection for a final send, which carries a `deadline` and is limited to the time left.
    pub(crate) fn send_all(&self, events: &[Event], deadline: Option<Instant>) {
        let client = if deadline.is_some() {
            &self.fresh
        } else {
            &self.client
        };
        let body = match events {
            [] => return,
            [event] => encode(event, PAYLOAD_LIMIT),
            _ => encode(events, BATCH_LIMIT),
        };
        self.post(client, body, deadline);
    }

    #[cfg(test)]
    pub(crate) fn send(&self, event: &Event, deadline: Option<Instant>) {
        self.post(&self.client, encode(event, PAYLOAD_LIMIT), deadline);
    }

    fn post(
        &self,
        client: &reqwest::blocking::Client,
        body: Option<Vec<u8>>,
        deadline: Option<Instant>,
    ) {
        let Some(body) = body else {
            return;
        };
        let mut request = client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            request = request.timeout(remaining);
        }
        let _ = request.send();
    }
}

fn encode(value: &(impl Serialize + ?Sized), limit: usize) -> Option<Vec<u8>> {
    let mut body = Body(Vec::with_capacity(PAYLOAD_LIMIT), limit);
    serde_json::to_writer(&mut body, value).ok()?;
    Some(body.0)
}

struct Body(Vec<u8>, usize);

impl Write for Body {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0.len()) {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::time::Instant;

    use super::*;
    use crate::{
        ActionCatalog, ContextBuilder, CoreOutcome, DecisionInterval, ExitOutcome, InstallationId,
        Invocation, LaunchOutcome,
    };

    struct Request {
        line: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    struct Server {
        endpoint: String,
        requests: Receiver<Request>,
        stop: Arc<AtomicBool>,
        done: Receiver<()>,
    }

    impl Server {
        fn start(response: &str, delay: Duration) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}/box/ping", listener.local_addr().unwrap());
            let response = response.to_owned();
            let (sent, requests) = mpsc::channel();
            let (finished, done) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                while !stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if let Some(request) = read_request(&mut stream) {
                                let _ = sent.send(request);
                                std::thread::sleep(delay);
                                let _ = stream.write_all(response.as_bytes());
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
                let _ = finished.send(());
            });
            Self {
                endpoint,
                requests,
                stop,
                done,
            }
        }

        fn delivery(&self, timeout: Duration) -> Delivery {
            Delivery::new(self.endpoint.clone(), timeout, "box/1.2.3").unwrap()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.done.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<Request> {
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut headers = BTreeMap::new();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).ok()?;
            if header == "\r\n" {
                break;
            }
            let (key, value) = header.split_once(':')?;
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length: usize = headers
            .get("content-length")
            .map_or(Some(0), |value| value.parse().ok())?;
        if length > BATCH_LIMIT + 1 {
            return None;
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).ok()?;
        Some(Request {
            line,
            headers,
            body,
        })
    }

    fn invocation() -> Invocation {
        let directory = tempfile::tempdir().unwrap();
        Invocation::new(
            InstallationId::load_or_create(directory.path()).unwrap(),
            ContextBuilder::new("1.2.3").unwrap().finish(),
            Instant::now(),
            std::time::SystemTime::now(),
        )
        .unwrap()
    }

    const OK: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    #[test]
    fn posts_events_once_in_order_without_credentials() {
        let server = Server::start(OK, Duration::ZERO);
        let delivery = server.delivery(Duration::from_secs(1));
        let invocation = invocation();
        let started = Instant::now();
        let polling = DecisionInterval::new(started, ActionCatalog::new([]))
            .finish(started + Duration::from_millis(500), true)
            .unwrap();
        let events = [
            invocation.run_event(LaunchOutcome::Confirmed(None)),
            invocation.polling_event(polling),
            invocation.shutdown_event(Instant::now(), ExitOutcome::Zero, Some(CoreOutcome::Ok)),
        ];
        for event in &events {
            delivery.send(event, None);
        }
        for event in &events {
            let request = server
                .requests
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert_eq!(request.line, "POST /box/ping HTTP/1.1\r\n");
            assert_eq!(request.headers["content-type"], "application/json");
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("cookie"));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
                serde_json::to_value(event).unwrap()
            );
        }
        assert!(
            server
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
    }

    /// A keep-alive receiver that labels each request with the connection it arrived on.
    fn keep_alive_server() -> (String, Receiver<(usize, Vec<u8>)>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/box/ping", listener.local_addr().unwrap());
        let (sent, requests) = mpsc::channel();
        std::thread::spawn(move || {
            for (connection, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { return };
                let sent = sent.clone();
                std::thread::spawn(move || {
                    while let Some(request) = read_request(&mut stream) {
                        if sent.send((connection, request.body)).is_err()
                            || stream
                                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                                .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (endpoint, requests)
    }

    #[test]
    fn final_sends_use_a_new_connection_and_sends_during_the_run_reuse_one() {
        let (endpoint, requests) = keep_alive_server();
        let delivery = Delivery::new(endpoint, Duration::from_secs(2), "box/1.2.3").unwrap();
        let invocation = invocation();
        let next = || requests.recv_timeout(Duration::from_secs(2)).unwrap();
        let body = |events: &[Event]| -> serde_json::Value {
            match events {
                [event] => serde_json::to_value(event).unwrap(),
                _ => serde_json::to_value(events).unwrap(),
            }
        };
        let run = [invocation.run_event(LaunchOutcome::Unknown)];
        let shutdown = [invocation.shutdown_event(Instant::now(), ExitOutcome::Nonzero, None)];
        let pair = [run[0].clone(), shutdown[0].clone()];

        delivery.send_all(&run, None);
        let (warm, _) = next();
        delivery.send_all(&pair, None);
        let (during, sent) = next();
        assert_eq!(
            during, warm,
            "a send during the run reuses the pooled connection"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&sent).unwrap(),
            body(&pair)
        );

        let deadline = || Some(Instant::now() + Duration::from_secs(2));
        let mut finals = Vec::new();
        for events in [&shutdown[..], &pair[..]] {
            delivery.send_all(events, deadline());
            let (connection, sent) = next();
            assert_ne!(connection, warm, "a final send opens a new connection");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&sent).unwrap(),
                body(events)
            );
            finals.push(connection);
        }
        assert_ne!(
            finals[0], finals[1],
            "each final send opens its own connection"
        );
        assert!(requests.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn a_batch_stops_at_its_deadline() {
        let server = Server::start(OK, Duration::from_millis(500));
        let delivery = server.delivery(Duration::from_secs(2));
        let invocation = invocation();
        let events = [
            invocation.run_event(LaunchOutcome::Unknown),
            invocation.shutdown_event(Instant::now(), ExitOutcome::Nonzero, None),
        ];
        let started = Instant::now();
        delivery.send_all(&events, Some(started + Duration::from_millis(150)));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(400), "{elapsed:?}");
        server
            .requests
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn payloads_accept_the_limit_and_refuse_the_next_byte() {
        for limit in [PAYLOAD_LIMIT, BATCH_LIMIT] {
            let at_limit = "x".repeat(limit - 2);
            assert_eq!(encode(&at_limit, limit).unwrap().len(), limit);
            assert!(encode(&(at_limit + "x"), limit).is_none());
            let escaped = "\n".repeat(limit / 2);
            assert!(encode(&escaped, limit).is_none());
        }
    }

    #[test]
    fn errors_and_redirects_get_one_attempt_without_following_location() {
        let destination = Server::start(OK, Duration::ZERO);
        for status in [
            "302 Found",
            "307 Temporary Redirect",
            "400 Bad Request",
            "403 Forbidden",
            "429 Too Many Requests",
            "500 Internal Server Error",
        ] {
            let response = format!(
                "HTTP/1.1 {status}\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                destination.endpoint
            );
            let server = Server::start(&response, Duration::ZERO);
            let delivery = server.delivery(Duration::from_secs(1));
            delivery.send(&invocation().run_event(LaunchOutcome::Unknown), None);
            assert!(
                server.requests.recv_timeout(Duration::from_secs(1)).is_ok(),
                "{status}"
            );
            assert!(
                server
                    .requests
                    .recv_timeout(Duration::from_millis(50))
                    .is_err()
            );
        }
        assert!(destination.requests.try_recv().is_err());
    }

    #[test]
    fn request_timeout_does_not_retry_an_ambiguous_failure() {
        let server = Server::start(OK, Duration::from_millis(250));
        let delivery = server.delivery(Duration::from_millis(40));
        let started = Instant::now();
        delivery.send(&invocation().run_event(LaunchOutcome::Unknown), None);
        assert!(started.elapsed() < Duration::from_millis(200));
        server
            .requests
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(
            server
                .requests
                .recv_timeout(Duration::from_millis(350))
                .is_err()
        );
    }

    #[test]
    fn endpoint_overrides_accept_only_loopback_http_without_credentials_in_every_build() {
        for test_transport in [false, true] {
            for endpoint in [
                "http://127.0.0.1:8080/box/ping",
                "http://127.0.0.2:8080/box/ping",
                "http://[::1]:8080/box/ping",
            ] {
                assert_eq!(
                    destination(test_transport, Some(OsStr::new(endpoint))).as_deref(),
                    Some(endpoint)
                );
            }
            for endpoint in [
                "",
                "http://localhost:8080/box/ping",
                "http://192.0.2.1/box/ping",
                "http://[2001:db8::1]/box/ping",
                "https://127.0.0.1/box/ping",
                "http://name@127.0.0.1/box/ping",
                "http://:password@127.0.0.1/box/ping",
                "file:///box/ping",
                "not a URL",
            ] {
                assert!(
                    destination(test_transport, Some(OsStr::new(endpoint))).is_none(),
                    "test_transport={test_transport}, endpoint={endpoint:?}"
                );
            }
        }
        assert!(destination(true, None).is_none());
        assert_eq!(destination(false, None).as_deref(), Some(ENDPOINT));
    }

    #[test]
    #[cfg(unix)]
    fn a_non_utf8_endpoint_override_disables_delivery_in_every_build() {
        use std::os::unix::ffi::OsStrExt as _;

        for test_transport in [false, true] {
            assert!(destination(test_transport, Some(OsStr::from_bytes(b"\xff"))).is_none());
        }
    }

    #[test]
    #[cfg(not(feature = "test-transport"))]
    fn test_builds_do_not_start_production_delivery() {
        assert!(configured_endpoint().is_none());
    }
}
