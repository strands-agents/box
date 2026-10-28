//! Runs a selected workload for the benchmark runner.

#![warn(missing_docs, unreachable_pub)]

use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[path = "../protocol.rs"]
mod protocol;

const TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (Some(mode), None) if mode == protocol::STARTUP => startup(),
        (Some(mode), None) if mode == protocol::EGRESS => egress(),
        _ => Err(io::Error::other("usage: box-bench-probe startup|egress")),
    }
}

fn startup() -> io::Result<()> {
    let mut output = io::stdout().lock();
    output.write_all(protocol::READY)?;
    output.flush()?;
    let mut release = [0; protocol::RELEASE.len()];
    io::stdin().read_exact(&mut release)?;
    if release != *protocol::RELEASE {
        return Err(io::Error::other("invalid benchmark release"));
    }
    Ok(())
}

/// Answers each command line on stdin with one line on stdout, until stdin closes.
///
/// Every request goes to the gateway in `HTTP_PROXY` when Box set it, and to the URL's own host
/// otherwise. `NO_PROXY` is ignored, so a loopback upstream also goes through the gateway. The
/// request bytes are the same in both cases: an absolute-form `GET` with `Connection: close`.
fn egress() -> io::Result<()> {
    let proxy = std::env::var("HTTP_PROXY")
        .ok()
        .map(|url| authority(&url).map(str::to_owned))
        .transpose()?;
    let mut output = io::stdout().lock();
    output.write_all(protocol::READY)?;
    output.flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let reply = match line.split_whitespace().collect::<Vec<_>>()[..] {
            [protocol::LOAD, status, url, concurrency, count] => load(
                proxy.as_deref(),
                url,
                status,
                concurrency.parse().map_err(io::Error::other)?,
                count.parse().map_err(io::Error::other)?,
            )?,
            [protocol::STREAM, url] => {
                let (first, total, ok) = exchange(proxy.as_deref(), url, "200")?;
                if !ok {
                    return Err(io::Error::other("the streamed reply was not a 200"));
                }
                format!("{} {}", first.as_nanos(), total.as_nanos())
            }
            _ => return Err(io::Error::other(format!("unknown command: {line}"))),
        };
        writeln!(output, "{reply}")?;
        output.flush()?;
    }
    Ok(())
}

/// Sends `count` requests from `concurrency` threads, each on a new connection.
fn load(
    proxy: Option<&str>,
    url: &str,
    status: &str,
    concurrency: usize,
    count: usize,
) -> io::Result<String> {
    let next = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let started = Instant::now();
    let latencies: Vec<Duration> = thread::scope(|scope| {
        let workers: Vec<_> = (0..concurrency)
            .map(|_| {
                scope.spawn(|| {
                    let mut latencies = Vec::new();
                    while next.fetch_add(1, Ordering::Relaxed) < count {
                        match exchange(proxy, url, status) {
                            Ok((_, total, true)) => latencies.push(total),
                            _ => {
                                failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    latencies
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("load worker"))
            .collect()
    });
    let mut reply = format!("{} {}", started.elapsed().as_nanos(), failures.into_inner());
    for latency in latencies {
        reply.push_str(&format!(" {}", latency.as_nanos()));
    }
    Ok(reply)
}

/// Sends one request and reads the reply to EOF. Returns the time to the first reply byte, the
/// total time, and whether the status is `status`. The clock starts before the connect.
fn exchange(
    proxy: Option<&str>,
    url: &str,
    status: &str,
) -> io::Result<(Duration, Duration, bool)> {
    let host = authority(url)?;
    let request = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let started = Instant::now();
    let mut stream = TcpStream::connect(proxy.unwrap_or(host))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.write_all(request.as_bytes())?;
    let mut buffer = [0; 16 * 1024];
    let mut head = Vec::new();
    let mut first = None;
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        first.get_or_insert_with(|| started.elapsed());
        let wanted = 12usize.saturating_sub(head.len()).min(read);
        head.extend_from_slice(&buffer[..wanted]);
    }
    let total = started.elapsed();
    let first = first.ok_or_else(|| io::Error::other("empty reply"))?;
    Ok((first, total, head.get(9..12) == Some(status.as_bytes())))
}

/// The `host:port` of an `http://` URL.
fn authority(url: &str) -> io::Result<&str> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::other(format!("not an http URL: {url}")))?;
    Ok(rest.split('/').next().unwrap_or(rest))
}
