//! Measures the egress gateway against the same requests sent directly.
//!
//! One `box-bench-probe egress` runs in a box and one runs directly. Both send the same
//! absolute-form requests to a plain-HTTP upstream on `127.0.0.1` that this runner serves: the
//! boxed one through the gateway in `HTTP_PROXY`, the direct one to the upstream itself.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{Fixtures, Running, protocol};

/// Requests in each load, at each concurrency.
const REQUESTS: usize = 2000;
/// Requests refused at the first decision.
const REFUSED: usize = 500;
/// Times the chunked reply is fetched in each mode.
const STREAMS: usize = 5;
const CONCURRENCY: [usize; 3] = [1, 16, 256];
/// The longest one command may take to answer.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const SMALL: &str = "/small";
const CHUNKED: &str = "/chunked";
const CHUNKS: usize = 10;
const CHUNK_INTERVAL: Duration = Duration::from_millis(200);
/// A loopback port no policy permits, so the gateway refuses at the first `net:connect`.
const REFUSED_URL: &str = "http://127.0.0.1:9/small";

/// Serves `/small` and `/chunked` on an ephemeral loopback port, one thread per connection.
fn start_upstream() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve(stream));
        }
    });
    Ok(port)
}

fn serve(mut stream: TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(COMMAND_TIMEOUT))?;
    let mut head = Vec::new();
    let mut buffer = [0; 4096];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 || head.len() > 64 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buffer[..read]);
    }
    let line = String::from_utf8_lossy(&head);
    let target = line.split(' ').nth(1).unwrap_or_default();
    // The gateway forwards origin-form; a direct client sends absolute-form.
    let path = match target.strip_prefix("http://") {
        Some(rest) => rest.find('/').map_or("/", |start| &rest[start..]),
        None => target,
    };
    if path == SMALL {
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    } else if path == CHUNKED {
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )?;
        for index in 0..CHUNKS {
            thread::sleep(CHUNK_INTERVAL);
            let data = format!("chunk {index}\n");
            stream.write_all(format!("{:x}\r\n{data}\r\n", data.len()).as_bytes())?;
        }
        stream.write_all(b"0\r\n\r\n")
    } else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }
}

/// One probe in egress mode, driven one command line at a time.
struct Workload {
    child: Running,
    input: ChildStdin,
    lines: mpsc::Receiver<io::Result<String>>,
    log: PathBuf,
}

impl Workload {
    fn start(mut command: Command, log: PathBuf) -> io::Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(&log)?);
        let mut child = Running(command.spawn()?);
        let input = child.0.stdin.take().expect("piped stdin");
        let output = child.0.stdout.take().expect("piped stdout");
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let workload = Self {
            child,
            input,
            lines,
            log,
        };
        let ready = workload.line()?;
        if format!("{ready}\n").as_bytes() != protocol::READY {
            return Err(workload.failure("invalid readiness marker"));
        }
        Ok(workload)
    }

    fn failure(&self, what: &str) -> io::Error {
        io::Error::other(format!("{what}; stderr: {}", self.log.display()))
    }

    fn line(&self) -> io::Result<String> {
        match self.lines.recv_timeout(COMMAND_TIMEOUT) {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(error)) => Err(self.failure(&error.to_string())),
            Err(_) => Err(self.failure("the workload stopped or timed out")),
        }
    }

    fn ask(&mut self, command: &str) -> io::Result<String> {
        writeln!(self.input, "{command}")?;
        self.input.flush()?;
        self.line()
    }

    fn load(
        &mut self,
        status: u16,
        url: &str,
        concurrency: usize,
        count: usize,
    ) -> io::Result<Load> {
        let reply = self.ask(&format!(
            "{} {status} {url} {concurrency} {count}",
            protocol::LOAD
        ))?;
        let mut numbers = reply.split(' ').map(str::parse::<u128>);
        let mut next = || {
            numbers
                .next()
                .ok_or_else(|| self.failure("short load reply"))?
                .map_err(|error| self.failure(&error.to_string()))
        };
        let elapsed = next()?;
        let failures = next()?;
        let mut latencies = Vec::new();
        for latency in numbers {
            latencies.push(latency.map_err(io::Error::other)? as f64 / 1_000_000.0);
        }
        latencies.sort_by(f64::total_cmp);
        Ok(Load {
            seconds: elapsed as f64 / 1e9,
            failures: failures as usize,
            latencies,
        })
    }

    fn stream(&mut self, url: &str) -> io::Result<(f64, f64)> {
        let reply = self.ask(&format!("{} {url}", protocol::STREAM))?;
        let parsed: Vec<f64> = reply
            .split(' ')
            .map(|value| value.parse::<f64>().map(|nanos| nanos / 1_000_000.0))
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        match parsed[..] {
            [first, total] => Ok((first, total)),
            _ => Err(self.failure("invalid stream reply")),
        }
    }

    /// Close stdin, and wait for a clean exit.
    fn finish(self) -> io::Result<()> {
        let Self {
            mut child,
            input,
            log,
            ..
        } = self;
        drop(input);
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            if let Some(status) = child.0.try_wait()? {
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "workload exited {status}; stderr: {}",
                        log.display()
                    )));
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "exit timed out; stderr: {}",
                    log.display()
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

struct Load {
    seconds: f64,
    failures: usize,
    /// Each successful request, in milliseconds, sorted.
    latencies: Vec<f64>,
}

impl Load {
    fn rate(&self) -> f64 {
        self.latencies.len() as f64 / self.seconds
    }

    /// The nearest-rank percentile, in milliseconds.
    fn percentile(&self, percent: usize) -> f64 {
        let rank = (self.latencies.len() * percent).div_ceil(100).max(1);
        self.latencies.get(rank - 1).copied().unwrap_or(f64::NAN)
    }
}

/// The resident set of `pid` in KiB, from `ps`.
fn resident_kib(pid: u32) -> io::Result<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(io::Error::other)
}

/// Run `work` while sampling the resident set of `pid`, and return the peak in KiB.
fn peak_resident<T>(pid: u32, work: impl FnOnce() -> T) -> (T, u64) {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            let mut peak = 0;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(kib) = resident_kib(pid) {
                    peak = peak.max(kib);
                }
                thread::sleep(Duration::from_millis(10));
            }
            peak
        });
        let result = work();
        stop.store(true, Ordering::Relaxed);
        (result, sampler.join().expect("resident sampler"))
    })
}

fn scoped_policy(port: u16) -> String {
    format!(
        "@id(\"bench_connect\")\n\
         permit (principal, action == Box::Action::\"net:connect\", resource)\n\
         when {{ context.input.host == \"127.0.0.1\" && context.input.port == {port} }};\n\n\
         @id(\"bench_request\")\n\
         permit (principal, action == Box::Action::\"http:request\", resource)\n\
         when {{ context.input.host == \"127.0.0.1\" && context.input.port == {port} }};\n"
    )
}

const PERMISSIVE_POLICY: &str = "@id(\"bench_any\")\n\
     permit (principal, action in [Box::Action::\"net:connect\", Box::Action::\"http:request\"], resource);\n";

/// The scoped policy, after 100 rules that the benchmark requests do not match.
fn crowded_policy(port: u16) -> String {
    let mut policy = String::new();
    for other in 1000..1100 {
        policy.push_str(&format!(
            "@id(\"bench_other_{other}\")\n\
             forbid (principal, action in [Box::Action::\"net:connect\", Box::Action::\"http:request\"], resource)\n\
             when {{ context.input.host == \"127.0.0.1\" && context.input.port == {other} }};\n\n"
        ));
    }
    policy + &scoped_policy(port)
}

fn start_box(
    box_binary: &Path,
    fixtures: &Fixtures,
    probe: &Path,
    index: usize,
    policy: &str,
    output: &Path,
) -> io::Result<Workload> {
    let (config, directory) = fixtures.prepare(index, probe, protocol::EGRESS, policy)?;
    let mut command = Command::new(box_binary);
    command
        .args(["run", "--config"])
        .arg(config)
        .current_dir(directory);
    Workload::start(command, output.join(format!("box-{index}.stderr")))
}

fn milliseconds(value: f64) -> String {
    format!("{value:.3} ms")
}

fn compare(report: &mut String, label: &str, boxed: &Load, direct: &Load) {
    let line = format!(
        "{label}: box {:.1} req/s, direct {:.1} req/s; box p50 {} p99 {}; direct p50 {} p99 {}; \
         added p50 {} p99 {}; failures box {} direct {}\n",
        boxed.rate(),
        direct.rate(),
        milliseconds(boxed.percentile(50)),
        milliseconds(boxed.percentile(99)),
        milliseconds(direct.percentile(50)),
        milliseconds(direct.percentile(99)),
        milliseconds(boxed.percentile(50) - direct.percentile(50)),
        milliseconds(boxed.percentile(99) - direct.percentile(99)),
        boxed.failures,
        direct.failures,
    );
    eprint!("{line}");
    report.push_str(&line);
}

fn alone(report: &mut String, label: &str, boxed: &Load) {
    let line = format!(
        "{label}: box {:.1} req/s; box p50 {} p99 {}; failures {}\n",
        boxed.rate(),
        milliseconds(boxed.percentile(50)),
        milliseconds(boxed.percentile(99)),
        boxed.failures,
    );
    eprint!("{line}");
    report.push_str(&line);
}

fn record(samples: &mut File, scenario: &str, mode: &str, load: &Load) -> io::Result<()> {
    for latency in &load.latencies {
        writeln!(samples, "{scenario},{mode},{latency:.6}")?;
    }
    samples.flush()
}

pub(crate) fn benchmark(box_binary: &Path, output: &Path) -> io::Result<()> {
    let probe = std::env::current_exe()?
        .with_file_name("box-bench-probe")
        .canonicalize()?;
    let port = start_upstream()?;
    let small = format!("http://127.0.0.1:{port}{SMALL}");
    let chunked = format!("http://127.0.0.1:{port}{CHUNKED}");
    let fixtures = Fixtures::new()?;
    let mut samples = File::create(output.join("samples.partial.csv"))?;
    writeln!(samples, "scenario,mode,latency_ms")?;
    let mut report = format!(
        "Plain-HTTP egress through a fresh box against the same requests sent directly.\n\
         {REQUESTS} requests for each load, one connection for each request, a 2-byte reply.\n"
    );

    let mut direct_command = Command::new(&probe);
    direct_command.arg(protocol::EGRESS).env_clear();
    let mut direct = Workload::start(direct_command, output.join("direct.stderr"))?;
    let mut boxed = start_box(
        box_binary,
        &fixtures,
        &probe,
        0,
        &scoped_policy(port),
        output,
    )?;
    let pid = boxed.child.0.id();
    boxed.load(200, &small, 16, 200)?;
    direct.load(200, &small, 16, 200)?;
    for (index, concurrency) in CONCURRENCY.into_iter().enumerate() {
        let measure_box = |boxed: &mut Workload| -> io::Result<(Load, u64, u64)> {
            let idle = resident_kib(pid)?;
            let (load, peak) =
                peak_resident(pid, || boxed.load(200, &small, concurrency, REQUESTS));
            Ok((load?, idle, peak))
        };
        let ((boxed_load, idle, peak), direct_load) = if index % 2 == 0 {
            let boxed_result = measure_box(&mut boxed)?;
            (
                boxed_result,
                direct.load(200, &small, concurrency, REQUESTS)?,
            )
        } else {
            let direct_load = direct.load(200, &small, concurrency, REQUESTS)?;
            (measure_box(&mut boxed)?, direct_load)
        };
        let label = format!("small reply, concurrency {concurrency}");
        compare(&mut report, &label, &boxed_load, &direct_load);
        let line = format!(
            "{label}: strands-box run resident set {idle} KiB before, peak {peak} KiB during\n"
        );
        eprint!("{line}");
        report.push_str(&line);
        record(
            &mut samples,
            &format!("small-c{concurrency}"),
            "box",
            &boxed_load,
        )?;
        record(
            &mut samples,
            &format!("small-c{concurrency}"),
            "direct",
            &direct_load,
        )?;
    }

    let mut first = (Vec::new(), Vec::new());
    let mut total = (Vec::new(), Vec::new());
    for index in 0..STREAMS {
        let (boxed_stream, direct_stream) = if index % 2 == 0 {
            (boxed.stream(&chunked)?, direct.stream(&chunked)?)
        } else {
            let direct_stream = direct.stream(&chunked)?;
            (boxed.stream(&chunked)?, direct_stream)
        };
        first.0.push(boxed_stream.0);
        total.0.push(boxed_stream.1);
        first.1.push(direct_stream.0);
        total.1.push(direct_stream.1);
    }
    let median = |values: &mut Vec<f64>| {
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    };
    let line = format!(
        "chunked reply, {CHUNKS} chunks over {} ms, median of {STREAMS}: \
         box first byte {} total {}; direct first byte {} total {}\n",
        CHUNK_INTERVAL.as_millis() * CHUNKS as u128,
        milliseconds(median(&mut first.0)),
        milliseconds(median(&mut total.0)),
        milliseconds(median(&mut first.1)),
        milliseconds(median(&mut total.1)),
    );
    eprint!("{line}");
    report.push_str(&line);

    let refused = boxed.load(403, REFUSED_URL, 1, REFUSED)?;
    alone(
        &mut report,
        &format!("refused at the first net:connect, concurrency 1, {REFUSED} requests"),
        &refused,
    );
    record(&mut samples, "refused-c1", "box", &refused)?;
    boxed.finish()?;

    let variants = [
        (
            "permissive policy, 1 rule, no condition",
            PERMISSIVE_POLICY.to_owned(),
        ),
        ("crowded policy, 102 rules", crowded_policy(port)),
    ];
    for (index, (name, policy)) in variants.into_iter().enumerate() {
        let mut boxed = start_box(box_binary, &fixtures, &probe, index + 1, &policy, output)?;
        boxed.load(200, &small, 16, 200)?;
        for concurrency in [1, 16] {
            let load = boxed.load(200, &small, concurrency, REQUESTS)?;
            alone(
                &mut report,
                &format!("{name}, concurrency {concurrency}"),
                &load,
            );
            record(
                &mut samples,
                &format!("policy{}-c{concurrency}", index + 1),
                "box",
                &load,
            )?;
        }
        boxed.finish()?;
    }
    direct.finish()?;

    fs::write(output.join("summary.txt"), &report)?;
    drop(samples);
    fs::rename(
        output.join("samples.partial.csv"),
        output.join("samples.csv"),
    )?;
    print!("{report}");
    Ok(())
}
