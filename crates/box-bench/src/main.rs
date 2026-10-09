//! Measures fresh Box startup through a contained workload's readiness marker.

#![warn(missing_docs, unreachable_pub)]

mod protocol;

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HELP: &str = "\
Usage: box-bench --box-bin PATH [--iterations N] [--output DIRECTORY] [--timeout-secs N]

Measure fresh box state with warm operating system caches.
Use release builds of Box, its sibling binaries, and both benchmark binaries.
Build this crate with:
  cargo build --release --all-features --manifest-path crates/box-bench/Cargo.toml

--box-bin PATH       Built strands-box executable; required.
--iterations N       Measured pairs after one warmup pair; default 100.
--output DIRECTORY   New result directory; default target/results/<run> in this crate.
--timeout-secs N     Deadline for readiness and, separately, exit; default 30.

Each pair runs box-bench-probe startup in a fresh box and directly, alternating order.
The clock starts before spawn and stops when the runner reads READY from stdout.
Configuration, warmup, and shutdown are outside the reported startup duration.
Stderr goes to per-launch files. Samples and metadata remain in the result directory.
Only a fully successful run produces samples.csv and summary.txt.
";

struct Options {
    box_binary: PathBuf,
    iterations: usize,
    output: PathBuf,
    timeout: Duration,
}

impl Options {
    fn parse() -> io::Result<Option<Self>> {
        let mut args = env::args_os().skip(1);
        let mut box_binary = None;
        let mut iterations = 100;
        let mut timeout = 30;
        let mut output = None;
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                print!("{HELP}");
                return Ok(None);
            }
            let value = args
                .next()
                .ok_or_else(|| io::Error::other(format!("missing value for {flag:?}")))?;
            match flag.to_str() {
                Some("--box-bin") => box_binary = Some(PathBuf::from(value)),
                Some("--output") => output = Some(PathBuf::from(value)),
                Some("--iterations") => {
                    iterations = value
                        .to_string_lossy()
                        .parse::<usize>()
                        .map_err(io::Error::other)?;
                }
                Some("--timeout-secs") => {
                    timeout = value
                        .to_string_lossy()
                        .parse::<u64>()
                        .map_err(io::Error::other)?;
                }
                _ => return Err(io::Error::other(format!("unknown option {flag:?}"))),
            }
        }
        if iterations == 0 || iterations > 100_000 || !(1..=3600).contains(&timeout) {
            return Err(io::Error::other(
                "iterations must be 1..=100000; timeout must be 1..=3600 seconds",
            ));
        }
        Ok(Some(Self {
            box_binary: box_binary
                .ok_or_else(|| io::Error::other("--box-bin is required; use --help"))?
                .canonicalize()?,
            iterations,
            output: output.unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("target/results")
                    .join(run_id())
            }),
            timeout: Duration::from_secs(timeout),
        }))
    }
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

struct Fixtures(PathBuf);

impl Fixtures {
    fn new() -> io::Result<Self> {
        let path = Path::new("/var/tmp")
            .canonicalize()?
            .join(format!("bb-{}", run_id()));
        private_directory(&path)?;
        Ok(Self(path))
    }

    fn prepare(&self, index: usize, probe: &Path) -> io::Result<(PathBuf, PathBuf)> {
        let directory = self.0.join(index.to_string());
        private_directory(&directory)?;
        let box_directory = directory.join("box");
        private_directory(&box_directory)?;
        let workspace = directory.join("workspace");
        private_directory(&workspace)?;
        fs::write(
            directory.join("policy.dw"),
            "forbid(principal, action, resource);\n",
        )?;
        let config = directory.join("box.toml");
        fs::write(
            &config,
            format!(
                "name = \"startup\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
             [agent]\ncommand = [{}, \"{}\"]\nworkspace = {}\n",
                toml_path(&box_directory)?,
                toml_path(probe)?,
                protocol::STARTUP,
                toml_path(&workspace)?,
            ),
        )?;
        Ok((config, workspace))
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove fixture directory {:?}: {error}", self.0);
        }
    }
}

fn toml_path(path: &Path) -> io::Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| io::Error::other("fixture paths must be UTF-8"))?;
    if text.contains(['\'', '\n', '\r']) || text.chars().any(char::is_control) {
        return Err(io::Error::other(
            "fixture paths cannot contain quotes or control characters",
        ));
    }
    Ok(format!("'{text}'"))
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn measure(mut command: Command, log: &Path, timeout: Duration) -> io::Result<Duration> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(File::create(log)?);
    let (pipe_sender, pipe_receiver) = mpsc::channel::<std::process::ChildStdout>();
    let (ready_sender, ready_receiver) = mpsc::channel();
    thread::spawn(move || {
        if let Ok(mut pipe) = pipe_receiver.recv() {
            let mut marker = [0; protocol::READY.len()];
            let result = pipe.read_exact(&mut marker).and_then(|()| {
                if marker == *protocol::READY {
                    Ok(())
                } else {
                    Err(io::Error::other("invalid readiness marker"))
                }
            });
            let _ = ready_sender.send((Instant::now(), result));
        }
    });
    let started = Instant::now();
    let mut child = Running(command.spawn()?);
    pipe_sender
        .send(child.0.stdout.take().expect("piped stdout"))
        .map_err(io::Error::other)?;
    let (ready, marker) = ready_receiver
        .recv_timeout(timeout.saturating_sub(started.elapsed()))
        .map_err(|error| {
            io::Error::other(format!(
                "readiness failed: {error}; stderr: {}",
                log.display()
            ))
        })?;
    marker.map_err(|error| io::Error::other(format!("{error}; stderr: {}", log.display())))?;
    let elapsed = ready.duration_since(started);
    if elapsed > timeout {
        return Err(io::Error::other(format!(
            "readiness exceeded its deadline; stderr: {}",
            log.display()
        )));
    }
    child
        .0
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(protocol::RELEASE)?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(format!(
                    "launch exited {status}; stderr: {}",
                    log.display()
                )));
            }
            return Ok(elapsed);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "exit timed out; stderr: {}",
                log.display()
            )));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn sha256(path: &Path) -> io::Result<String> {
    let output = match Command::new("sha256sum").arg(path).output() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()?,
        result => result?,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let hash = text.split_whitespace().next().unwrap_or("");
    if !output.status.success()
        || hash.len() != 64
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::other(format!("cannot hash {}", path.display())));
    }
    Ok(hash.to_owned())
}

struct Pinned(Vec<(PathBuf, String)>);

impl Pinned {
    fn new(binaries: Vec<PathBuf>) -> io::Result<Self> {
        binaries
            .into_iter()
            .map(|path| {
                let hash = sha256(&path)?;
                Ok((path, hash))
            })
            .collect::<io::Result<_>>()
            .map(Self)
    }

    fn record(&self, output: &mut impl Write) -> io::Result<()> {
        for (binary, hash) in &self.0 {
            writeln!(output, "binary={binary:?} sha256={hash}")?;
        }
        Ok(())
    }

    fn verify(&self) -> io::Result<()> {
        for (binary, hash) in &self.0 {
            if sha256(binary)? != *hash {
                return Err(io::Error::other(format!(
                    "binary changed during measurement: {}",
                    binary.display()
                )));
            }
        }
        Ok(())
    }
}

fn summary(label: &str, values: &mut [f64]) -> String {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    let median = if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    };
    let p95 = values[(values.len() * 95).div_ceil(100) - 1];
    format!("{label}: median {median:.3} ms, p95 {p95:.3} ms")
}

fn benchmark(options: &Options) -> io::Result<()> {
    let runner = env::current_exe()?.canonicalize()?;
    let probe = runner.with_file_name("box-bench-probe").canonicalize()?;
    let pinned = Pinned::new(vec![
        options.box_binary.clone(),
        options
            .box_binary
            .with_file_name("strands-box-sock-alias")
            .canonicalize()?,
        options
            .box_binary
            .with_file_name("strands-box-contain-trampoline")
            .canonicalize()?,
        runner,
        probe.clone(),
    ])?;
    let mut metadata = File::create(options.output.join("metadata.txt"))?;
    writeln!(
        metadata,
        "case=fresh-state-startup\ncache=warm\nwarmup_pairs=1\nmeasured_pairs={}\n\
        timeout_seconds={}\nos={}\narchitecture={}\nrunner_profile={}\n\
        policy=forbid-all\nfilesystem_grants=none\ntelemetry=default\nstderr=per-launch-file\n\
        probe_mode={}\n\
        timing=parent-before-spawn-to-reader-READY\np95=nearest-rank",
        options.iterations,
        options.timeout.as_secs(),
        env::consts::OS,
        env::consts::ARCH,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        protocol::STARTUP,
    )?;
    let os = Command::new("uname").args(["-srv"]).output()?;
    if !os.status.success() {
        return Err(io::Error::other("uname failed"));
    }
    writeln!(
        metadata,
        "os_version={}",
        String::from_utf8_lossy(&os.stdout).trim()
    )?;
    pinned.record(&mut metadata)?;
    let fixtures = Fixtures::new()?;
    let mut samples = File::create(options.output.join("samples.partial.csv"))?;
    writeln!(samples, "pair,phase,first,box_ns,direct_ns,added_ns")?;
    let mut boxed = Vec::new();
    let mut direct = Vec::new();
    let mut added = Vec::new();
    for index in 0..=options.iterations {
        let (config, directory) = fixtures.prepare(index, &probe)?;
        let mut box_command = Command::new(&options.box_binary);
        box_command
            .args(["run", "--config"])
            .arg(config)
            .current_dir(&directory);
        let mut direct_command = Command::new(&probe);
        direct_command
            .arg(protocol::STARTUP)
            .env_clear()
            .current_dir(&directory);
        let box_log = options.output.join(format!("{index}-box.stderr"));
        let direct_log = options.output.join(format!("{index}-direct.stderr"));
        let box_first = index % 2 == 0;
        let (box_time, direct_time) = if box_first {
            (
                measure(box_command, &box_log, options.timeout)?,
                measure(direct_command, &direct_log, options.timeout)?,
            )
        } else {
            let direct_time = measure(direct_command, &direct_log, options.timeout)?;
            (
                measure(box_command, &box_log, options.timeout)?,
                direct_time,
            )
        };
        let difference = box_time.as_nanos() as i128 - direct_time.as_nanos() as i128;
        writeln!(
            samples,
            "{index},{},{},{},{},{difference}",
            if index == 0 { "warmup" } else { "measured" },
            if box_first { "box" } else { "direct" },
            box_time.as_nanos(),
            direct_time.as_nanos()
        )?;
        samples.flush()?;
        if index > 0 {
            boxed.push(box_time.as_secs_f64() * 1000.0);
            direct.push(direct_time.as_secs_f64() * 1000.0);
            added.push(difference as f64 / 1_000_000.0);
        }
        if index % 10 == 0 {
            eprintln!("completed {index}/{} measured pairs", options.iterations);
        }
    }
    pinned.verify()?;
    let report = format!(
        "Fresh box state; warm operating system caches; {} measured pairs.\n{}\n{}\n{}\n",
        options.iterations,
        summary("Box startup", &mut boxed),
        summary("Direct startup", &mut direct),
        summary("Paired added startup", &mut added)
    );
    fs::write(options.output.join("summary.txt"), &report)?;
    drop(samples);
    fs::rename(
        options.output.join("samples.partial.csv"),
        options.output.join("samples.csv"),
    )?;
    print!("{report}");
    Ok(())
}

fn run() -> io::Result<()> {
    let Some(mut options) = Options::parse()? else {
        return Ok(());
    };
    if let Some(parent) = options
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    private_directory(&options.output)?;
    options.output = options.output.canonicalize()?;
    eprintln!("results: {}", options.output.display());
    match benchmark(&options) {
        Ok(()) => Ok(()),
        Err(error) => {
            fs::write(options.output.join("failure.txt"), error.to_string())?;
            Err(error)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("box-bench: {error}");
        std::process::exit(1);
    }
}
