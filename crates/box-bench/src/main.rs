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

const USAGE: &str = "\
Usage: box-bench PATH-TO-STRANDS-BOX

Build Box and this crate in release mode, then run box-bench with the strands-box binary.
Each pair runs box-bench-probe startup in a fresh box and directly, alternating order.
The clock stops when the runner reads READY. Shutdown is outside the measured startup.
Results go to target/results/<run> in this crate.
";

const ITERATIONS: usize = 100;
const TIMEOUT: Duration = Duration::from_secs(30);

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

fn benchmark(box_binary: &Path, output: &Path) -> io::Result<()> {
    let probe = env::current_exe()?
        .with_file_name("box-bench-probe")
        .canonicalize()?;
    fs::write(
        output.join("metadata.txt"),
        format!(
            "os={}\narchitecture={}\n",
            env::consts::OS,
            env::consts::ARCH
        ),
    )?;
    let fixtures = Fixtures::new()?;
    let mut samples = File::create(output.join("samples.partial.csv"))?;
    writeln!(samples, "pair,phase,first,box_ns,direct_ns,added_ns")?;
    let mut boxed = Vec::new();
    let mut direct = Vec::new();
    let mut added = Vec::new();
    for index in 0..=ITERATIONS {
        let (config, directory) = fixtures.prepare(index, &probe)?;
        let mut box_command = Command::new(box_binary);
        box_command
            .args(["run", "--config"])
            .arg(config)
            .current_dir(&directory);
        let mut direct_command = Command::new(&probe);
        direct_command
            .arg(protocol::STARTUP)
            .env_clear()
            .current_dir(&directory);
        let box_log = output.join(format!("{index}-box.stderr"));
        let direct_log = output.join(format!("{index}-direct.stderr"));
        let box_first = index % 2 == 0;
        let (box_time, direct_time) = if box_first {
            (
                measure(box_command, &box_log, TIMEOUT)?,
                measure(direct_command, &direct_log, TIMEOUT)?,
            )
        } else {
            let direct_time = measure(direct_command, &direct_log, TIMEOUT)?;
            (measure(box_command, &box_log, TIMEOUT)?, direct_time)
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
            eprintln!("completed {index}/{ITERATIONS} measured pairs");
        }
    }
    let report = format!(
        "Fresh box state; warm operating system caches; {ITERATIONS} measured pairs.\n{}\n{}\n{}\n",
        summary("Box startup", &mut boxed),
        summary("Direct startup", &mut direct),
        summary("Paired added startup", &mut added)
    );
    fs::write(output.join("summary.txt"), &report)?;
    drop(samples);
    fs::rename(
        output.join("samples.partial.csv"),
        output.join("samples.csv"),
    )?;
    print!("{report}");
    Ok(())
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let (Some(box_binary), None) = (args.next(), args.next()) else {
        return Err(io::Error::other(USAGE));
    };
    let box_binary = PathBuf::from(box_binary)
        .canonicalize()
        .map_err(|error| io::Error::other(format!("{error}\n{USAGE}")))?;
    let output = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/results")
        .join(run_id());
    fs::create_dir_all(output.parent().expect("results directory"))?;
    private_directory(&output)?;
    eprintln!("results: {}", output.display());
    benchmark(&box_binary, &output).inspect_err(|error| {
        let _ = fs::write(output.join("failure.txt"), error.to_string());
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("box-bench: {error}");
        std::process::exit(1);
    }
}
