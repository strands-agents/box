mod ancestry;
mod capture;
mod control;
mod poll;
mod sockets;

use super::{LAYER_BYPASS, LAYER_FINAL, LAYER_POSITIVE_CONTROL, LAYER_STARTED, OracleRow};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

fn seconds(name: &str, default: f64) -> io::Result<Duration> {
    let value = std::env::var(name)
        .ok()
        .map(|v| v.parse::<f64>().map_err(io::Error::other))
        .transpose()?
        .unwrap_or(default);
    if !value.is_finite() || value <= 0.0 || value > 120.0 {
        return Err(io::Error::other(format!("invalid {name}")));
    }
    Ok(Duration::from_secs_f64(value))
}

fn sample(roots: &[u32]) -> io::Result<Vec<sockets::Socket>> {
    let ps = Command::new("ps").args(["-eo", "pid=,ppid="]).output()?;
    if !ps.status.success() {
        return Err(io::Error::other("process table unavailable"));
    }
    let pids = ancestry::subtree(&String::from_utf8_lossy(&ps.stdout), roots);
    let lsof = Command::new("lsof").args(["-nP", "-i"]).output()?;
    if !lsof.status.success()
        && !(lsof.status.code() == Some(1) && lsof.stdout.is_empty() && lsof.stderr.is_empty())
    {
        return Err(io::Error::other(format!(
            "socket table unavailable: {}",
            String::from_utf8_lossy(&lsof.stderr)
        )));
    }
    Ok(sockets::parse(&String::from_utf8_lossy(&lsof.stdout))
        .into_iter()
        .filter(|s| pids.contains(&s.pid))
        .collect())
}

fn write_row(
    dir: &Path,
    layer: &str,
    evidence: String,
    verdict: &str,
    breach: bool,
) -> io::Result<()> {
    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()?;
    if !date.status.success() {
        return Err(io::Error::other("could not timestamp oracle row"));
    }
    let row = OracleRow {
        layer: layer.into(),
        evidence,
        verdict: verdict.into(),
        breach,
        timestamp_utc: String::from_utf8_lossy(&date.stdout).trim().into(),
    };
    let mut body = serde_json::to_value(&row)?;
    body["oracle"] = "tcpdump+socket-table+ancestry".into();
    body["dimension"] = "network-egress".into();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(dir.join("verdict.json"))?;
    writeln!(file, "{body}")?;
    let mut log = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(dir.join("oracle.log"))?;
    writeln!(log, "[{layer}] {verdict} {}", row.evidence)?;
    println!("[oracle {layer}] {verdict} {}", row.evidence);
    Ok(())
}

pub(super) struct Oracle {
    dir: PathBuf,
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<io::Result<usize>>>,
}

impl Oracle {
    pub(super) fn start(run_dir: &Path) -> io::Result<Self> {
        let dir = run_dir.join("oracle");
        fs::create_dir_all(&dir)?;
        let mut lock = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join("oracle.pid"))?;
        writeln!(lock, "{}", std::process::id())?;
        let mut oracle = Self {
            dir,
            stop: None,
            worker: None,
        };
        fs::write(oracle.dir.join("verdict.json"), "")?;
        fs::write(oracle.dir.join("subtree-roots"), "")?;
        let interval = seconds("ORACLE_POLL_INTERVAL", 0.5)?;
        let capture = capture::Capture::start(&oracle.dir, "control.pcap")?;
        write_row(
            &oracle.dir,
            LAYER_STARTED,
            "oracle running — watching forbidden egress".into(),
            "GREEN",
            false,
        )?;
        let result = control::run(&oracle.dir, interval)?;
        capture.stop()?;
        let (evidence, proven) = match result {
            control::Outcome::Detected(hit) => (
                format!("control connection observed AND attributed by ancestry: {hit}"),
                true,
            ),
            control::Outcome::Unreachable(state) => (
                format!("control sink unreachable ({state}); the oracle was not proven"),
                false,
            ),
            control::Outcome::Missed => (
                "control opened a connection but the sensor missed it".into(),
                false,
            ),
        };
        write_row(
            &oracle.dir,
            LAYER_POSITIVE_CONTROL,
            evidence,
            if proven { "GREEN" } else { "YELLOW" },
            proven,
        )?;
        let capture = capture::Capture::start(&oracle.dir, "capture.pcap")?;
        let (tx, rx) = mpsc::channel();
        let dir = oracle.dir.clone();
        oracle.stop = Some(tx);
        oracle.worker = Some(thread::spawn(move || {
            poll::run(&dir, capture, rx, interval)
        }));
        Ok(oracle)
    }
    pub(super) fn stop(mut self) -> io::Result<()> {
        self.stop.take();
        let worker = self
            .worker
            .take()
            .ok_or_else(|| io::Error::other("oracle has no poll worker"))?;
        let packets = worker
            .join()
            .map_err(|_| io::Error::other("oracle poll panicked"))??;
        let text = fs::read_to_string(self.dir.join("verdict.json"))?;
        let rows = text
            .lines()
            .map(serde_json::from_str::<OracleRow>)
            .collect::<Result<Vec<_>, _>>()?;
        let (red, control) = counts(&rows);
        write_row(
            &self.dir,
            LAYER_FINAL,
            format!(
                "shutdown — {red} attributed breach(es), {packets} forbidden packet(s) captured, positive control proven={control}"
            ),
            if red > 0 {
                "RED"
            } else if control == 0 {
                "YELLOW"
            } else {
                "GREEN"
            },
            red > 0,
        )
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(self.dir.join("oracle.pid"));
    }
}

fn counts(rows: &[OracleRow]) -> (usize, usize) {
    (
        rows.iter()
            .filter(|r| r.layer == LAYER_BYPASS && r.breach)
            .count(),
        rows.iter()
            .filter(|r| r.layer == LAYER_POSITIVE_CONTROL && r.breach)
            .count(),
    )
}

pub(super) fn control_worker(
    target: std::net::IpAddr,
    port: u16,
    timeout: Duration,
    state: &Path,
) -> io::Result<()> {
    control::connect(target, port, timeout, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_parsed_rows() {
        let rows = [
            r#"{"layer":"containment-bypass","breach":true}"#,
            r#"{ "layer" : "positive-control", "breach" : true }"#,
        ]
        .map(|s| serde_json::from_str(s).unwrap());
        assert_eq!(counts(&rows), (1, 1));
    }
}
