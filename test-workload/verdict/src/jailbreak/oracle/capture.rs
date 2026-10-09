use super::{OwnedChild, sockets::FORBIDDEN};
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) struct Capture {
    child: OwnedChild,
    path: PathBuf,
    empty_pcapng: bool,
}

impl Capture {
    pub(super) fn start(dir: &Path, name: &str) -> io::Result<Self> {
        Self::launch(
            dir,
            name,
            Command::new("tcpdump"),
            cfg!(target_os = "macos"),
        )
    }

    fn launch(
        dir: &Path,
        name: &str,
        mut command: Command,
        empty_pcapng: bool,
    ) -> io::Result<Self> {
        let path = dir.join(name);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let log_path = dir.join("tcpdump.log");
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let log_offset = log.metadata()?.len();
        let child = command
            .args(["-i", "any", "-n", "-U", "-w"])
            .arg(&path)
            .arg(FORBIDDEN.filter())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()?;
        let mut capture = Self {
            child: OwnedChild(child),
            path,
            empty_pcapng,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            super::super::shutdown::check()?;
            capture.check()?;
            let mut current_log = String::new();
            let mut log = fs::File::open(&log_path)?;
            log.seek(SeekFrom::Start(log_offset))?;
            log.read_to_string(&mut current_log)?;
            if fs::metadata(&capture.path).is_ok_and(|m| ready(m.len(), &current_log, empty_pcapng))
            {
                return Ok(capture);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "tcpdump did not initialize its capture file: {current_log}"
                )));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    pub(super) fn check(&mut self) -> io::Result<()> {
        if let Some(status) = self.child.0.try_wait()? {
            return Err(io::Error::other(format!(
                "tcpdump exited during observation: {status}"
            )));
        }
        Ok(())
    }
    pub(super) fn count(&self) -> io::Result<usize> {
        if self.empty_pcapng && fs::metadata(&self.path)?.len() == 0 {
            return Ok(0);
        }
        count(&self.path)
    }
    pub(super) fn summary(&self) -> io::Result<String> {
        let mut command = Command::new("tcpdump");
        command.args(["-nn", "-q", "-tt"]);
        if self.empty_pcapng {
            command.args(["-k", "INPD"]);
        }
        let output = command.arg("-r").arg(&self.path).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "packet summary failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(packet_summary(&String::from_utf8_lossy(&output.stdout)))
    }
    pub(super) fn stop(mut self) -> io::Result<usize> {
        self.check()?;
        let status = Command::new("kill")
            .args(["-INT", &self.child.0.id().to_string()])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("could not stop tcpdump"));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.0.try_wait()? {
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "tcpdump shutdown failed: {status}"
                    )));
                }
                return self.count();
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("tcpdump did not stop"));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn count(path: &Path) -> io::Result<usize> {
    let output = Command::new("tcpdump")
        .args(["-n", "-r"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "cannot read packet capture: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count())
}

fn packet_summary(output: &str) -> String {
    let mut summary = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(8)
        .collect::<Vec<_>>()
        .join("\n");
    crate::truncate_on_boundary(&mut summary, 4096);
    summary
}

fn ready(bytes: u64, current_log: &str, empty_pcapng: bool) -> bool {
    bytes >= 24 || (bytes == 0 && empty_pcapng && current_log.contains("listening on "))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_summary_keeps_addresses_and_bounds_diagnostic_output() {
        let packet = "1791506911.000001 (en0, proc timed:123, out) IP 10.0.0.1.49152 > 169.254.169.123.123: UDP, length 48";
        let output = std::iter::repeat_n(packet, 12)
            .collect::<Vec<_>>()
            .join("\n");
        let summary = packet_summary(&output);
        assert_eq!(summary.lines().count(), 8);
        assert!(summary.contains("169.254.169.123.123"));
        assert!(summary.contains("timed:123"));
        assert_eq!(packet_summary(&"é".repeat(3000)).len(), 4096);
    }
    #[test]
    fn empty_pktap_capture_starts_after_the_listener_is_ready() {
        let dir = std::env::temp_dir().join(format!("jailbreak-pktap-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "printf '' > \"$FAKE_PCAP\"; printf 'tcpdump: listening on any, link-type PKTAP\\n' >&2; exec sleep 30"])
            .env("FAKE_PCAP", dir.join("capture.pcap"));
        let started = Instant::now();
        let capture = Capture::launch(&dir, "capture.pcap", command, true).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(capture.count().unwrap(), 0);
        drop(capture);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn empty_capture_requires_pktap_and_a_current_listener_banner() {
        assert!(!ready(0, "", true));
        assert!(!ready(0, "tcpdump: listening on any", false));
        assert!(!ready(12, "tcpdump: listening on any", true));
        assert!(ready(24, "", false));
    }
}
