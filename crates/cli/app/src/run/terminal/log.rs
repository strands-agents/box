use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use nix::libc;

use super::super::Launch;
use crate::files::open_at;

const FILE: &str = "box.log";
const PREVIEW_BYTES: usize = 1024;
const PREVIEW_LINES: usize = 6;

pub(super) struct Log {
    pub(super) input: File,
    pub(super) output: io::Result<File>,
    line: Vec<u8>,
    tail: String,
    truncated: bool,
    unshown: usize,
}

impl Log {
    pub(super) fn open(launch: &Launch, input: File) -> Self {
        let output = (|| {
            let directory = launch._claim.0.try_clone()?.into();
            let file = File::from(open_at(
                &directory,
                FILE,
                libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NONBLOCK,
                0o600,
            )?);
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                return Err(io::Error::other(
                    "log is not a regular file owned only by you",
                ));
            }
            file.set_permissions(Permissions::from_mode(0o600))?;
            Ok(file)
        })();
        Self::new(input, output)
    }

    pub(super) fn new(input: File, output: io::Result<File>) -> Self {
        Self {
            input,
            output,
            line: Vec::with_capacity(PREVIEW_BYTES + 1),
            tail: String::new(),
            truncated: false,
            unshown: 0,
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        self.save(bytes);
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let remaining = PREVIEW_BYTES + 1 - self.line.len();
            self.line
                .extend_from_slice(&part[..part.len().min(remaining)]);
            if part.ends_with(b"\n") {
                self.collect();
            }
        }
    }

    /// A message from `box` itself, which the preview always shows.
    pub(super) fn message(&mut self, message: &str) {
        self.save(message.as_bytes());
        self.show(message.trim_end());
    }

    /// Startup lines are expected, so the count of lines left out of the preview starts after them.
    pub(super) fn started(&mut self) {
        self.unshown = 0;
    }

    fn save(&mut self, bytes: &[u8]) {
        if let Ok(file) = &mut self.output
            && let Err(error) = file.write_all(bytes)
        {
            self.output = Err(error);
        }
    }

    fn collect(&mut self) {
        let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
        let text = String::from_utf8_lossy(line).into_owned();
        self.line.clear();
        let core_error = matches!(
            diagnostics::parse(&text),
            diagnostics::Line::Message(message) if message.severity == diagnostics::Severity::Error
        );
        if core_error
            || text
                .split_once(": ")
                .is_some_and(|(_, message)| message.starts_with("error:"))
        {
            self.show(&text);
        } else {
            self.unshown += 1;
        }
    }

    fn show(&mut self, text: &str) {
        let text = super::super::banner::clean(text);
        let end = text.floor_char_boundary(PREVIEW_BYTES - 1);
        self.truncated |= end < text.len();
        self.tail.push_str(&text[..end]);
        self.tail.push('\n');
        while self.tail.len() > PREVIEW_BYTES || self.tail.lines().count() > PREVIEW_LINES {
            let end = self.tail.find('\n').unwrap() + 1;
            self.tail.drain(..end);
            self.truncated = true;
        }
    }

    pub(super) fn preview(&mut self) -> String {
        if !self.line.is_empty() {
            self.collect();
        }
        if self.tail.is_empty() {
            return String::new();
        }
        let mut preview = format!(
            "box: recent log output{}\n",
            if self.truncated { " (truncated)" } else { "" },
        );
        for line in self.tail.lines() {
            preview.push_str("  ");
            preview.push_str(line);
            preview.push('\n');
        }
        preview
    }

    /// What `box` prints on exit. A run that `box` removes gets only the preview.
    pub(super) fn report(mut self, launch: &Launch, kept: bool) -> String {
        let preview = self.preview();
        if !kept {
            return preview;
        }
        let path = launch.config.with_file_name(FILE);
        let path = match path.to_str() {
            Some(text) if super::super::banner::clean(text) == text => text.to_owned(),
            _ => format!("{path:?}"),
        };
        let log = match &self.output {
            Ok(_) => path,
            Err(error) => format!(
                "could not write {path}: {}",
                error.to_string().escape_debug()
            ),
        };
        let id = launch.name();
        format!(
            "\n{preview}box: run {id} ended\n  startup disclosure \u{b7} {}\n  log      {log}\n  \
             history  {}\n  reuse    {}\n\n",
            match self.unshown {
                1 => "1 more message".to_owned(),
                count => format!("{count} more messages"),
            },
            launch.history_command(false),
            launch.reuse_command(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_keeps_the_flood_and_the_preview_only_keeps_bounded_errors() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut log = Log::new(File::open("/dev/null").unwrap(), file.reopen());
        let mut bytes = b"loader: error: first failure\n".to_vec();
        bytes.extend_from_slice(
            &b"policy: warning[P0201]: dogwood evaluation failed: x; denying\n".repeat(2000),
        );
        bytes.extend_from_slice(b"box: error: final failure with \x1b[2J\x00input");
        for part in bytes.chunks(7) {
            log.push(part);
        }
        assert_eq!(std::fs::read(file.path()).unwrap(), bytes);
        let preview = log.preview();
        assert_eq!(
            preview,
            concat!(
                "box: recent log output\n",
                "  loader: error: first failure\n",
                "  box: error: final failure with \\u{1b}[2J\\u{0}input\n",
            ),
        );

        log.push(
            format!(
                "strands-box: warning[B0501]: {}",
                "x".repeat(PREVIEW_BYTES * 2)
            )
            .as_bytes(),
        );
        assert!(log.line.len() <= PREVIEW_BYTES + 1);
        log.message("box: policy update failed: invalid edit\n");
        log.push(b"strands-box: error[B0105]: still part of the warning\n");
        assert_eq!(
            log.preview(),
            format!("{preview}  box: policy update failed: invalid edit\n")
        );
        assert_eq!(log.unshown, 2001);

        for number in 0..7 {
            log.push(format!("box: error: failure {number}\n").as_bytes());
        }
        let recent: String = (1..7)
            .map(|number| format!("  box: error: failure {number}\n"))
            .collect();
        assert_eq!(
            log.preview(),
            format!("box: recent log output (truncated)\n{recent}")
        );
        log.push(format!("box: error: {}", "éé\0".repeat(PREVIEW_BYTES)).as_bytes());
        let preview = log.preview();
        let error = preview
            .strip_prefix("box: recent log output (truncated)\n  ")
            .unwrap();
        assert!(error.starts_with("box: error: éé\\u{0}"));
        assert!(error.len() <= PREVIEW_BYTES);
    }

    fn log_report(launch: &Launch) -> String {
        Log::new(File::open("/dev/null").unwrap(), tempfile::tempfile()).report(launch, true)
    }

    #[test]
    fn logs_append_privately_and_keep_the_preview_when_saving_fails() {
        let host = crate::FakeHost::new();
        let launcher = host.launcher();
        let profile = host.home().join("quoted 'profile/profile.toml");
        crate::fixtures::write(
            &profile,
            "[profile]\nname = \"test\"\n[agent]\ncommand = [\"/usr/bin/true\"]\n",
        );
        let mut launch = launcher
            .prepare(profile.to_str().unwrap(), &host.project(), None)
            .unwrap();
        let path = launch.config.with_file_name(FILE);
        std::fs::write(&path, "first run\n").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let mut log = Log::open(&launch, File::open("/dev/null").unwrap());
        log.push(b"startup\n");
        log.started();
        log.push(b"second run\n");
        let console = log.report(&launch, true);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"first run\nstartup\nsecond run\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        assert!(
            console.starts_with(&format!(
                "\nbox: run {} ended\n  startup disclosure \u{b7} 1 more message\n  log      ",
                launch.name
            )),
            "{console}"
        );
        assert!(
            console.contains(&format!("\n  history  box runs history {}\n", launch.name)),
            "{console}"
        );
        let arguments = console.split_once("box run ").unwrap().1;
        let parsed = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("printf '%s\\n' {arguments}")])
            .output()
            .unwrap();
        assert!(parsed.status.success());
        assert_eq!(
            String::from_utf8(parsed.stdout).unwrap(),
            format!("{}\n--box-id\n{}\n", profile.display(), launch.name),
        );

        let target = host.home().join("untouched");
        std::fs::write(&target, "keep").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        for mut log in [
            Log::open(&launch, File::open("/dev/null").unwrap()),
            Log::new(File::open("/dev/null").unwrap(), File::open(&target)),
        ] {
            log.push(b"strands-box: error[B0105]: important failure\n");
            let console = log.report(&launch, true);
            assert!(console.contains("  strands-box: error[B0105]: important failure\n"));
            assert!(
                console.contains("\n  log      could not write "),
                "{console}"
            );
        }
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");

        let mut log = Log::new(File::open("/dev/null").unwrap(), tempfile::tempfile());
        log.push(b"strands-box: error[B0105]: refused\nbox: running profile\n");
        assert_eq!(
            log.report(&launch, false),
            "box: recent log output\n  strands-box: error[B0105]: refused\n",
        );

        for argument in [
            "/control\u{9b}2J",
            "/invisible\u{202e}name",
            "/two\\\\slashes",
        ] {
            launch.policy.argument = argument.into();
            assert!(
                log_report(&launch).contains(&format!(
                    "\n  reuse    repeat your command with --box-id {} before any --\n",
                    launch.name
                )),
                "{}",
                log_report(&launch)
            );
            assert_eq!(
                launch.reuse_instruction(),
                format!(
                    "box: to reuse this box run: repeat your command with --box-id {} before any --",
                    launch.name
                ),
            );
        }
    }
}
