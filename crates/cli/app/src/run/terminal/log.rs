use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::fd::AsFd;
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
}

impl Log {
    pub(super) fn open(launch: &Launch, input: File) -> Self {
        let output = (|| {
            let directory = launch._claim.0.as_fd().try_clone_to_owned()?;
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
        }
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        if let Ok(file) = &mut self.output
            && let Err(error) = file.write_all(bytes)
        {
            self.output = Err(error);
        }
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let remaining = PREVIEW_BYTES + 1 - self.line.len();
            self.line
                .extend_from_slice(&part[..part.len().min(remaining)]);
            if part.ends_with(b"\n") {
                self.finish_line();
            }
        }
    }

    fn finish_line(&mut self) {
        if [
            "box: error:",
            "strands-box: error:",
            "strands-box: shutdown failed:",
            "policy: history flush shutdown failed:",
            "policy: periodic history flush failed:",
        ]
        .iter()
        .any(|prefix| self.line.starts_with(prefix.as_bytes()))
        {
            let line = self.line.strip_suffix(b"\n").unwrap_or(&self.line);
            let mut text = escaped(line);
            let end = text.floor_char_boundary(PREVIEW_BYTES - 1);
            self.truncated |= end < text.len();
            text.truncate(end);
            self.tail.push_str(&text);
            self.tail.push('\n');
            while self.tail.len() > PREVIEW_BYTES || self.tail.lines().count() > PREVIEW_LINES {
                let end = self.tail.find('\n').unwrap() + 1;
                self.tail.drain(..end);
                self.truncated = true;
            }
        }
        self.line.clear();
    }

    pub(super) fn preview(&mut self) -> String {
        self.finish_line();
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

    pub(super) fn report(mut self, launch: &Launch) -> String {
        let path = launch.config.with_file_name(FILE);
        let path = escaped(path.as_os_str().as_encoded_bytes());
        let saved = match &self.output {
            Ok(_) => format!("box: full log: {path}\n"),
            Err(error) => format!(
                "box: could not write log {path}: {}\n",
                escaped(error.to_string().as_bytes()),
            ),
        };
        let reuse = if launch.policy.argument.chars().any(char::is_control) {
            format!(
                "repeat your command with --box-id {} before any --",
                launch.name,
            )
        } else {
            format!(
                "box run {} --box-id {}",
                shell_argument(&launch.policy.argument),
                launch.name,
            )
        };
        format!(
            "\n{}{saved}\nbox: to reuse this box run: {reuse}\n\n",
            self.preview(),
        )
    }
}

fn escaped(bytes: &[u8]) -> String {
    let mut text = String::new();
    for character in String::from_utf8_lossy(bytes).chars() {
        if character.is_control() {
            text.extend(character.escape_default());
        } else {
            text.push(character);
        }
    }
    text
}

fn shell_argument(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./:-".contains(&byte))
    {
        argument.to_string()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_keeps_the_flood_and_the_preview_only_keeps_bounded_errors() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut log = Log::new(File::open("/dev/null").unwrap(), file.reopen());
        let mut bytes = b"policy: history flush shutdown failed: first failure\n".to_vec();
        bytes.extend_from_slice(&b"policy: warn: error while evaluating policy\n".repeat(2000));
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
                "  policy: history flush shutdown failed: first failure\n",
                "  box: error: final failure with \\u{1b}[2J\\u{0}input\n",
            ),
        );

        log.push(format!("policy: warn: {}", "x".repeat(PREVIEW_BYTES * 2)).as_bytes());
        assert!(log.line.len() <= PREVIEW_BYTES + 1);
        log.push(b"strands-box: error: still part of the warning\n");
        assert_eq!(log.preview(), preview);

        for number in 0..20 {
            log.push(format!("box: error: failure {number}\n").as_bytes());
        }
        let preview = log.preview();
        assert!(preview.contains("  box: error: failure 19\n"));
        assert!(!preview.contains("  box: error: failure 0\n"));
        assert_eq!(preview.lines().count(), PREVIEW_LINES + 1);
        log.push(format!("box: error: {}", "éé\0".repeat(PREVIEW_BYTES)).as_bytes());
        let preview = log.preview();
        assert!(preview.contains("  box: error: éé\\u{0}"));
        assert!(preview.len() < PREVIEW_BYTES + 100);
        assert!(
            preview
                .lines()
                .skip(1)
                .all(|line| line.starts_with("  box: error: "))
        );
    }

    #[test]
    fn logs_append_privately_and_keep_the_preview_when_saving_fails() {
        let host = crate::FakeHost::new();
        let launcher = host.launcher();
        crate::fixtures::write(
            &launcher.profiles().root().join("test/profile.toml"),
            "[agent]\ncommand = [\"/usr/bin/true\"]\n",
        );
        let mut launch = launcher.prepare("test", &host.project(), None).unwrap();
        launch.policy.argument = "/quoted 'profile/profile.toml".into();
        let path = launch.config.with_file_name(FILE);
        std::fs::write(&path, "first run\n").unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let mut log = Log::open(&launch, File::open("/dev/null").unwrap());
        log.push(b"second run\n");
        let console = log.report(&launch);
        assert_eq!(std::fs::read(&path).unwrap(), b"first run\nsecond run\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
        );
        assert!(console.starts_with("\nbox: full log: "));
        let arguments = console.split_once("box run ").unwrap().1;
        let parsed = std::process::Command::new("/bin/sh")
            .args(["-c", &format!("printf '%s\\n' {arguments}")])
            .output()
            .unwrap();
        assert!(parsed.status.success());
        assert_eq!(
            String::from_utf8(parsed.stdout).unwrap(),
            format!("{}\n--box-id\n{}\n", launch.policy.argument, launch.name),
        );

        let target = host.home().join("untouched");
        std::fs::write(&target, "keep").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        for mut log in [
            Log::open(&launch, File::open("/dev/null").unwrap()),
            Log::new(File::open("/dev/null").unwrap(), File::open(&target)),
        ] {
            log.push(b"strands-box: error: important failure\n");
            let console = log.report(&launch);
            assert!(console.contains("  strands-box: error: important failure\n"));
            assert!(console.contains("could not write log"));
            assert!(!console.contains("box: full log:"));
        }
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");

        launch.policy.argument = "/control\u{9b}2J/profile.toml".into();
        let console = Log::open(&launch, File::open("/dev/null").unwrap()).report(&launch);
        assert!(!console.contains('\u{9b}'));
        assert!(console.ends_with(&format!(
            "\n\nbox: to reuse this box run: repeat your command with --box-id {} before any --\n\n",
            launch.name,
        )));
    }
}
