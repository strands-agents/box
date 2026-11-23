use std::io::{self, Write};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use super::terminal;

pub(super) const INTERVAL: Duration = Duration::from_millis(100);
pub(super) const CLEAR: &[u8] = b"\r\x1b[2K";

pub(super) fn draw(
    output: &mut impl Write,
    label: &str,
    frame: usize,
    columns: u16,
) -> io::Result<()> {
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'][frame % 10];
    let line = format!("{spinner} {label}…");
    let color = std::env::var("TERM").is_ok_and(|term| term != "dumb")
        && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
    output.write_all(CLEAR)?;
    for (index, character) in line
        .chars()
        .take(usize::from(columns.saturating_sub(1)))
        .enumerate()
    {
        if index == 0 && color {
            write!(output, "\x1b[38;2;74;222;128m{character}\x1b[39m")?;
        } else {
            write!(output, "{character}")?;
        }
    }
    output.flush()
}

pub(super) struct Startup {
    updates: Sender<Option<String>>,
    thread: Option<JoinHandle<()>>,
}

impl Startup {
    /// Show `label` until the next phase.
    pub(super) fn phase(&self, label: &str) {
        let _ = self.updates.send(Some(label.to_owned()));
    }

    pub(super) fn start(label: &str) -> Option<Self> {
        if !terminal::attached() {
            return None;
        }
        let mut output = terminal::nonblocking_output(io::stderr()).ok()?;
        let mut columns = terminal::terminal_size(0).ok()?.ws_col;
        let mut label = label.to_owned();
        let (updates, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("box-starting".into())
            .spawn(move || {
                let mut frame = 0;
                loop {
                    if let Ok(size) = terminal::terminal_size(0) {
                        columns = size.ws_col;
                    }
                    if draw(&mut output, &label, frame, columns).is_err() {
                        break;
                    }
                    frame += 1;
                    match receiver.recv_timeout(INTERVAL) {
                        Ok(Some(next)) => label = next,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        _ => break,
                    }
                }
                let _ = output.write_all(CLEAR);
            })
            .ok()?;
        Some(Self {
            updates,
            thread: Some(thread),
        })
    }
}

impl Drop for Startup {
    fn drop(&mut self) {
        let _ = self.updates.send(None);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
