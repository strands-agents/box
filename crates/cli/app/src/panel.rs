use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::libc;
use strands_box_cli::Error;

const PANEL_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];
const LEAVE_PANEL: &[u8] = b"\x1b[?25h\x1b[?1049l";
static PANEL_ACTIVE: AtomicBool = AtomicBool::new(false);
// shortcut: one terminal snapshot per process; revisit if commands open multiple panels.
static PANEL_TERMINAL: OnceLock<libc::termios> = OnceLock::new();

extern "C" fn close_panel(signal: libc::c_int) {
    // SAFETY: the snapshot has process lifetime; both calls are async-signal-safe.
    unsafe {
        if let Some(original) = PANEL_TERMINAL.get() {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
        }
        libc::write(
            libc::STDERR_FILENO,
            LEAVE_PANEL.as_ptr().cast(),
            LEAVE_PANEL.len(),
        );
    }
    let _ = signal_hook::low_level::emulate_default_handler(signal);
}

/// The screen used by an interactive command until it returns to the shell.
pub(super) struct Panel {
    active: bool,
    signals: [Option<libc::sigaction>; 2],
}

impl Panel {
    /// Open a panel on a capable terminal, preserving the shell screen.
    pub(super) fn enter() -> Result<Self, Error> {
        let active = io::stdin().is_terminal()
            && io::stderr().is_terminal()
            && std::env::var_os("TERM").is_some_and(|term| term != "dumb" && !term.is_empty());
        if active
            && PANEL_ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(io_error(
                "open panel",
                Path::new("stdin"),
                io::Error::other("another panel is already open"),
            ));
        }
        let mut panel = Self {
            active,
            signals: [None, None],
        };
        if panel.active {
            let mut original = std::mem::MaybeUninit::uninit();
            // SAFETY: tcgetattr initializes original on success.
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } == -1 {
                return Err(io_error(
                    "read settings",
                    Path::new("stdin"),
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: tcgetattr succeeded; the snapshot outlives every signal handler.
            PANEL_TERMINAL.get_or_init(|| unsafe { original.assume_init() });
            // SAFETY: each disposition is initialized before use and retained until drop.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = close_panel as *const () as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                for signal in PANEL_SIGNALS {
                    libc::sigaddset(&mut action.sa_mask, signal);
                }
                for (signal, previous) in PANEL_SIGNALS.into_iter().zip(&mut panel.signals) {
                    let mut saved = std::mem::MaybeUninit::uninit();
                    if libc::sigaction(signal, &action, saved.as_mut_ptr()) == -1 {
                        return Err(io_error(
                            "watch signals",
                            Path::new("stdin"),
                            io::Error::last_os_error(),
                        ));
                    }
                    *previous = Some(saved.assume_init());
                }
            }
        }
        // The alternate screen keeps the cursor on its row, so home it or the first page starts
        // wherever the shell prompt was.
        panel.write("\x1b[?1049h\x1b[H")?;
        Ok(panel)
    }

    /// Replace the previous page.
    pub(super) fn clear(&self) -> Result<(), Error> {
        self.write("\x1b[H\x1b[J")
    }

    fn write(&self, text: &str) -> Result<(), Error> {
        if self.active {
            let mut output = io::stderr().lock();
            output
                .write_all(text.as_bytes())
                .and_then(|()| output.flush())
                .map_err(|source| io_error("write", Path::new("stderr"), source))?;
        }
        Ok(())
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        let _ = self.write("\x1b[?25h\x1b[?1049l");
        for (signal, previous) in PANEL_SIGNALS.into_iter().zip(&self.signals) {
            if let Some(previous) = previous {
                // SAFETY: previous is the disposition returned when this panel opened.
                unsafe { libc::sigaction(signal, previous, std::ptr::null_mut()) };
            }
        }
        if self.active {
            PANEL_ACTIVE.store(false, Ordering::Release);
        }
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> Error {
    Error::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[path = "panel_tests.rs"]
mod tests;
