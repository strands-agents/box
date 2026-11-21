use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use nix::libc;
use nix::pty::{Winsize, openpty};
use nix::sys::termios::{self, SetArg, Termios};
use ratatui::layout::Rect;
use signal_hook::iterator::Signals;

use super::Launch;
use super::banner::{BANNER_ROWS, Banner, Decision, PolicyStatus};
use super::policy::PolicyControl;
use super::startup;
use crate::error::Error;
use alacritty_terminal::term::{ClipboardType, TermMode};
use emulator::Emulator;
use input::Input;
use log::Log;
use mouse::Mouse;

mod emulator;
mod input;
mod log;
mod mouse;
mod native;

const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// The policy decisions Box Core holds for the banner before it drops one, which Box Core
/// reserves up front.
const DECISION_CAPACITY: usize = 8 * 1024;
/// The most policy decisions the banner takes before it draws a frame.
const DECISIONS_PER_FRAME: usize = 8 * 1024;

pub(super) fn attached() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var("TERM").map_or(true, |term| term != "dumb")
}

fn terminal_error(source: io::Error) -> Error {
    crate::files::io_error("use", Path::new("terminal"), source)
}

pub(super) fn run(
    launch: &Launch,
    keep_run: &mut bool,
    execute: impl for<'a> FnOnce(strands_box::RunOptions<'a>) -> ExitCode,
) -> Result<ExitCode, Error> {
    let mut terminal = Terminal::new().map_err(terminal_error)?;
    let with_banner = matches!(launch.display, super::Display::Banner);
    if !with_banner {
        terminal.panel_rows = 0;
    }
    let mut reporting = nonblocking_output(io::stderr()).map_err(terminal_error)?;
    let pair = openpty(
        &child_size(terminal.size, terminal.panel_rows),
        &terminal.original,
    )
    .map_err(|error| terminal_error(error.into()))?;
    let mut master = File::from(pair.master);
    let workload_terminal = File::from(pair.slave);
    for descriptor in [&master, &workload_terminal] {
        if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(terminal_error(io::Error::last_os_error()));
        }
    }
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        if flags == -1
            || libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1
        {
            return Err(terminal_error(io::Error::last_os_error()));
        }
    }
    let mut banner = Banner::new(
        &launch.profile_name,
        &launch.profile.display().to_string(),
        &launch
            .profile
            .with_file_name("policy.dw")
            .display()
            .to_string(),
    );
    // Box Core has not started, and this launch holds the box's lock, so the records hold every
    // earlier run of this box and nothing of this one. The run waits for this read
    // (docs/design/cli/profiles.md#start-box-core).
    if with_banner && let Some(saved) = crate::records::saved(&launch.home, &launch.journal) {
        banner.restore(saved);
    }
    let saved = [
        duplicate(1).map_err(terminal_error)?,
        duplicate(2).map_err(terminal_error)?,
    ];
    let (reader, writer) = nix::unistd::pipe().map_err(|error| terminal_error(error.into()))?;
    let reader = File::from(reader);
    let writer = File::from(writer);
    for fd in [&reader, &writer] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(terminal_error(io::Error::last_os_error()));
        }
    }
    let mut fallback = reader.try_clone().map_err(terminal_error)?;
    let mut restore = None;
    let (sender, decisions) = strands_box::policy_decisions(DECISION_CAPACITY);
    let profile = launch.profile_name.clone();
    let mut ui = None;
    let code = execute(strands_box::RunOptions {
        terminal: Some(workload_terminal.try_clone().map_err(terminal_error)?),
        on_ready: Some(Box::new(|| {
            io::stdout().flush()?;
            let redirect = Redirect::new(saved, writer.as_raw_fd())?;
            drop(writer);
            terminal.start()?;
            let policy = if with_banner {
                Some(PolicyControl::start(launch.policy.clone())?)
            } else {
                None
            };
            let mut diagnostics = Log::open(launch, reader);
            ui = Some(
                std::thread::Builder::new()
                    .name("box-terminal".into())
                    .spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            relay(
                                &mut terminal,
                                &mut master,
                                workload_terminal,
                                &mut diagnostics,
                                policy.as_ref(),
                                &profile,
                                |initial| {
                                    BannerWorker::new(
                                        banner,
                                        move || decisions.try_recv().ok().map(Decision::from),
                                        initial,
                                    )
                                },
                            )
                        }))
                        .unwrap_or_else(|_| Err(io::Error::other("terminal relay panicked")));
                        if result.is_err() {
                            drop(terminal);
                            unsafe {
                                libc::kill(libc::getpid(), libc::SIGTERM);
                            }
                            drop(master);
                            if let Ok(file) = &mut diagnostics.output {
                                let _ = io::copy(&mut diagnostics.input, file);
                            }
                            let _ = io::copy(&mut diagnostics.input, &mut io::sink());
                        }
                        result.map(|()| diagnostics)
                    })?,
            );
            *keep_run = true;
            restore = Some(redirect);
            launch.report();
            Ok(())
        })),
        policy_decisions: with_banner.then_some(sender),
        ..launch.run_options()
    });
    drop(restore);
    match ui {
        Some(thread) => {
            let diagnostics = thread
                .join()
                .map_err(|_| terminal_error(io::Error::other("terminal relay panicked")))?
                .map_err(terminal_error)?;
            let report = diagnostics.report(launch).replace('\n', "\r\n");
            let deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
            if write_until(&mut reporting, report.as_bytes(), deadline).is_err() {
                return Ok(ExitCode::FAILURE);
            }
        }
        None => {
            let _ = io::copy(&mut fallback, &mut io::stderr());
        }
    }
    Ok(code)
}

struct Redirect {
    saved: [File; 2],
}
impl Redirect {
    fn new(saved: [File; 2], writer: i32) -> io::Result<Self> {
        let redirect = Self { saved };
        for fd in 1..3 {
            if unsafe { libc::dup2(writer, fd) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(redirect)
    }
}
impl Drop for Redirect {
    fn drop(&mut self) {
        for fd in 1..3 {
            unsafe {
                libc::dup2(self.saved[(fd - 1) as usize].as_raw_fd(), fd);
            }
        }
    }
}

fn duplicate(fd: i32) -> io::Result<File> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(copy) })
    }
}

#[derive(Clone)]
struct BannerRequest {
    columns: usize,
    minimized: bool,
    activity: super::history::ActivityView,
    host_rows: u16,
    child_rows: u16,
    pointer: Option<(usize, u16)>,
    color: bool,
    policy: PolicyStatus,
    copied: Option<(String, Instant)>,
}

struct BannerFrame {
    request: BannerRequest,
    bytes: Vec<u8>,
    controls: Option<(u16, super::banner::Heading)>,
    files: Vec<(Rect, String)>,
}

struct BannerWorker {
    requests: std::sync::mpsc::SyncSender<BannerRequest>,
    frames: std::sync::mpsc::Receiver<io::Result<BannerFrame>>,
}

impl BannerWorker {
    fn new(
        mut banner: Banner,
        mut decisions: impl FnMut() -> Option<Decision> + Send + 'static,
        initial: BannerRequest,
    ) -> io::Result<Self> {
        Self::spawn(initial, move |request| {
            for _ in 0..DECISIONS_PER_FRAME {
                let Some(decision) = decisions() else { break };
                banner.record(
                    decision.permitted,
                    &decision.action,
                    &decision.resource,
                    decision.reason.as_deref(),
                    &decision.rule,
                );
            }
            banner.activity = request.activity;
            banner.policy = request.policy;
            banner.copied = request.copied.clone();
            let mut panel = banner.view(request.columns, request.minimized);
            let available = request.host_rows.saturating_sub(request.child_rows);
            let first = request.child_rows + 1 + available.saturating_sub(panel.buffer.area.height);
            let skipped = panel.buffer.area.height.saturating_sub(available);
            panel.hover(request.pointer.and_then(|(column, row)| {
                row.checked_sub(first).map(|row| (column, row + skipped))
            }));
            let host_row = |row: u16| {
                row.checked_sub(skipped)
                    .map(|row| first + row)
                    .filter(|row| *row <= request.host_rows)
            };
            let controls = panel
                .heading
                .take()
                .and_then(|(row, heading)| host_row(row).map(|row| (row, heading)));
            let files = panel
                .files
                .drain(..)
                .filter_map(|(mut area, path)| {
                    area.y = host_row(area.y)?;
                    Some((area, path))
                })
                .collect();
            let mut bytes = Vec::new();
            panel.write(&mut bytes, request.child_rows + 1, available, request.color)?;
            Ok(BannerFrame {
                request,
                bytes,
                controls,
                files,
            })
        })
    }

    fn spawn(
        initial: BannerRequest,
        mut draw: impl FnMut(BannerRequest) -> io::Result<BannerFrame> + Send + 'static,
    ) -> io::Result<Self> {
        use std::sync::mpsc::{self, RecvTimeoutError};
        let (commands, requests) = mpsc::sync_channel(1);
        let (frames, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("box-banner".into())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                        let mut request = initial;
                        let mut retry_available = true;
                        loop {
                            match requests.recv_timeout(Duration::from_millis(30)) {
                                Ok(next) => request = next,
                                Err(RecvTimeoutError::Disconnected) => return Ok(()),
                                Err(RecvTimeoutError::Timeout) => {}
                            }
                            let frame = match draw(request.clone()) {
                                Ok(frame) => {
                                    retry_available = true;
                                    frame
                                }
                                Err(_) if retry_available => {
                                    retry_available = false;
                                    std::thread::sleep(Duration::from_millis(100));
                                    continue;
                                }
                                Err(error) => return Err(error),
                            };
                            if let Err(mpsc::TrySendError::Disconnected(_)) =
                                frames.try_send(Ok(frame))
                            {
                                return Ok(());
                            }
                        }
                    }));
                let failure = match result {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => error,
                    Err(_) => io::Error::other("banner worker panicked"),
                };
                let _ = frames.try_send(Err(failure));
            })?;
        Ok(Self {
            requests: commands,
            frames: receiver,
        })
    }
}

fn relay(
    terminal: &mut Terminal,
    master: &mut File,
    workload_terminal: File,
    diagnostics: &mut Log,
    policy: Option<&PolicyControl>,
    profile: &str,
    start_banner: impl FnOnce(BannerRequest) -> io::Result<BannerWorker>,
) -> io::Result<()> {
    use super::history::ActivityView;
    use std::sync::mpsc::TryRecvError;
    #[derive(PartialEq)]
    enum DisplayPhase {
        Startup,
        Ready,
        Agent,
    }
    let mut retained_terminal = Some(workload_terminal);
    let mut phase = DisplayPhase::Startup;
    let mut visible = false;
    let native = policy.is_none();
    let mut native_startup = native.then(native::StartupOutput::default);
    let started = Instant::now();
    let mut loading_frame = None;
    let mut input = Input::new();
    let mut output = Vec::new();
    let mut written = 0;
    let mut finishing = false;
    let mut drain_deadline: Option<Instant> = None;
    let initial = BannerRequest {
        columns: usize::from(terminal.size.ws_col.saturating_sub(1)),
        minimized: true,
        activity: ActivityView::default(),
        host_rows: terminal.size.ws_row,
        child_rows: child_size(terminal.size, terminal.panel_rows).ws_row,
        pointer: None,
        color: terminal.color,
        policy: PolicyStatus::default(),
        copied: None,
    };
    let mut worker = match (!native).then(|| start_banner(initial)) {
        Some(Ok(worker)) => Some(worker),
        Some(Err(error)) => {
            diagnostics.message(&format!("box: banner disabled: {error}\n"));
            None
        }
        None => None,
    };
    let mut screen = Emulator::new(
        child_size(terminal.size, terminal.panel_rows).ws_row,
        terminal.size.ws_col,
    );
    let mut panel: Option<BannerFrame> = None;
    let mut pending_files = None;
    let mut pending_copy = None;
    let mut copy_request: Option<(String, bool)> = None;
    let mut copied = None;
    let mut drawn = None;
    let mut dirty = true;
    let mut activity = ActivityView::default();
    let mut policy_status = PolicyStatus::default();
    let mut pending_input = PendingInput::default();
    let mut forwarded_input = Vec::new();
    let mut bytes = [0_u8; 16 * 1024];
    let mut master_closed = false;
    let mut diagnostics_closed = false;
    let mut last_modes = None;
    const INPUT_LIMIT: usize = 64 * 1024;
    loop {
        let mut failed = false;
        if let Some(BannerWorker { frames, .. }) = &worker {
            loop {
                match frames.try_recv() {
                    Ok(Ok(mut next)) => {
                        input.controls = next.controls.take();
                        panel = Some(next);
                    }
                    Ok(Err(error)) => {
                        diagnostics.message(&format!("box: banner disabled: {error}\n"));
                        failed = true;
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        diagnostics.message("box: banner disabled: worker stopped\n");
                        failed = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
        }
        if failed {
            // A toggle that arrived with the last frame would turn policy off with no banner.
            input.toggle_policy = false;
            if let Some(policy) = policy {
                policy.restore()?;
            }
            worker = None;
            panel = None;
            input.banner_shown = false;
            input.controls = None;
            input.files.clear();
            pending_files = None;
            dirty = true;
        }
        input.enabled = worker.is_some() && visible;
        input.banner_running = worker.is_some();
        dirty |= terminal.resizes.pending().next().is_some();
        let requested_size = terminal_size(terminal.input.as_raw_fd())?;
        let rows = if worker.is_none() {
            0
        } else if input.minimized {
            1
        } else {
            BANNER_ROWS
        };
        if requested_size != terminal.size || rows != terminal.panel_rows {
            terminal.size = requested_size;
            terminal.panel_rows = rows;
            let size = child_size(terminal.size, rows);
            input.selecting = false;
            screen.clear_selection();
            screen.resize(size.ws_row, size.ws_col);
            if !master_closed
                && unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) } == -1
            {
                return Err(io::Error::last_os_error());
            }
            input.pointer = None;
            input.files.clear();
            pending_files = None;
            dirty = true;
        }
        input.native_rows = child_size(terminal.size, terminal.panel_rows).ws_row;
        for _ in 0..std::mem::take(&mut input.navigation) {
            activity = activity.next();
        }
        if let Some(policy) = policy {
            if std::mem::take(&mut input.toggle_policy) {
                policy.toggle()?;
            }
            if std::mem::take(&mut input.reload_policy) {
                policy.reload()?;
            }
            for (status, error) in policy.changes.try_iter() {
                policy_status = status;
                if let Some(error) = error {
                    diagnostics.message(&format!("box: error: policy update failed: {error}\n"));
                }
            }
        }
        input.reload_available = policy_status.pending && policy_status.enabled;
        if let Some(BannerWorker { requests, .. }) = &worker {
            let _ = requests.try_send(BannerRequest {
                columns: usize::from(terminal.size.ws_col.saturating_sub(1)),
                minimized: input.minimized,
                activity,
                host_rows: terminal.size.ws_row,
                child_rows: input.native_rows,
                pointer: input.pointer,
                color: terminal.color,
                policy: policy_status,
                copied: copied.clone(),
            });
        }
        if !input.selecting {
            dirty |= screen.process(&[]);
        }
        let modes = screen.mode();
        update_input_modes(&mut input, modes);
        let mode_key = (modes, input.enabled);
        if phase == DisplayPhase::Startup && unsafe { libc::tcgetpgrp(master.as_raw_fd()) } > 0 {
            phase = DisplayPhase::Ready;
        }
        let can_write = output.is_empty();
        let content_ready = native_startup
            .as_ref()
            .map_or_else(|| screen.has_content(), native::StartupOutput::ready);
        let revealing = phase == DisplayPhase::Agent && !visible && can_write && content_ready;
        if !visible && can_write && !finishing {
            if revealing {
                output.extend_from_slice(startup::CLEAR);
                if let Some(mut startup) = native_startup.take() {
                    output.append(&mut startup.bytes);
                } else if terminal.active {
                    output.extend_from_slice(b"\x1b[?1049h\x1b[0m\x1b[r\x1b[2J\x1b[H\x1b[?2004h\x1b[?9;1000;1002;1003;1005;1006;1015;1016l\x1b[?1006h\x1b[?1003h");
                }
                visible = true;
                input.enabled = worker.is_some();
            } else if !master_closed {
                let frame =
                    (started.elapsed().as_millis() / startup::INTERVAL.as_millis()) as usize;
                if loading_frame != Some(frame) {
                    startup::draw(
                        &mut output,
                        &format!("Starting {profile} in the box"),
                        frame,
                        terminal.size.ws_col,
                    )?;
                    loading_frame = Some(frame);
                }
            }
        }
        let can_render = !native && visible && can_write && !finishing;
        if !native
            && can_write
            && phase == DisplayPhase::Agent
            && !finishing
            && last_modes != Some(mode_key)
        {
            write!(
                output,
                "\x1b[?1{}\x1b{}\x1b[?1004{}\x1b[?2004h",
                if modes.contains(TermMode::APP_CURSOR) {
                    'h'
                } else {
                    'l'
                },
                if modes.contains(TermMode::APP_KEYPAD) {
                    '='
                } else {
                    '>'
                },
                if modes.contains(TermMode::FOCUS_IN_OUT) {
                    'h'
                } else {
                    'l'
                }
            )?;
            write!(
                output,
                "\x1b[?1006h\x1b[?1003{}",
                if input.enabled || input.mouse.tracking != 0 {
                    'h'
                } else {
                    'l'
                }
            )?;
            last_modes = Some(mode_key);
        }
        if panel.as_ref().is_some_and(|frame| {
            frame.request.columns != usize::from(terminal.size.ws_col.saturating_sub(1))
                || frame.request.host_rows != terminal.size.ws_row
                || frame.request.child_rows != input.native_rows
                || frame.request.minimized != input.minimized
        }) {
            panel = None;
            input.controls = None;
            input.files.clear();
        }
        if let Some(frame) = panel.as_ref() {
            dirty |= drawn.as_ref() != Some(&frame.bytes);
        }
        if dirty && can_render {
            screen.render(&mut output)?;
            if let Some(panel) = &panel {
                output.write_all(&panel.bytes)?;
                input.banner_shown = true;
                drawn = Some(panel.bytes.clone());
                pending_files = Some(panel.files.clone());
            } else {
                drawn = None;
                input.banner_shown = false;
                pending_files = Some(Vec::new());
                for row in input.native_rows..terminal.size.ws_row {
                    write!(output, "\x1b[{};1H\x1b[0m\x1b[2K", row + 1)?;
                }
            }
            screen.restore_cursor(&mut output)?;
            dirty = false;
        }
        if phase == DisplayPhase::Agent {
            pending_input.push(InputSource::Reply, screen.take_replies(&mut output));
            if output.len() < INPUT_LIMIT
                && let Some((text, show_notice)) = copy_request.take()
            {
                emulator::copy_to_clipboard(&mut output, ClipboardType::Clipboard, &text);
                pending_copy = show_notice.then_some(text);
            }
        }
        let before = written;
        let complete = write_pending(&mut terminal.output, &output, &mut written)?;
        terminal.output_state.process(&output[before..written]);
        if written > before {
            drain_deadline = None;
        }
        if complete {
            output.clear();
            written = 0;
            if let Some(files) = pending_files.take() {
                input.files = files;
            }
            if let Some(path) = pending_copy.take() {
                copied = Some((path, Instant::now()));
            }
        }
        if master_closed && diagnostics_closed {
            if output.is_empty() {
                if finishing {
                    termios::tcsetattr(&terminal.input, SetArg::TCSANOW, &terminal.original)?;
                    terminal.active = false;
                    return Ok(());
                }
                let hidden = !visible && phase != DisplayPhase::Ready && !content_ready;
                if hidden && (native_startup.is_some() || !native) {
                    output.extend_from_slice(startup::CLEAR);
                }
                if hidden && let Some(mut startup) = native_startup.take() {
                    output.append(&mut startup.bytes);
                } else if hidden || (visible && (native || !dirty)) {
                    restore_screen(&mut output, terminal.output_state.alternate())?;
                    if !native {
                        screen.write_primary(&mut output)?;
                    }
                    finishing = true;
                }
            }
            let deadline =
                drain_deadline.get_or_insert_with(|| Instant::now() + OUTPUT_DRAIN_TIMEOUT);
            if Instant::now() >= *deadline {
                diagnostics.message(
                    "box: error: terminal output stayed blocked; final screen was not fully written\n",
                );
                return Ok(());
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: if master_closed || input.selecting {
                    -1
                } else {
                    master.as_raw_fd()
                },
                events: (if phase != DisplayPhase::Ready
                    && pending_input.replies < INPUT_LIMIT
                    && output.len()
                        + native_startup
                            .as_ref()
                            .map_or(0, |startup| startup.bytes.len())
                        < INPUT_LIMIT
                {
                    libc::POLLIN
                } else {
                    0
                }) | libc::POLLHUP
                    | if pending_input.is_empty() {
                        0
                    } else {
                        libc::POLLOUT
                    },
                revents: 0,
            },
            libc::pollfd {
                fd: if master_closed || pending_input.closed || phase != DisplayPhase::Agent {
                    -1
                } else {
                    terminal.input.as_raw_fd()
                },
                events: if pending_input.keyboard < INPUT_LIMIT {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: if diagnostics_closed {
                    -1
                } else {
                    diagnostics.input.as_raw_fd()
                },
                events: libc::POLLHUP
                    | if phase == DisplayPhase::Agent || output.len() < INPUT_LIMIT {
                        libc::POLLIN
                    } else {
                        0
                    },
                revents: 0,
            },
            libc::pollfd {
                fd: if output.is_empty() {
                    -1
                } else {
                    terminal.output.as_raw_fd()
                },
                events: libc::POLLOUT,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 4, 30) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::other("terminal descriptor closed"));
        }
        if phase == DisplayPhase::Ready && output.is_empty() && fds[2].revents == 0 {
            phase = DisplayPhase::Agent;
        }
        if !master_closed
            && (diagnostics_closed
                || fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
        {
            match master.read(&mut bytes) {
                Ok(0) => master_closed = true,
                Ok(n) => {
                    if phase == DisplayPhase::Startup {
                        phase = DisplayPhase::Ready;
                    }
                    if let Some(startup) = &mut native_startup {
                        startup.push(&bytes[..n], &mut output);
                    } else if native {
                        output.extend_from_slice(&bytes[..n]);
                    } else {
                        dirty |= screen.process(&bytes[..n]);
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EIO) => master_closed = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if diagnostics_closed {
                        drop(retained_terminal.take());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if fds[2].revents != 0 {
            match diagnostics.input.read(&mut bytes) {
                Ok(0) => {
                    diagnostics_closed = true;
                    pending_input.close();
                }
                Ok(n) => {
                    diagnostics.push(&bytes[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if master_closed && diagnostics_closed {
            dirty |= screen.finish_output();
        }
        update_input_modes(&mut input, screen.mode());
        if fds[1].revents != 0 {
            let room = bytes
                .len()
                .min(INPUT_LIMIT.saturating_sub(pending_input.keyboard));
            match nix::unistd::read(terminal.input.as_raw_fd(), &mut bytes[..room]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "terminal input closed",
                    ));
                }
                Ok(n) if native => forwarded_input.extend_from_slice(&bytes[..n]),
                Ok(n) => input.route(&bytes[..n], &mut forwarded_input),
                Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                Err(e) => return Err(e.into()),
            }
        }
        input.flush_escape(&mut forwarded_input);
        for action in input.actions.drain(..) {
            match action {
                input::Action::Select(click) => {
                    if let Some(text) = screen.select(click) {
                        copy_request = Some((text, false));
                    }
                    dirty = true;
                }
                input::Action::ClearSelection => dirty |= screen.clear_selection(),
                input::Action::CopyPath(path) => copy_request = Some((path, true)),
                input::Action::Scroll(scroll) => {
                    dirty |= screen.clear_selection();
                    dirty |= screen.scroll(scroll);
                }
            }
        }
        pending_input.push(InputSource::Keyboard, std::mem::take(&mut forwarded_input));
        if phase == DisplayPhase::Agent {
            pending_input.push(InputSource::Reply, screen.take_replies(&mut output));
        }
        if !master_closed {
            pending_input.write(master)?;
        }
    }
}

fn write_pending(output: &mut impl Write, bytes: &[u8], written: &mut usize) -> io::Result<bool> {
    if *written < bytes.len() {
        match output.write(&bytes[*written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "terminal output stopped",
                ));
            }
            Ok(count) => *written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(*written == bytes.len())
}

fn write_until(output: &mut File, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    while !write_pending(output, bytes, &mut written)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal output stayed blocked",
            ));
        }
        let mut ready = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut ready, 1, remaining.as_millis() as i32 + 1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    Ok(())
}

pub(super) fn nonblocking_output(output: impl AsFd) -> io::Result<File> {
    File::options()
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(nix::unistd::ttyname(output)?)
}

enum InputSource {
    Keyboard,
    Reply,
}

#[derive(Default)]
struct PendingInput {
    chunks: VecDeque<(InputSource, Vec<u8>, usize)>,
    keyboard: usize,
    replies: usize,
    closed: bool,
}

impl PendingInput {
    fn close(&mut self) {
        *self = Self {
            closed: true,
            ..Self::default()
        };
    }

    fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
    fn push(&mut self, source: InputSource, bytes: Vec<u8>) {
        if self.closed || bytes.is_empty() {
            return;
        }
        match source {
            InputSource::Keyboard => self.keyboard += bytes.len(),
            InputSource::Reply => self.replies += bytes.len(),
        }
        self.chunks.push_back((source, bytes, 0));
    }
    fn write(&mut self, master: &mut impl Write) -> io::Result<()> {
        let Some((source, bytes, consumed)) = self.chunks.front_mut() else {
            return Ok(());
        };
        match master.write(&bytes[*consumed..]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "terminal input write stopped",
            )),
            Ok(n) => {
                *consumed += n;
                match source {
                    InputSource::Keyboard => self.keyboard -= n,
                    InputSource::Reply => self.replies -= n,
                }
                if *consumed == bytes.len() {
                    self.chunks.pop_front();
                }
                Ok(())
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::EIO | libc::EPIPE)) => {
                self.close();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

fn update_input_modes(input: &mut Input, modes: TermMode) {
    input.agent_paste = modes.contains(TermMode::BRACKETED_PASTE);
    input.mouse = Mouse {
        tracking: if modes.contains(TermMode::MOUSE_MOTION) {
            1003
        } else if modes.contains(TermMode::MOUSE_DRAG) {
            1002
        } else if modes.contains(TermMode::MOUSE_REPORT_CLICK) {
            1000
        } else {
            0
        },
        format: if modes.contains(TermMode::SGR_MOUSE) {
            1006
        } else if modes.contains(TermMode::UTF8_MOUSE) {
            1005
        } else {
            0
        },
    };
}

struct Terminal {
    input: File,
    output: File,
    resizes: Signals,
    original: Termios,
    size: Winsize,
    panel_rows: u16,
    active: bool,
    color: bool,
    output_state: native::OutputState,
}

impl Terminal {
    fn new() -> io::Result<Self> {
        Ok(Self {
            input: duplicate(0)?,
            output: nonblocking_output(io::stdout())?,
            resizes: Signals::new([libc::SIGWINCH])?,
            original: termios::tcgetattr(io::stdin())?,
            size: terminal_size(0)?,
            panel_rows: 1,
            active: false,
            output_state: native::OutputState::default(),
            color: std::env::var("TERM").is_ok_and(|term| term != "dumb")
                && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty()),
        })
    }

    fn start(&mut self) -> io::Result<()> {
        let mut raw = self.original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&self.input, SetArg::TCSANOW, &raw)?;
        self.active = true;
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = restore_screen(&mut &self.output, self.output_state.alternate());
        let _ = termios::tcsetattr(&self.input, SetArg::TCSANOW, &self.original);
    }
}

fn restore_screen(output: &mut impl Write, alternate: Option<u16>) -> io::Result<()> {
    output.write_all(b"\x18\x1b\\\x1b[?2026l")?;
    if let Some(mode) = alternate {
        write!(output, "\x1b[?{mode}l")?;
    }
    write!(
        output,
        "\x1b[!p\x1b7\x1b[?6l\x1b[r\x1b8\
             \x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\
             \x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?2004l\x1b[=0u\
             \x1b[?1l\x1b>\x1b[4l\x1b[?7h\x1b(B\x1b[0m\x1b[0 q\x1b[?25h"
    )
}

pub(super) fn terminal_size(fd: i32) -> io::Result<Winsize> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut size) } == -1 {
        return Err(io::Error::last_os_error());
    }
    size.ws_row = size.ws_row.max(1);
    size.ws_col = size.ws_col.max(1);
    Ok(size)
}

fn child_size(mut size: Winsize, panel_rows: u16) -> Winsize {
    size.ws_col = size
        .ws_col
        .max(alacritty_terminal::term::MIN_COLUMNS as u16);
    if panel_rows == 0 {
        return size;
    }
    size.ws_row = size
        .ws_row
        .saturating_sub(panel_rows)
        .saturating_sub(1)
        .max(1);
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn every_decision_from_a_burst_reaches_the_banner_count() {
        let (sender, receiver) = mpsc::channel();
        let total = DECISIONS_PER_FRAME * 3 + 7;
        for index in 0..total {
            sender
                .send(Decision {
                    permitted: index % 5 == 0,
                    action: "net:connect".into(),
                    resource: format!("host-{index}:443"),
                    reason: Some("no permit matched".into()),
                    rule: "<default-deny>".into(),
                })
                .unwrap();
        }
        let denied = (0..total).filter(|index| index % 5 != 0).count();
        let size = Winsize {
            ws_row: 20,
            ws_col: 200,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let request = BannerRequest {
            columns: 199,
            minimized: false,
            activity: super::super::history::ActivityView::default(),
            host_rows: 20,
            child_rows: child_size(size, BANNER_ROWS).ws_row,
            pointer: None,
            color: false,
            policy: PolicyStatus::default(),
            copied: None,
        };
        let worker = BannerWorker::new(
            Banner::new("claude", "/p/profile.toml", "/p/policy.dw"),
            move || receiver.try_recv().ok(),
            request.clone(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let expected = format!("{denied} operations denied");
        loop {
            let frame = worker
                .frames
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            let mut text = String::new();
            let mut escape = false;
            for character in String::from_utf8_lossy(&frame.bytes).chars() {
                match (escape, character) {
                    (false, '\x1b') => escape = true,
                    (false, character) => text.push(character),
                    (true, '@'..='Z' | 'a'..='~') => {
                        escape = false;
                        text.push(' ');
                    }
                    (true, _) => {}
                }
            }
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if text.contains(&expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "banner never showed {expected}: {text}"
            );
            let _ = worker.requests.try_send(request.clone());
        }
    }

    #[test]
    fn file_copy_targets_match_visible_rows_after_resizing_and_clipping() {
        let config = "/profiles/claude/profile.toml";
        let policy = "/profiles/claude/policy.dw";
        for width in [4, 60, 120] {
            for height in [1, 2, 3, 5, 8, 40] {
                for minimized in [true, false] {
                    let size = Winsize {
                        ws_row: height,
                        ws_col: width,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    let request = BannerRequest {
                        columns: usize::from(width - 1),
                        minimized,
                        activity: super::super::history::ActivityView::default(),
                        host_rows: height,
                        child_rows: child_size(size, if minimized { 1 } else { BANNER_ROWS })
                            .ws_row,
                        pointer: None,
                        color: false,
                        policy: PolicyStatus::default(),
                        copied: Some((config.into(), Instant::now())),
                    };
                    let worker = BannerWorker::new(
                        Banner::new("claude", config, policy),
                        || None,
                        request.clone(),
                    )
                    .unwrap();
                    let frame = worker
                        .frames
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap()
                        .unwrap();
                    let mut screen = vt100::Parser::new(height, width, 0);
                    screen.process(&frame.bytes);
                    for (path, name) in [(policy, "policy.dw"), (config, "profile.toml")] {
                        let visible_row = screen
                            .screen()
                            .rows(0, width)
                            .position(|line| line.contains(name))
                            .map(|row| row as u16 + 1);
                        let target = frame.files.iter().find(|(_, file)| file == path);
                        assert_eq!(
                            target.map(|(area, _)| area.y),
                            visible_row,
                            "{width}x{height}, minimized={minimized}, {name}"
                        );
                        if let Some((area, _)) = target {
                            if path == config && area.y > request.child_rows + 1 {
                                assert!(
                                    screen
                                        .screen()
                                        .rows(0, width)
                                        .nth(usize::from(area.y - 2))
                                        .unwrap()
                                        .contains("Copied path")
                                );
                            }
                            let mut input = Input::new();
                            input.minimized = minimized;
                            input.native_rows = request.child_rows;
                            input.files = frame.files.clone();
                            let mut agent = Vec::new();
                            input.route(
                                format!("\x1b[<0;{};{}M", area.x + 1, area.y).as_bytes(),
                                &mut agent,
                            );
                            assert!(matches!(
                                input.actions.as_slice(),
                                [input::Action::CopyPath(copied)] if copied == path
                            ));
                            assert!(agent.is_empty());
                        }
                    }
                }
            }
        }
    }

    fn nonblocking(file: &File) {
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );
    }

    #[test]
    fn native_display_hides_startup_logs_and_preserves_terminal_bytes() {
        assert!(!exercise_worker(|_| unreachable!(), 12, None, true).contains("box:"));
    }

    #[test]
    fn early_exit_and_slow_output_keep_the_final_screen() {
        for (native, slow) in [(true, false), (false, false), (false, true)] {
            let size = Winsize {
                ws_row: 40,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let outer = openpty(&size, None).unwrap();
            let mut host = File::from(outer.master);
            let input = File::from(outer.slave);
            let mut terminal = Terminal {
                output: input.try_clone().unwrap(),
                original: termios::tcgetattr(&input).unwrap(),
                input,
                resizes: Signals::new([libc::SIGWINCH]).unwrap(),
                size,
                panel_rows: u16::from(!native),
                active: false,
                color: false,
                output_state: native::OutputState::default(),
            };
            terminal.start().unwrap();
            nonblocking(&host);
            nonblocking(&terminal.output);
            let inner =
                openpty(&child_size(size, terminal.panel_rows), &terminal.original).unwrap();
            let mut master = File::from(inner.master);
            let mut child = File::from(inner.slave);
            let workload_terminal = child.try_clone().unwrap();
            nonblocking(&master);
            let (read, write) = nix::unistd::pipe().unwrap();
            let mut diagnostics = Log::new(File::from(read), tempfile::tempfile());
            let producer = if slow {
                Some(std::thread::spawn(move || {
                    for row in 0..1500 {
                        writeln!(child, "ROW {row:04} {}\r", "x".repeat(100)).unwrap();
                    }
                    child.write_all(b"FINAL FAREWELL\r\n").unwrap();
                    drop(child);
                    drop(write);
                }))
            } else {
                if !native {
                    child.write_all(b"PRIMARY").unwrap();
                }
                child.write_all(b"\x1b[?1049h").unwrap();
                drop(child);
                drop(write);
                None
            };
            let scene = super::super::policy::tests::Scene::new();
            let policy = scene.start(|_| Ok(()));
            let worker = std::thread::spawn(move || {
                let result = relay(
                    &mut terminal,
                    &mut master,
                    workload_terminal,
                    &mut diagnostics,
                    (!native).then_some(&policy),
                    "test",
                    |initial| {
                        BannerWorker::spawn(initial, |request| {
                            Ok(BannerFrame {
                                request,
                                bytes: Vec::new(),
                                controls: None,
                                files: Vec::new(),
                            })
                        })
                    },
                );
                (result.map(|()| diagnostics), terminal)
            });
            let started = Instant::now();
            let mut last_output = started;
            let mut output = Vec::new();
            while !worker.is_finished() {
                let mut bytes = [0; 1024];
                match host.read(&mut bytes) {
                    Ok(count) => {
                        if count > 0 {
                            last_output = Instant::now();
                            output.extend_from_slice(&bytes[..count]);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("host read: {error}"),
                }
                assert!(
                    last_output.elapsed() < Duration::from_secs(10)
                        && started.elapsed() < Duration::from_secs(60),
                    "relay did not finish: native={native}, slow={slow}, bytes={}",
                    output.len()
                );
                std::thread::sleep(Duration::from_millis(if slow { 25 } else { 2 }));
            }
            let (result, terminal) = worker.join().unwrap();
            if let Some(producer) = producer {
                producer.join().unwrap();
            }
            let error = host.read_to_end(&mut output).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            let mut diagnostics = result.unwrap();
            assert!(diagnostics.preview().is_empty());
            assert!(!terminal.active);
            if !slow {
                assert_eq!(
                    output.windows(8).any(|bytes| bytes == b"\x1b[?1049h"),
                    native
                );
            }
            let mut screen = vt100::Parser::new(size.ws_row, size.ws_col, 2000);
            screen.process(&output);
            assert!(!screen.screen().alternate_screen());
            screen.process(b"$ ");
            if slow {
                assert!(screen.screen().contents().contains("FINAL FAREWELL\n$ "));
            } else {
                assert_eq!(
                    screen.screen().contents(),
                    if native { "$ " } else { "PRIMARY\n$ " }
                );
            }
        }
    }

    #[test]
    fn cleanup_keeps_the_native_footer_and_the_shell_cursor_after_it() {
        for bytes in [
            b"BEFORE\r\nFOOTER\r\n".as_slice(),
            b"BEFORE\r\nFOOTER\r\n\x1b[?1049hTRANSIENT",
        ] {
            let mut state = native::OutputState::default();
            let mut host = vt100::Parser::new(12, 60, 100);
            state.process(bytes);
            host.process(bytes);
            let mut cleanup = Vec::new();
            restore_screen(&mut cleanup, state.alternate()).unwrap();
            host.process(&cleanup);
            assert!(!host.screen().alternate_screen());
            host.process(b"$ ");
            assert_eq!(host.screen().contents(), "BEFORE\nFOOTER\n$ ");
        }
    }

    fn relay_terminal(native: bool) -> (Terminal, File, File, File) {
        let size = Winsize {
            ws_row: 12,
            ws_col: 60,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let outer = openpty(&size, None).unwrap();
        let host = File::from(outer.master);
        let input = File::from(outer.slave);
        let mut raw = termios::tcgetattr(&input).unwrap();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&input, SetArg::TCSANOW, &raw).unwrap();
        nonblocking(&host);
        let inner = openpty(&child_size(size, u16::from(!native)), &raw).unwrap();
        let master = File::from(inner.master);
        let child = File::from(inner.slave);
        nonblocking(&master);
        let mut terminal = Terminal {
            output: input.try_clone().unwrap(),
            output_state: native::OutputState::default(),
            input,
            resizes: Signals::new([libc::SIGWINCH]).unwrap(),
            original: raw,
            size,
            panel_rows: u16::from(!native),
            active: false,
            color: false,
        };
        terminal.start().unwrap();
        nonblocking(&terminal.output);
        (terminal, host, master, child)
    }

    fn exercise_worker(
        start: impl FnOnce(BannerRequest) -> io::Result<BannerWorker> + Send + 'static,
        child_rows: u16,
        banner_ready: Option<&str>,
        native: bool,
    ) -> String {
        exercise(start, child_rows, banner_ready, native, 1).0
    }

    /// Run the relay as `exercise_worker` does, and keep the agent running until the policy worker
    /// has installed `installs` policies. Return the diagnostics and each installed policy.
    fn exercise(
        start: impl FnOnce(BannerRequest) -> io::Result<BannerWorker> + Send + 'static,
        child_rows: u16,
        banner_ready: Option<&str>,
        native: bool,
        installs: usize,
    ) -> (String, Vec<String>) {
        let (mut terminal, mut host, mut master, mut child) = relay_terminal(native);
        let workload_terminal = child.try_clone().unwrap();
        let size = terminal.size;
        let (read, write) = nix::unistd::pipe().unwrap();
        let mut core_output = File::from(write);
        let saved = tempfile::NamedTempFile::new().unwrap();
        let mut diagnostics = Log::new(File::from(read), saved.reopen());
        let _host_lifetime = terminal.output.try_clone().unwrap();
        let (ready, readiness) = mpsc::channel();
        let (toggled, toggles) = mpsc::channel();
        let (installed, all_installed) = mpsc::channel();
        let scene = super::super::policy::tests::Scene::new();
        let mut count = 0;
        let policy = scene.start(move |policy| {
            toggled.send(policy.text.clone()).unwrap();
            count += 1;
            if count == installs {
                let _ = installed.send(());
            }
            Ok(())
        });
        // With a banner running, Ctrl+\ belongs to `box`: it turns policy off once a frame is on
        // screen, and does nothing before. Without a banner it reaches the agent.
        let banner_running = !native && child_rows < size.ws_row;
        let banner_up = banner_running && banner_ready.is_some();
        let expected: &'static [u8] = if banner_running {
            b"ping\r"
        } else {
            b"\x1cping\r"
        };
        let relay_thread = std::thread::spawn(move || {
            relay(
                &mut terminal,
                &mut master,
                workload_terminal,
                &mut diagnostics,
                (!native).then_some(&policy),
                "test",
                start,
            )
        });
        let native_bytes = b"\x1b[?u\x1b]52;c;?\x07\x1b_Ga=q;AAAA\x1b\\";
        let child_thread = std::thread::spawn(move || {
            core_output.write_all(&vec![b' '; 33 * 1024]).unwrap();
            core_output.write_all(b"CORE_START\n").unwrap();
            if native {
                child.write_all(native_bytes).unwrap();
            }
            child
                .write_all(b"\x1b[2J\x1b[?1h\x1b[?2004h\x1b[6n")
                .unwrap();
            let mut fds = [libc::pollfd {
                fd: child.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            assert!(unsafe { libc::poll(fds.as_mut_ptr(), 1, 5000) } > 0);
            let mut reply = [0; 6];
            child.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"\x1b[1;1R");
            assert!(unsafe { libc::poll(fds.as_mut_ptr(), 1, 5000) } > 0);
            let mut keys = [0; 5];
            child.read_exact(&mut keys).unwrap();
            assert_eq!(&keys, b"load\r");
            child.write_all(b"\x1b[HBEFORE").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let current = terminal_size(child.as_raw_fd()).unwrap();
                if current.ws_row == child_rows && current.ws_col == size.ws_col + u16::from(native)
                {
                    break;
                }
                assert!(Instant::now() < deadline, "child was not resized");
                std::thread::sleep(Duration::from_millis(5));
            }
            ready.send(()).unwrap();
            let mut fds = [libc::pollfd {
                fd: child.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            assert!(
                unsafe { libc::poll(fds.as_mut_ptr(), 1, 5000) } > 0,
                "relay stopped forwarding keys"
            );
            let mut keys = vec![0; expected.len()];
            child.read_exact(&mut keys).unwrap();
            assert_eq!(&keys, expected);
            if banner_up {
                all_installed
                    .recv_timeout(Duration::from_secs(5))
                    .expect("the policy worker installed each policy");
            }
            core_output.write_all(&b"\nCORE_LIVE\n".repeat(16)).unwrap();
            child
                .write_all(b"\x1b[?1049hTRANSIENT\x1b[?1049l\x1b[?2026h\x1b[999;1HDONE\r\n")
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(7);
        let mut screen = vt100::Parser::new(size.ws_row, size.ws_col, 1000);
        let mut sent = false;
        let mut loading_seen = false;
        let mut output = Vec::new();
        let mut child_ready = false;
        let mut bytes = [0; 8192];
        loop {
            assert!(
                Instant::now() < deadline,
                "relay did not finish after child EOF"
            );
            child_ready |= readiness.try_recv().is_ok();
            if native && !loading_seen && output.windows(4).any(|part| part == b"\x1b[6n") {
                assert!(
                    output
                        .windows(native_bytes.len())
                        .any(|part| part == native_bytes)
                );
                let resized = Winsize {
                    ws_col: size.ws_col + 1,
                    ..size
                };
                assert_ne!(
                    unsafe { libc::ioctl(host.as_raw_fd(), libc::TIOCSWINSZ as _, &resized) },
                    -1
                );
                host.write_all(b"\x1b[1;1Rload\r").unwrap();
                loading_seen = true;
            }
            if !native
                && !loading_seen
                && screen.screen().application_cursor()
                && screen.screen().bracketed_paste()
                && screen
                    .screen()
                    .contents()
                    .contains("Starting test in the box")
            {
                assert!(!screen.screen().contents().contains("BANNER"));
                host.write_all(b"load\r").unwrap();
                loading_seen = true;
            }
            if !sent
                && child_ready
                && screen.screen().contents().contains("BEFORE")
                && banner_ready.is_none_or(|text| screen.screen().contents().contains(text))
            {
                host.write_all(b"\x1cping\r").unwrap();
                sent = true;
            }
            match host.read(&mut bytes) {
                Ok(n) => {
                    output.extend_from_slice(&bytes[..n]);
                    screen.process(&bytes[..n]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) || error.raw_os_error() == Some(libc::EIO) => {}
                Err(error) => panic!("host read: {error}"),
            }
            if relay_thread.is_finished() {
                relay_thread.join().unwrap().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let report = std::fs::read_to_string(saved.path()).unwrap();
        assert!(
            report.contains("CORE_START\n"),
            "startup stderr was not captured"
        );
        assert!(
            !output
                .windows(b"CORE_START".len())
                .any(|bytes| bytes == b"CORE_START"),
            "startup stderr reached the visible screen"
        );
        assert!(
            !output
                .windows(b"CORE_LIVE".len())
                .any(|bytes| bytes == b"CORE_LIVE"),
            "Core messages reached the agent display"
        );
        assert_eq!(report.matches("CORE_LIVE").count(), 16);
        assert!(
            !report.contains("TRANSIENT"),
            "workload output reached the log"
        );
        while let Ok(n) = host.read(&mut bytes) {
            if n == 0 {
                break;
            }
            screen.process(&bytes[..n]);
        }
        child_thread.join().unwrap();
        assert!(loading_seen, "no startup indicator before the agent drew");
        let mut policies = Vec::new();
        if banner_up {
            assert_eq!(
                toggles.recv_timeout(Duration::from_secs(2)).unwrap(),
                scene.profile.off()
            );
            policies.extend(toggles.try_iter());
        } else {
            assert!(
                toggles.recv_timeout(Duration::from_millis(200)).is_err(),
                "Ctrl+\\ changed policy without a banner"
            );
        }
        assert!(!screen.screen().alternate_screen());
        screen.process(b"$ ");
        assert!(screen.screen().contents().contains("DONE\n$ "));
        let mut contents = screen.screen().contents();
        screen.screen_mut().set_scrollback(1000);
        contents.push_str(&screen.screen().contents());
        assert!(
            !contents.contains("CORE_LIVE"),
            "Core messages overwrote the agent screen: {contents}"
        );
        assert!(contents.contains("BEFORE"), "{contents}");
        assert!(
            contents.contains("DONE"),
            "synchronized output lost at EOF: {contents}"
        );
        (report, policies)
    }

    #[test]
    fn scrolling_and_copying_pause_redraws_until_release_or_cancellation() {
        let (mut terminal, mut host, mut master, mut child) = relay_terminal(false);
        let workload_terminal = child.try_clone().unwrap();
        let size = terminal.size;
        let _host_lifetime = terminal.output.try_clone().unwrap();
        let (read, core_output) = nix::unistd::pipe().unwrap();
        let mut diagnostics = Log::new(File::from(read), tempfile::tempfile());
        let scene = super::super::policy::tests::Scene::new();
        let policy = scene.start(|_| Ok(()));
        let worker = std::thread::spawn(move || {
            relay(
                &mut terminal,
                &mut master,
                workload_terminal,
                &mut diagnostics,
                Some(&policy),
                "test",
                |initial| {
                    BannerWorker::spawn(initial, |request| {
                        Ok(BannerFrame {
                            bytes: if request.minimized {
                                b"\x1b[12;1HBANNER".to_vec()
                            } else {
                                b"\x1b[12;1HBANNER policy.dw".to_vec()
                            },
                            controls: None,
                            files: vec![(Rect::new(7, 12, 9, 1), "/copy-test/policy.dw".into())],
                            request,
                        })
                    })
                },
            )
        });
        let mut screen = vt100::Parser::new(size.ws_row, size.ws_col, 0);
        let mut output = Vec::new();
        let mut wait = |host: &mut File, done: &dyn Fn(&vt100::Screen, &[u8]) -> bool| {
            let size = terminal_size(host.as_raw_fd()).unwrap();
            screen.screen_mut().set_size(size.ws_row, size.ws_col);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut bytes = [0; 8192];
            loop {
                match host.read(&mut bytes) {
                    Ok(n) => {
                        output.extend_from_slice(&bytes[..n]);
                        screen.process(&bytes[..n]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("host read: {error}"),
                }
                if done(screen.screen(), &output) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "interaction timed out: {}",
                    screen.screen().contents()
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        child.write_all(b"\x1b[?2004hREADY").unwrap();
        wait(&mut host, &|screen, _| {
            screen.contents().contains("READY")
                && screen.mouse_protocol_mode() == vt100::MouseProtocolMode::AnyMotion
        });
        host.write_all(b"\x1d").unwrap();
        wait(&mut host, &|screen, _| {
            screen.contents().contains("policy.dw")
        });
        child.write_all(&b"HISTORY\r\n".repeat(16)).unwrap();
        child.write_all(b"\x1b[2J\x1b[HBEFORE").unwrap();
        wait(&mut host, &|screen, _| screen.contents().contains("BEFORE"));
        host.write_all(b"\x1b[<64;2;3M").unwrap();
        wait(&mut host, &|screen, _| {
            screen.contents().contains("HISTORY")
        });
        host.write_all(b"\x1b[200~\x1b[201~").unwrap();
        wait(&mut host, &|screen, _| {
            screen.contents().contains("BEFORE") && !screen.contents().contains("HISTORY")
        });
        child
            .write_all(b"\x1b[6n\x1b[?2026h\x1b[3;1HBUFFERED")
            .unwrap();
        host.write_all(b"\x1b[<0;1;1M\x1b[<32;6;1M").unwrap();
        nonblocking(&child);
        let mut reply = [0; 18];
        let mut received = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while received < reply.len() {
            match child.read(&mut reply[received..]) {
                Ok(n) => received += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("child read: {error}"),
            }
            assert!(Instant::now() < deadline, "synchronized frame was not read");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(&reply, b"\x1b[200~\x1b[201~\x1b[1;7R");
        wait(&mut host, &|screen, _| screen.cell(0, 0).unwrap().inverse());
        child
            .write_all(b"\x1b[?2026l\x1b[H\x1b[2KBEFORE\x1b[2;1HLIVE")
            .unwrap();
        let redraw_at = Instant::now();
        wait(&mut host, &|screen, _| {
            assert!(
                !screen.contents().contains("LIVE") && !screen.contents().contains("BUFFERED"),
                "agent repainted during selection"
            );
            redraw_at.elapsed() >= Duration::from_millis(150)
        });
        host.write_all(
            b"\x1b[<0;6;1m\x1b[<0;8;12M\x1b[<0;8;12m\x1b[<0;3;1M\x1b[<32;6;1M\x1b[<0;6;1m",
        )
        .unwrap();
        wait(&mut host, &|screen, output| {
            screen.contents().contains("LIVE")
                && output.windows(16).any(|b| b == b"\x1b]52;c;Rk9SRQ==\x07")
        });
        host.write_all(b"\x1b[<0;1;1M\x1b[<32;6;1M").unwrap();
        wait(&mut host, &|screen, _| screen.cell(0, 0).unwrap().inverse());
        let resized = Winsize {
            ws_col: size.ws_col + 1,
            ..size
        };
        assert_ne!(
            unsafe { libc::ioctl(host.as_raw_fd(), libc::TIOCSWINSZ as _, &resized) },
            -1
        );
        child.write_all(b"\x1b[3;1HRESIZED").unwrap();
        wait(&mut host, &|screen, _| {
            screen.contents().contains("RESIZED") && !screen.cell(0, 0).unwrap().inverse()
        });
        host.write_all(b"\x1b[<0;1;1M\x1b[<32;6;1M").unwrap();
        wait(&mut host, &|screen, _| screen.cell(0, 0).unwrap().inverse());
        host.write_all(b"x").unwrap();
        wait(&mut host, &|screen, _| {
            !screen.cell(0, 0).unwrap().inverse()
        });
        drop(core_output);
        drop(child);
        wait(&mut host, &|_, _| worker.is_finished());
        worker.join().unwrap().unwrap();
        let latest = output.windows(7).rposition(|b| b == b"\x1b]52;c;").unwrap();
        assert!(
            output[latest..].starts_with(b"\x1b]52;c;Rk9SRQ==\x07"),
            "an older copy replaced the latest selection"
        );
    }

    #[test]
    fn late_core_messages_wait_until_exit_without_changing_the_agent_screen() {
        let diagnostics = exercise_worker(
            |initial| {
                BannerWorker::spawn(initial, |request| {
                    Ok(BannerFrame {
                        request,
                        bytes: b"\x1b[12;1HBANNER".to_vec(),
                        controls: None,
                        files: Vec::new(),
                    })
                })
            },
            10,
            Some("BANNER"),
            false,
        );
        assert!(!diagnostics.contains("box:"));
    }

    #[test]
    fn a_worker_spawn_failure_keeps_the_same_pty_and_restores_full_height() {
        let diagnostics =
            exercise_worker(|_| Err(io::Error::other("spawn refused")), 12, None, false);
        assert!(diagnostics.contains("spawn refused"));
    }

    #[test]
    fn a_worker_error_keeps_input_output_and_resizes_the_child() {
        let diagnostics = exercise_worker(
            |initial| BannerWorker::spawn(initial, |_| Err(io::Error::other("banner draw failed"))),
            12,
            None,
            false,
        );
        assert!(diagnostics.contains("banner draw failed"));
    }

    /// **A banner that fails while policy is off turns policy back on**, so policy is never off
    /// without a banner that says so.
    #[test]
    fn a_banner_that_fails_while_policy_is_off_turns_policy_back_on() {
        let (diagnostics, installed) = exercise(
            |initial| {
                BannerWorker::spawn(initial, |request| {
                    if !request.policy.enabled {
                        return Err(io::Error::other("banner draw failed"));
                    }
                    Ok(BannerFrame {
                        request,
                        bytes: b"\x1b[12;1HREADY".to_vec(),
                        controls: None,
                        files: Vec::new(),
                    })
                })
            },
            10,
            Some("READY"),
            false,
            2,
        );
        assert!(diagnostics.contains("banner draw failed"));
        assert_eq!(installed.len(), 1, "{installed:?}");
        assert!(!installed[0].contains("policy_off"), "{installed:?}");
    }

    #[test]
    fn a_stalled_worker_cannot_block_input_output_or_shutdown() {
        let (release, blocked) = mpsc::channel();
        exercise_worker(
            move |initial| {
                BannerWorker::spawn(initial, move |_| {
                    blocked.recv().unwrap();
                    Err(io::Error::other("released"))
                })
            },
            10,
            None,
            false,
        );
        release.send(()).unwrap();
    }

    #[test]
    fn a_temporary_worker_error_recovers_without_resizing_or_interrupting_the_agent() {
        let diagnostics = exercise_worker(
            |initial| {
                let mut failed = false;
                BannerWorker::spawn(initial, move |request| {
                    if !failed {
                        failed = true;
                        return Err(io::Error::other("temporary"));
                    }
                    Ok(BannerFrame {
                        request,
                        bytes: b"\x1b[12;1HRECOVERED".to_vec(),
                        controls: None,
                        files: Vec::new(),
                    })
                })
            },
            10,
            Some("RECOVERED"),
            false,
        );
        assert!(!diagnostics.contains("box:"));
    }

    #[test]
    fn healthy_frames_allow_later_recovery_but_consecutive_errors_stop() {
        use super::super::history::ActivityView;

        let request = BannerRequest {
            columns: 60,
            minimized: true,
            activity: ActivityView::default(),
            host_rows: 12,
            child_rows: 10,
            pointer: None,
            color: false,
            policy: PolicyStatus::default(),
            copied: None,
        };
        let mut attempt = 0;
        let (consumed, consumption) = mpsc::channel();
        let worker = BannerWorker::spawn(request, move |request| {
            attempt += 1;
            if matches!(attempt, 3 | 5) {
                consumption.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            match attempt {
                2 | 4 => Ok(BannerFrame {
                    request,
                    bytes: vec![attempt],
                    controls: None,
                    files: Vec::new(),
                }),
                1 | 3 => Err(io::Error::other("temporary")),
                5 | 6 => Err(io::Error::other("permanent")),
                _ => panic!("persistent failure was retried without a bound"),
            }
        })
        .unwrap();
        for expected in [2, 4] {
            let frame = worker
                .frames
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            assert_eq!(frame.bytes, vec![expected]);
            consumed.send(()).unwrap();
        }
        let failure = worker.frames.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(failure.err().unwrap().to_string(), "permanent");
    }

    #[test]
    fn short_writes_keep_input_and_output_bytes_in_order() {
        struct ShortWriter(Vec<u8>, Option<io::Error>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some(error) = self.1.take() {
                    return Err(error);
                }
                let count = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut pending = PendingInput::default();
        pending.push(InputSource::Keyboard, b"keys".to_vec());
        pending.push(InputSource::Reply, b"\x1b[2;4R".to_vec());
        pending.push(InputSource::Keyboard, b"more".to_vec());
        let mut writer = ShortWriter(Vec::new(), None);
        pending.write(&mut writer).unwrap();
        assert_eq!((pending.keyboard, pending.replies), (6, 6));
        while !pending.is_empty() {
            pending.write(&mut writer).unwrap();
        }
        assert_eq!(writer.0, b"keys\x1b[2;4Rmore");
        assert_eq!((pending.keyboard, pending.replies), (0, 0));

        writer.0.clear();
        let mut written = 0;
        assert!(!write_pending(&mut writer, b"frame", &mut written).unwrap());
        assert_eq!(written, 2);
        for error in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            writer.1 = Some(error.into());
            assert!(!write_pending(&mut writer, b"frame", &mut written).unwrap());
            assert_eq!(written, 2);
        }
        assert!(!write_pending(&mut writer, b"frame", &mut written).unwrap());
        assert!(write_pending(&mut writer, b"frame", &mut written).unwrap());
        assert_eq!(writer.0, b"frame");

        for error in [libc::EIO, libc::EPIPE] {
            let mut pending = PendingInput::default();
            pending.push(InputSource::Keyboard, b"keys".to_vec());
            pending.push(InputSource::Reply, b"reply".to_vec());
            let mut writer = ShortWriter(Vec::new(), Some(io::Error::from_raw_os_error(error)));
            pending.write(&mut writer).unwrap();
            pending.push(InputSource::Keyboard, b"more".to_vec());
            pending.push(InputSource::Reply, b"reply".to_vec());
            pending.write(&mut writer).unwrap();
            assert!(writer.0.is_empty());
            assert!(pending.is_empty());
            assert_eq!((pending.keyboard, pending.replies), (0, 0));
        }
    }

    #[test]
    fn a_one_column_host_gives_the_child_the_models_minimum_width() {
        let size = Winsize {
            ws_row: 1,
            ws_col: 1,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        for rows in [0, 1] {
            let size = child_size(size, rows);
            assert_eq!((size.ws_row, size.ws_col), (1, 2));
        }
    }

    #[test]
    fn terminal_cleanup_resets_modes_before_restoring_the_outer_screen() {
        let size = Winsize {
            ws_row: 12,
            ws_col: 60,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pair = openpty(&size, None).unwrap();
        let mut host = File::from(pair.master);
        let input = File::from(pair.slave);
        let inspect = input.try_clone().unwrap();
        let original = termios::tcgetattr(&input).unwrap();
        let mut terminal = Terminal {
            output: input.try_clone().unwrap(),
            output_state: native::OutputState::default(),
            input,
            original: original.clone(),
            resizes: Signals::new([libc::SIGWINCH]).unwrap(),
            size,
            panel_rows: 1,
            active: false,
            color: false,
        };
        terminal.start().unwrap();
        assert!(
            !termios::tcgetattr(&inspect)
                .unwrap()
                .local_flags
                .contains(termios::LocalFlags::ICANON)
        );
        drop(terminal);
        let restored = termios::tcgetattr(&inspect).unwrap();
        assert_eq!(restored.input_flags, original.input_flags);
        assert_eq!(restored.output_flags, original.output_flags);
        assert_eq!(restored.control_flags, original.control_flags);
        assert_eq!(restored.control_chars, original.control_chars);
        assert_eq!(
            restored.local_flags & !termios::LocalFlags::PENDIN,
            original.local_flags & !termios::LocalFlags::PENDIN
        );
        nonblocking(&host);
        let mut bytes = Vec::new();
        let _ = host.read_to_end(&mut bytes);
        assert!(bytes.ends_with(b"\x1b[?25h"));
        assert!(bytes.windows(8).any(|bytes| bytes == b"\x1b[?2004l"));
    }
}
