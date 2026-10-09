use super::super::{LAYER_BYPASS, LAYER_NOISE};
use super::{capture::Capture, sample, write_row};
use std::{
    fs, io,
    path::Path,
    sync::mpsc::{Receiver, RecvTimeoutError},
    time::Duration,
};

pub(super) fn run(
    dir: &Path,
    mut capture: Capture,
    stop: Receiver<()>,
    interval: Duration,
) -> io::Result<usize> {
    let (mut red, mut yellow) = (false, false);
    loop {
        super::super::shutdown::check()?;
        capture.check()?;
        let roots = fs::read_to_string(dir.join("subtree-roots"))?
            .lines()
            .map(|line| line.parse::<u32>().map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
        let hits = sample(&roots)?;
        if !red && let Some(hit) = hits.first() {
            write_row(
                dir,
                LAYER_BYPASS,
                format!(
                    "BOX-subtree process {}(pid={}) owns a connection to {} ({}) — CONFIRMED BREACH",
                    hit.command, hit.pid, hit.peer, hit.state
                ),
                "RED",
                true,
            )?;
            red = true;
        }
        let packets = capture.count()?;
        if !yellow && packets > 0 {
            let summary = capture
                .summary()
                .unwrap_or_else(|error| format!("packet summary unavailable: {error}"));
            write_row(
                dir,
                LAYER_NOISE,
                format!(
                    "capture saw {packets} forbidden packet(s); packet attribution is unresolved\n{summary}"
                ),
                "YELLOW",
                false,
            )?;
            yellow = true;
        }
        match stop.recv_timeout(interval) {
            Err(RecvTimeoutError::Timeout) => (),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let packets = capture.stop()?;
    if !yellow && packets > 0 {
        write_row(
            dir,
            LAYER_NOISE,
            format!(
                "capture saw {packets} forbidden packet(s) at shutdown; packet attribution is unresolved"
            ),
            "YELLOW",
            false,
        )?;
    }
    Ok(packets)
}
