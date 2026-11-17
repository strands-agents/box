//! Runs a selected workload for the benchmark runner.

#![warn(missing_docs, unreachable_pub)]

use std::io::{self, Read, Write};

#[path = "../protocol.rs"]
mod protocol;

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (Some(mode), None) if mode == protocol::STARTUP => startup(),
        _ => Err(io::Error::other("usage: box-bench-probe startup")),
    }
}

fn startup() -> io::Result<()> {
    let mut output = io::stdout().lock();
    output.write_all(protocol::READY)?;
    output.flush()?;
    let mut release = [0; protocol::RELEASE.len()];
    io::stdin().read_exact(&mut release)?;
    if release != *protocol::RELEASE {
        return Err(io::Error::other("invalid benchmark release"));
    }
    Ok(())
}
