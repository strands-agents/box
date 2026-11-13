// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: head [-n LINES | -c BYTES] [FILE]
Output the first part of files.

Options:
  -n, --lines LINES   number of lines to show (default: 10)
  -c, --bytes BYTES   number of bytes to show";

#[command("head")]
async fn cmd_head(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(legacy_count(args));
    let mut n: usize = 10;
    let mut bytes: Option<u64> = None;
    let mut file = None;
    while let Some(arg) = parser.next()? {
        match arg {
            Short('n') | Long("lines") => {
                n = parser.value()?.parse()?;
                bytes = None;
            }
            Short('c') | Long("bytes") => bytes = Some(parser.value()?.parse()?),
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) if file.is_none() => file = Some(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    let mut w = io::stdout()?;
    if let Some(path) = &file {
        let fd = io::open(os, path, OpenFlags::read()).await?;
        let reader = io::take_reader(fd)?;
        return write_head(&mut w, reader, n, bytes).await;
    }

    // `io::stdin` takes fd 0 out of the process. Put the remaining input back so a later
    // command (or the rest of a substitution's caller) can still read it. `take(c)` requests
    // only `c` bytes; leftover channel data stays in the reader and is restored with it.
    let mut reader = io::stdin()?;
    let status = write_head(&mut w, &mut reader, n, bytes).await;
    io::with_process(|p| p.restore_fd(0, reader.into_fd_kind()));
    status
}

async fn write_head<R, W>(w: &mut W, reader: R, n: usize, bytes: Option<u64>) -> CommandResult
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    if let Some(c) = bytes {
        tokio::io::copy(&mut reader.take(c), &mut *w).await?;
        return Ok(0);
    }
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    for _ in 0..n {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        w.write_all(line.as_bytes()).await?;
    }
    Ok(0)
}

/// `-N` spelled as `-n N`, the obsolete form coreutils still accepts.
fn legacy_count(args: &[String]) -> Vec<String> {
    let mut rewritten = Vec::with_capacity(args.len() + 1);
    for arg in args {
        match arg.strip_prefix('-') {
            Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                rewritten.push("-n".to_string());
                rewritten.push(digits.to_string());
            }
            _ => rewritten.push(arg.clone()),
        }
    }
    rewritten
}
