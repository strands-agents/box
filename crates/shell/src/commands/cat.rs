// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: cat [-n] [FILE]...
Concatenate FILE(s) to standard output.
With no FILE, read standard input.

Options:
  -n    number all output lines";

async fn cat_stream<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    w: &mut crate::os::FdWriter,
    number: bool,
    lineno: &mut usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !number {
        tokio::io::copy(r, w).await?;
        return Ok(());
    }
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        *lineno += 1;
        wprint!(w, "{:>6}\t{}", lineno, line)?;
    }
    Ok(())
}

#[command("cat")]
async fn cmd_cat(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut files = Vec::new();
    let mut number = false;
    while let Some(arg) = parser.next()? {
        match arg {
            Short('n') => number = true,
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) => files.push(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    let mut w = io::stdout()?;
    let mut lineno = 0usize;
    if files.is_empty() {
        if let Ok(mut r) = io::stdin() {
            cat_stream(&mut r, &mut w, number, &mut lineno).await?;
        }
        return Ok(0);
    }
    let mut stdin = None;
    for path in &files {
        if path == "-" {
            if stdin.is_none() {
                stdin = Some(io::stdin()?);
            }
            let reader = stdin.as_mut().ok_or("cat: standard input unavailable")?;
            cat_stream(reader, &mut w, number, &mut lineno).await?;
        } else {
            let fd = io::open(os, path, OpenFlags::read()).await?;
            let mut reader = io::take_reader(fd)?;
            cat_stream(&mut reader, &mut w, number, &mut lineno).await?;
        }
    }
    Ok(0)
}
