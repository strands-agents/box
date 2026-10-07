// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: sleep SECONDS
Pause for SECONDS (accepts decimals).";

#[command("sleep")]
async fn cmd_sleep(_os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut secs = None;
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) if secs.is_none() => secs = Some(val.string()?.parse::<f64>()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    let secs = secs.ok_or("sleep: missing operand")?;
    let sleep_dur = std::time::Duration::from_secs_f64(secs);

    #[cfg(target_arch = "wasm32")]
    {
        // WASI supports std::thread::sleep via poll_oneoff
        std::thread::sleep(sleep_dur);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let deadline = io::with_process(|p| p.deadline);
        if let Some(dl) = deadline {
            // Whichever fires first, but the two outcomes are NOT the same and must not be
            // reported the same way. Losing to the deadline means the sleep did not happen;
            // `Ok(0)` there claims it did.
            //
            // `Shell::timeout`'s own doc states the contract this restores: an expired
            // command yields "`status = 1` with `strands-shell: execution timeout exceeded`
            // in stderr", which is what `check_limits` returns and what the Lua interrupt
            // hook raises. `sleep` was the one place that raced the deadline correctly and
            // then discarded the distinction — so `sleep 3600` under a 30s timeout exited 0
            // after 30s, indistinguishable from having actually slept an hour.
            tokio::select! {
                _ = tokio::time::sleep(sleep_dur) => {}
                _ = tokio::time::sleep_until(dl) => {
                    return Err("strands-shell: execution timeout exceeded".into());
                }
            }
        } else {
            tokio::time::sleep(sleep_dur).await;
        }
    }

    Ok(0)
}
