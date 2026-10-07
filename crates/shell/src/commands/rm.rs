// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: rm [-rf] FILE...
Remove files or directories.

Options:
  -f  ignore nonexistent files
  -r  remove directories and their contents recursively";

async fn report(path: &str, e: &std::io::Error) -> std::io::Result<()> {
    let mut ew = io::stderr()?;
    wprintln!(ew, "rm: {}: {}", path, e)
}

async fn remove_recursive(os: &Mediated, path: &str) -> std::io::Result<bool> {
    let st = io::lstat(os, path).await;
    if st.is_dir && !st.is_symlink {
        let mut ok = true;
        for entry in io::list_dir(os, path).await? {
            let child = format!("{}/{}", path, entry.name);
            if !Box::pin(remove_recursive(os, &child)).await? {
                ok = false;
            }
        }
        if let Err(e) = io::remove_dir(os, path).await {
            report(path, &e).await?;
            ok = false;
        }
        Ok(ok)
    } else if let Err(e) = io::remove_file(os, path).await {
        report(path, &e).await?;
        Ok(false)
    } else {
        Ok(true)
    }
}

#[command("rm")]
async fn cmd_rm(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut force = false;
    let mut recursive = false;
    let mut files = Vec::new();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('f') => force = true,
            Short('r') | Short('R') => recursive = true,
            Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) => files.push(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    if files.is_empty() {
        return Err("rm: missing operand".into());
    }
    let mut code = 0;
    for path in &files {
        let st = io::lstat(os, path).await;
        if !st.exists {
            if !force {
                let mut ew = io::stderr()?;
                wprintln!(ew, "rm: {}: No such file or directory", path)?;
                code = 1;
            }
            continue;
        }
        if st.is_dir && !st.is_symlink {
            if !recursive {
                let mut ew = io::stderr()?;
                wprintln!(ew, "rm: {}: is a directory", path)?;
                code = 1;
                continue;
            }
            match remove_recursive(os, path).await {
                Ok(true) => {}
                Ok(false) => code = 1,
                Err(e) => {
                    report(path, &e).await?;
                    code = 1;
                }
            }
        } else if let Err(e) = io::remove_file(os, path).await {
            report(path, &e).await?;
            code = 1;
        }
    }
    Ok(code)
}
