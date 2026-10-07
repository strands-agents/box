// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: mkdir [-p] DIRECTORY...
Create directories.

Options:
  -p  create parent directories as needed";

#[command("mkdir")]
async fn cmd_mkdir(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut parents = false;
    let mut dirs = Vec::new();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('p') => parents = true,
            Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) => dirs.push(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    if dirs.is_empty() {
        return Err("mkdir: missing operand".into());
    }
    for dir in &dirs {
        if parents {
            create_dir_with_parents(os, dir).await?;
        } else {
            io::create_dir(os, dir).await?;
        }
    }
    Ok(0)
}

/// Create `dir` and each missing ancestor, without creating an ancestor it cannot see.
async fn create_dir_with_parents(os: &Mediated, dir: &str) -> std::io::Result<()> {
    let prefixes = prefixes(dir);
    let mut missing = false;
    for (index, prefix) in prefixes.iter().enumerate() {
        if matches!(component(prefix), "." | "..") {
            missing = false;
            continue;
        }
        if !missing {
            let is_leaf = index + 1 == prefixes.len();
            let probed = if is_leaf {
                Some(io::stat(os, prefix).await)
            } else {
                io::stat_if_admitted(os, prefix).await
            };
            match probed {
                Some(st) if st.exists => continue,
                Some(_) => missing = true,
                None => continue,
            }
        }
        io::create_dir(os, prefix).await?;
    }
    Ok(())
}

/// The last component of a path prefix.
fn component(prefix: &str) -> &str {
    prefix.rsplit('/').next().unwrap_or(prefix)
}

/// Each path prefix of `dir` that ends at a component, shortest first.
fn prefixes(dir: &str) -> Vec<String> {
    let mut path = if dir.starts_with('/') {
        String::from("/")
    } else {
        String::new()
    };
    dir.split('/')
        .filter(|part| !part.is_empty())
        .map(|part| {
            if !path.is_empty() && !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(part);
            path.clone()
        })
        .collect()
}
