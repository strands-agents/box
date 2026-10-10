// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: sort [OPTIONS] [FILE]...
Sort lines of text.

Options:
  -r    reverse the result of comparisons
  -n    compare according to string numerical value
  -k FIELD  sort by field number (1-based), e.g. -k2,2n
  -t SEP    use SEP as field separator
  -s    stabilize sort by disabling last-resort comparison
  -u    output only unique lines
  -f    fold lower case to upper case for comparison
  -b    ignore leading blanks in sort keys";

async fn read_lines(
    os: &Mediated,
    files: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut lines = Vec::new();
    let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if files.is_empty() {
        Box::new(io::stdin()?)
    } else {
        let fd = io::open(os, &files[0], OpenFlags::read()).await?;
        Box::new(io::take_reader(fd)?)
    };
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let l = if line.ends_with('\n') {
            &line[..line.len() - 1]
        } else {
            &line[..]
        };
        lines.push(l.to_string());
    }
    // Handle remaining files
    for path in files.iter().skip(1) {
        let fd = io::open(os, path, OpenFlags::read()).await?;
        let mut reader = BufReader::new(io::take_reader(fd)?);
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let l = if line.ends_with('\n') {
                &line[..line.len() - 1]
            } else {
                &line[..]
            };
            lines.push(l.to_string());
        }
    }
    Ok(lines)
}

struct KeySpec {
    start_field: usize,
    end_field: Option<usize>,
    numeric: bool,
    reverse: bool,
    fold_case: bool,
    ignore_blanks: bool,
}

fn parse_key_spec(s: &str) -> Result<KeySpec, Box<dyn std::error::Error + Send + Sync>> {
    let mut ks = KeySpec {
        start_field: 0,
        end_field: None,
        numeric: false,
        reverse: false,
        fold_case: false,
        ignore_blanks: false,
    };
    let parts: Vec<&str> = s.splitn(2, ',').collect();
    // Parse start field (strip trailing flags)
    let start = parts[0].trim_end_matches(|c: char| c.is_ascii_alphabetic());
    ks.start_field = start.parse::<usize>()?;
    // Parse end field and flags from second part
    if parts.len() > 1 {
        let end_str = parts[1].trim_end_matches(|c: char| c.is_ascii_alphabetic());
        if !end_str.is_empty() {
            ks.end_field = Some(end_str.parse::<usize>()?);
        }
        let flags = &parts[1][end_str.len()..];
        for c in flags.chars() {
            match c {
                'n' => ks.numeric = true,
                'r' => ks.reverse = true,
                'f' => ks.fold_case = true,
                'b' => ks.ignore_blanks = true,
                _ => {}
            }
        }
    }
    // Also check flags on start part
    let start_flags = &parts[0][start.len()..];
    for c in start_flags.chars() {
        match c {
            'n' => ks.numeric = true,
            'r' => ks.reverse = true,
            'f' => ks.fold_case = true,
            'b' => ks.ignore_blanks = true,
            _ => {}
        }
    }
    Ok(ks)
}

fn extract_key(line: &str, field: usize, end_field: Option<usize>, sep: Option<char>) -> &str {
    if field == 0 {
        return line;
    }
    let parts: Vec<&str> = if let Some(s) = sep {
        line.split(s).collect()
    } else {
        line.split_whitespace().collect()
    };
    let Some(start) = parts.get(field - 1) else {
        return "";
    };
    let start_offset = start.as_ptr() as usize - line.as_ptr() as usize;
    let end_offset = end_field
        .and_then(|end| end.checked_sub(1))
        .and_then(|end| parts.get(end))
        .map_or(line.len(), |end| {
            end.as_ptr() as usize - line.as_ptr() as usize + end.len()
        });
    line.get(start_offset..end_offset).unwrap_or("")
}

#[command("sort")]
async fn cmd_sort(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut reverse = false;
    let mut numeric = false;
    let mut unique = false;
    let mut fold_case = false;
    let mut ignore_blanks = false;
    let mut stable = false;
    let mut key_spec: Option<KeySpec> = None;
    let mut sep: Option<char> = None;
    let mut files = Vec::new();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('r') => reverse = true,
            Short('n') => numeric = true,
            Short('u') => unique = true,
            Short('f') => fold_case = true,
            Short('b') => ignore_blanks = true,
            Short('s') => stable = true,
            Short('k') => {
                let v = parser.value()?.string()?;
                key_spec = Some(parse_key_spec(&v)?);
            }
            Short('t') => {
                let v = parser.value()?.string()?;
                sep = v.chars().next();
            }
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) => files.push(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }

    let field = key_spec.as_ref().map_or(0, |k| k.start_field);
    // Key-level flags override global flags
    let eff_numeric = key_spec.as_ref().map_or(numeric, |k| k.numeric || numeric);
    let eff_reverse = key_spec.as_ref().map_or(reverse, |k| k.reverse || reverse);
    let eff_fold = key_spec
        .as_ref()
        .map_or(fold_case, |k| k.fold_case || fold_case);
    let eff_blanks = key_spec
        .as_ref()
        .map_or(ignore_blanks, |k| k.ignore_blanks || ignore_blanks);

    let end_field = if eff_numeric {
        Some(field)
    } else {
        key_spec.as_ref().and_then(|k| k.end_field)
    };
    let mut lines = read_lines(os, &files).await?;

    let cmp = |a: &String, b: &String| -> std::cmp::Ordering {
        let mut ka = extract_key(a, field, end_field, sep);
        let mut kb = extract_key(b, field, end_field, sep);
        if eff_blanks {
            ka = ka.trim_start();
            kb = kb.trim_start();
        }
        let ord = if eff_numeric {
            let na: f64 = ka.trim().parse().unwrap_or(0.0);
            let nb: f64 = kb.trim().parse().unwrap_or(0.0);
            na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal)
        } else if eff_fold {
            ka.to_lowercase().cmp(&kb.to_lowercase())
        } else {
            ka.cmp(kb)
        };
        if eff_reverse { ord.reverse() } else { ord }
    };

    if stable {
        lines.sort_by(cmp);
    } else {
        lines.sort_unstable_by(cmp);
    }

    if unique {
        lines.dedup_by(|a, b| {
            let ka = extract_key(a, field, end_field, sep);
            let kb = extract_key(b, field, end_field, sep);
            if eff_fold {
                ka.to_lowercase() == kb.to_lowercase()
            } else {
                ka == kb
            }
        });
    }

    let mut w = io::stdout()?;
    for line in &lines {
        wprintln!(w, "{}", line)?;
    }
    Ok(0)
}
