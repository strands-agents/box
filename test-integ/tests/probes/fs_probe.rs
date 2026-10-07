//! fsprobe — one native filesystem syscall per invocation, from the agent's own boundary.
//!
//! A case compiles this source into the fixture's exec tree with `BoxFixture::compile_probe` and
//! runs it from the native contained bash under the agent's own `exec` entry, so every call here is
//! the agent's own syscall: nothing passes the broker.
//!
//! Every answer is one line with one grammar, `<TAG> <subject> <details>`: the tag is `<OP>_OK` or
//! `<OP>_REFUSED`, the subject is the operation's path, or `"from" -> "to"` for the two-path
//! operations, each path as a quoted Rust string literal (`{:?}`), and the details follow — `errno=<n>
//! (<message>)` for a refusal, `len=<n> :: <content>` for a read, `dev= ino= size=` for a stat,
//! nothing for the others. A read's `<content>` is the WHOLE file on one physical line: a backslash
//! is written `\\`, a newline `\n`, a carriage return `\r`, and every other character, quotes
//! included, verbatim (lossy UTF-8). So a case's `assert_absent` over the output sees every line of a
//! leaked file, and a needle with no backslash or line break matches exactly as authored.
//! `probe_lines.rs` parses that grammar; a case never matches a path by suffix.
//!
//! Operations: `rename FROM TO`, `read PATH`, `append PATH TEXT`, `create PATH TEXT`,
//! `symlink TARGET LINK`, `stat PATH`, `list PATH`. A `list` answers `names=` and the sorted entry
//! names joined by `,`.
//! Not a case: `build.rs` scans only the category folders, so this file is never a test module.
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;

/// The read content as one physical line: `\\` for a backslash, `\n` for a newline, `\r` for a
/// carriage return, everything else verbatim.
fn one_line(bytes: &[u8]) -> String {
    let mut line = String::with_capacity(bytes.len());
    for character in String::from_utf8_lossy(bytes).chars() {
        match character {
            '\\' => line.push_str("\\\\"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            other => line.push(other),
        }
    }
    line
}

fn refused(operation: &str, subject: &str, error: &std::io::Error) {
    println!(
        "{operation}_REFUSED {subject} errno={} ({error})",
        error.raw_os_error().unwrap_or(-1)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let operation = args.get(1).map(String::as_str).unwrap_or("");
    let rest: &[String] = if args.len() > 2 { &args[2..] } else { &[] };
    match (operation, rest) {
        ("rename", [from, to]) => {
            let subject = format!("{from:?} -> {to:?}");
            match std::fs::rename(from, to) {
                Ok(()) => println!("RENAME_OK {subject}"),
                Err(error) => refused("RENAME", &subject, &error),
            }
        }
        ("read", [path]) => match std::fs::read(path) {
            Ok(bytes) => println!(
                "READ_OK {path:?} len={} :: {}",
                bytes.len(),
                one_line(&bytes)
            ),
            Err(error) => refused("READ", &format!("{path:?}"), &error),
        },
        ("append", [path, text]) => {
            let appended = std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .and_then(|mut file| file.write_all(format!("{text}\n").as_bytes()));
            match appended {
                Ok(()) => println!("APPEND_OK {path:?}"),
                Err(error) => refused("APPEND", &format!("{path:?}"), &error),
            }
        }
        ("create", [path, text]) => {
            let created = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| file.write_all(format!("{text}\n").as_bytes()));
            match created {
                Ok(()) => println!("CREATE_OK {path:?}"),
                Err(error) => refused("CREATE", &format!("{path:?}"), &error),
            }
        }
        ("list", [path]) => match std::fs::read_dir(path).and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
                .collect::<Result<Vec<_>, _>>()
        }) {
            Ok(mut names) => {
                names.sort();
                println!("LIST_OK {path:?} names={}", names.join(","));
            }
            Err(error) => refused("LIST", &format!("{path:?}"), &error),
        },
        ("symlink", [target, link]) => {
            let subject = format!("{link:?} -> {target:?}");
            match std::os::unix::fs::symlink(target, link) {
                Ok(()) => println!("SYMLINK_OK {subject}"),
                Err(error) => refused("SYMLINK", &subject, &error),
            }
        }
        ("stat", [path]) => match std::fs::metadata(path) {
            Ok(meta) => println!(
                "STAT_OK {path:?} dev={} ino={} size={}",
                meta.dev(),
                meta.ino(),
                meta.len()
            ),
            Err(error) => refused("STAT", &format!("{path:?}"), &error),
        },
        _ => {
            eprintln!(
                "usage: fsprobe rename FROM TO | read PATH | append PATH TEXT | create PATH TEXT | symlink TARGET LINK | stat PATH | list PATH"
            );
            std::process::exit(2);
        }
    }
}
