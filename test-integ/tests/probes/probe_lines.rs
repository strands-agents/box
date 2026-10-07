// The parser and refusal oracle for `fs_probe.rs`'s one-line answers, `include!`d by each case that
// runs the probe.
//
// A line is `<TAG> <subject> <details>`. The subject is a quoted path (`{:?}`) or `"from" -> "to"`,
// so it is matched as a whole token right after the tag and never by suffix: a read's `:: <content>`
// tail (the whole file on one line, `\n` `\r` `\\` escaped, quotes verbatim), a longer path that ends
// the same way, and another operation on the same path all fail to match. A `*_REFUSED` line is a
// failed syscall, not yet a denial: `refused_as` admits it only when
// its errno is one the case names for that operation on this platform, from the mechanism's source,
// so EIO, EMFILE, ENOMEM, ENOSPC and every other failure a syscall can answer cannot pass as
// containment. `cn_r_02.rs` carries the regressions for the parser and the oracle.

/// The errno values the cases name, POSIX-fixed and identical on Linux and macOS. Each case uses
/// the ones its mechanism answers, so some are unused in any one file.
#[allow(dead_code)]
const EPERM: i32 = 1;
#[allow(dead_code)]
const ENOENT: i32 = 2;
#[allow(dead_code)]
const EBUSY: i32 = 16;
#[allow(dead_code)]
const EXDEV: i32 = 18;
#[allow(dead_code)]
const EROFS: i32 = 30;

/// The probe's subject for one path: the path as the quoted literal the probe prints.
fn subject(path: &std::path::Path) -> String {
    format!("{:?}", path.to_string_lossy())
}

/// The probe's subject for a two-path operation (`rename`, `symlink`): `"from" -> "to"`.
#[allow(dead_code)]
fn pair(from: &std::path::Path, to: &std::path::Path) -> String {
    format!("{} -> {}", subject(from), subject(to))
}

/// The first line of `out` whose tag starts with `tag` (`READ_OK`, `READ_REFUSED`, or `READ_` for
/// either) and whose subject is exactly `subject`: the whole subject, so the `from` half of a
/// two-path subject (followed by ` -> `) is not a match for the single path it names.
fn probe_line<'a>(out: &'a str, tag: &str, subject: &str) -> Option<&'a str> {
    out.lines().find(|line| {
        let Some((head, rest)) = line.split_once(' ') else {
            return false;
        };
        if !head.starts_with(tag) || !rest.starts_with(subject) {
            return false;
        }
        let tail = &rest[subject.len()..];
        tail.is_empty() || (tail.starts_with(' ') && !tail.starts_with(" -> "))
    })
}

/// The errno a `*_REFUSED` line carries, if it carries one.
fn errno_of(line: &str) -> Option<i32> {
    line.split(" errno=")
        .nth(1)?
        .split(' ')
        .next()?
        .parse()
        .ok()
}

/// The `<operation>_REFUSED` line for `subject` whose errno is one of `denials`, the values the
/// case names for this operation on this platform. `Err` says what was found instead — a success,
/// no attempt, a refusal with no errno, or a refusal whose errno is outside the family — so a
/// caller panics with the value rather than reading any failed syscall as a refusal.
fn refused_as<'a>(
    out: &'a str,
    operation: &str,
    subject: &str,
    denials: &[i32],
) -> Result<&'a str, String> {
    if let Some(line) = probe_line(out, &format!("{operation}_REFUSED"), subject) {
        return match errno_of(line) {
            Some(errno) if denials.contains(&errno) => Ok(line),
            Some(errno) => Err(format!(
                "{operation} on {subject} failed with errno {errno}, which is not a denial this \
                 platform's mechanism answers for it (accepted {denials:?}); a failed syscall is not \
                 a refusal: {line}"
            )),
            None => Err(format!(
                "{operation} on {subject} was refused with no errno, so the refusal cannot be \
                 attributed: {line}"
            )),
        };
    }
    match probe_line(out, &format!("{operation}_OK"), subject) {
        Some(line) => Err(format!("{operation} on {subject} succeeded: {line}")),
        None => Err(format!(
            "the probe never attempted {operation} on {subject}"
        )),
    }
}
