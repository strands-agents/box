//! A declared secret source: one host program that prints one secret on stdout, run for
//! `scheme://NAME[#FIELD]`.
//!
//! | Step | Owner |
//! |---|---|
//! | Split the reference into the name and the field | [`split_reference`] |
//! | Compose the program's environment | [`compose`] |
//! | Spawn the program and bound its time and output | [`run`] |
//! | Read stdout as text or as one JSON string | [`CommandSource::decode`] |
//! | Take one field, or refuse a whole JSON object | [`select`] |

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::model::{SECRET_REFERENCE_TOKEN, SecretSourceOutput};
use crate::sources::{SecretSource, uri_reference};
use crate::{CredentialError, Locator, Result, Secret, SecretSourceCommand, redact_credential_ref};

/// How long one run of a program may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes a program may write to stdout.
const STDOUT_LIMIT: usize = 1024 * 1024;

/// The most bytes of a program's stderr the runner keeps: the last ones.
const STDERR_CAPTURE: usize = 8 * 1024;

/// The most bytes of a program's stderr a failure carries.
const STDERR_EXCERPT: usize = 512;

/// The `PATH` every program receives.
const FIXED_PATH: &str = "/usr/bin:/bin";

/// The directory every program starts in.
const WORKING_DIRECTORY: &str = "/";

/// How often the runner looks for the program's exit while its stdout is open.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How often the runner looks for the program's exit after its stdout closed.
const SETTLE_INTERVAL: Duration = Duration::from_millis(1);

/// The longest the runner waits for a program's stderr, and the least it waits for its stdout,
/// after the program exited.
const READER_GRACE: Duration = Duration::from_secs(1);

/// What replaces a hidden value in a program's stderr.
const REDACTED: &str = "[REDACTED]";

/// The operator's environment as the source reads it, so a test reads no host state.
type Environment = Box<dyn Fn() -> Vec<(OsString, OsString)> + Send + Sync>;

/// The time and stdout bounds of one run.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    timeout: Duration,
    stdout: usize,
}

/// One variable of a program's environment.
struct ChildVariable {
    name: OsString,
    value: OsString,
    /// Whether `pass-secret-env` named it, so its value is hidden in a failure.
    secret: bool,
}

/// Which bytes of a pipe a reader keeps when the program writes more than the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keep {
    /// The first bytes, and the reader stops at the limit.
    First,
    /// The last bytes, and the reader reads the pipe to its end.
    Last,
}

impl Drop for ChildVariable {
    fn drop(&mut self) {
        wipe(std::mem::take(&mut self.value));
    }
}

/// Wipe one value of the operator's environment that the source copied.
fn wipe(value: OsString) {
    drop(Zeroizing::new(value.into_encoded_bytes()));
}

/// What one pipe of a program held.
struct Captured {
    bytes: Zeroizing<Vec<u8>>,
    /// Whether the program wrote more than the limit.
    overflowed: bool,
    /// Whether the pipe failed before its end.
    failed: bool,
}

/// Why one run produced no secret.
struct Failure {
    reason: String,
    stderr: Option<Captured>,
}

impl Failure {
    /// A failure that carries no stderr.
    fn plain(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            stderr: None,
        }
    }
}

/// Reads secrets for one declared scheme by running its program, once for each secret.
pub(crate) struct CommandSource {
    declaration: SecretSourceCommand,
    environment: Environment,
    bounds: Bounds,
    /// Each fetched secret, before the field step, keyed by the reference name.
    held: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl CommandSource {
    /// The source for `declaration`, over the process environment.
    pub(crate) fn new(declaration: SecretSourceCommand) -> Self {
        Self {
            declaration,
            environment: Box::new(|| std::env::vars_os().collect()),
            bounds: Bounds {
                timeout: TIMEOUT,
                stdout: STDOUT_LIMIT,
            },
            held: Mutex::default(),
        }
    }

    /// What went wrong, with the scheme, the program, and the redacted reference.
    fn describe(&self, reference: &str, reason: &str) -> String {
        format!(
            "the secret source {:?} ({:?}) for {} {reason}",
            self.declaration.scheme(),
            self.declaration.program(),
            redact_credential_ref(reference)
        )
    }

    /// A hard error that names the scheme, the program, and the redacted reference.
    fn refusal(&self, reference: &str, reason: &str) -> CredentialError {
        CredentialError::Credential(self.describe(reference, reason))
    }

    /// Run the program for `name` and read the secret from its stdout.
    fn fetch_once(&self, name: &str, reference: &str) -> Result<Zeroizing<String>> {
        let arguments: Vec<String> = self
            .declaration
            .arguments()
            .iter()
            .map(|argument| argument.replace(SECRET_REFERENCE_TOKEN, name))
            .collect();
        let environment = compose(&self.declaration, (self.environment)());
        let stdout = run(
            self.declaration.program(),
            &arguments,
            &environment,
            self.bounds,
        )
        .map_err(|failure| {
            let described = self.describe(reference, &failure.reason);
            let said = failure
                .stderr
                .map(|said| excerpt(&said, &hidden_values(name, &environment)))
                .filter(|said| !said.is_empty());
            CredentialError::Credential(match said {
                Some(said) => format!("{described}: {said}"),
                None => described,
            })
        })?;
        self.decode(&stdout, reference)
    }

    /// The secret that `stdout` holds, read as the declaration's `output` says.
    fn decode(&self, stdout: &[u8], reference: &str) -> Result<Zeroizing<String>> {
        let Ok(text) = std::str::from_utf8(stdout) else {
            return Err(self.refusal(reference, "wrote output that is not UTF-8"));
        };
        let text = without_one_newline(text);
        match self.declaration.output_form() {
            SecretSourceOutput::Text => Ok(Zeroizing::new(text.to_owned())),
            SecretSourceOutput::Json => {
                json_string(text).map_err(|reason| self.refusal(reference, &reason))
            }
        }
    }
}

impl std::fmt::Debug for CommandSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSource")
            .field("scheme", &self.declaration.scheme())
            .field("program", &self.declaration.program())
            .finish_non_exhaustive()
    }
}

impl SecretSource for CommandSource {
    fn scheme(&self) -> &str {
        self.declaration.scheme()
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        let scheme = self.declaration.scheme();
        let reference = uri_reference(loc, scheme)?;
        let (name, field) = split_reference(scheme, reference).map_err(|reason| {
            CredentialError::Credential(format!(
                "the reference {} is malformed: {reason}",
                redact_credential_ref(reference)
            ))
        })?;

        // The lock is held for the run, so two callers that ask for one secret run the program once.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if !held.contains_key(name) {
            let fetched = self.fetch_once(name, reference)?;
            held.insert(name.to_string(), fetched);
        }
        let value = select(&held[name], field).map_err(|reason| self.refusal(reference, reason))?;
        Secret::new(value, reference)
    }
}

/// The name and the field of `scheme://NAME[#FIELD]`, refused before any program starts.
fn split_reference<'a>(
    scheme: &str,
    reference: &'a str,
) -> std::result::Result<(&'a str, Option<&'a str>), &'static str> {
    let rest = reference
        .strip_prefix(scheme)
        .and_then(|rest| rest.strip_prefix("://"))
        .ok_or("it does not start with the scheme of its source")?;
    if rest.starts_with('-') {
        return Err("the text after `://` starts with `-`, which a program can read as a flag");
    }
    if rest.chars().any(char::is_control) {
        return Err("it holds a control character");
    }
    let (name, field) = match rest.split_once('#') {
        Some((name, field)) => (name, Some(field)),
        None => (rest, None),
    };
    if name.is_empty() {
        return Err("it names no secret after `://`");
    }
    match field {
        Some("") => Err("it names no field after `#`"),
        Some(field) if field.contains('#') => Err("it holds more than one `#`"),
        _ => Ok((name, field)),
    }
}

/// The environment of a program: `HOME`, the fixed `PATH`, and each passed variable that is set.
fn compose(
    declaration: &SecretSourceCommand,
    operator: Vec<(OsString, OsString)>,
) -> Vec<ChildVariable> {
    let mut composed = vec![ChildVariable {
        name: "PATH".into(),
        value: FIXED_PATH.into(),
        secret: false,
    }];
    for (name, value) in operator {
        // No pass list names `HOME` or `PATH` away from the values the source gives them. A prefix
        // entry of `pass-secret-env` that matches `HOME` still hides its value in a failure.
        let passed = match name.to_str() {
            Some("HOME") => Some(declaration.passes_as_secret("HOME")),
            Some("PATH") | None => None,
            Some(text) if declaration.passes(text) => Some(declaration.passes_as_secret(text)),
            Some(_) => None,
        };
        // A variable that does not pass can be a credential of another source.
        let Some(secret) = passed else {
            wipe(value);
            continue;
        };
        composed.push(ChildVariable {
            name,
            value,
            secret,
        });
    }
    composed
}

/// Read `pipe` on its own thread into one buffer that never grows, and send what it held.
fn reader(
    pipe: Option<impl Read + Send + 'static>,
    limit: usize,
    keep: Keep,
) -> Receiver<Captured> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        // One byte past the limit shows that the first bytes are not all. As much again as the
        // limit holds the last bytes while the reader moves on.
        let room = match keep {
            Keep::First => limit + 1,
            Keep::Last => limit * 2,
        };
        let mut bytes = Zeroizing::new(vec![0u8; room]);
        let mut length = 0;
        let mut dropped = false;
        let mut failed = pipe.is_none();
        if let Some(mut pipe) = pipe {
            loop {
                if length == room {
                    if keep == Keep::First {
                        break;
                    }
                    bytes.copy_within(limit.., 0);
                    length = limit;
                    dropped = true;
                }
                match pipe.read(&mut bytes[length..]) {
                    Ok(0) => break,
                    Ok(read) => length += read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
        }
        // The first bytes of a stopped read, or the last bytes of a whole one.
        let excess = length.saturating_sub(limit);
        if keep == Keep::Last {
            bytes.copy_within(excess..length, 0);
        }
        bytes.truncate(length - excess);
        let overflowed = dropped || excess > 0;
        // The receiver is gone when the runner already failed; the buffer is wiped as it drops.
        let _ = sender.send(Captured {
            bytes,
            overflowed,
            failed,
        });
    });
    receiver
}

/// Stop a program that the runner gives up on.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Run `program` with no shell, no stdin, and only `environment`, and return its stdout.
fn run(
    program: &Path,
    arguments: &[String],
    environment: &[ChildVariable],
    bounds: Bounds,
) -> std::result::Result<Zeroizing<Vec<u8>>, Failure> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .envs(
            environment
                .iter()
                .map(|variable| (&variable.name, &variable.value)),
        )
        .current_dir(WORKING_DIRECTORY)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Failure::plain(format!("did not start ({})", error.kind())))?;
    let stdout = reader(child.stdout.take(), bounds.stdout, Keep::First);
    let stderr = reader(child.stderr.take(), STDERR_CAPTURE, Keep::Last);
    let too_much = || Failure::plain(format!("wrote more than {} bytes to stdout", bounds.stdout));

    let deadline = Instant::now() + bounds.timeout;
    let mut output = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                stop(&mut child);
                return Err(Failure::plain(format!(
                    "did not finish within {:?}",
                    bounds.timeout
                )));
            }
            Ok(None) => {}
            Err(error) => {
                stop(&mut child);
                return Err(Failure::plain(format!(
                    "could not be waited for ({})",
                    error.kind()
                )));
            }
        }
        if output.is_some() {
            std::thread::sleep(SETTLE_INTERVAL);
            continue;
        }
        match stdout.recv_timeout(POLL_INTERVAL) {
            Ok(captured) if captured.overflowed => {
                stop(&mut child);
                return Err(too_much());
            }
            Ok(captured) => output = Some(captured),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                stop(&mut child);
                return Err(Failure::plain("lost its stdout reader"));
            }
        }
    };

    // A descendant that holds stdout open keeps the runner until the deadline, or for
    // `READER_GRACE` when less time is left.
    let patience = deadline
        .saturating_duration_since(Instant::now())
        .max(READER_GRACE);
    let output = match output {
        Some(output) => output,
        None => stdout
            .recv_timeout(patience)
            .map_err(|_| Failure::plain("left its stdout open after it exited"))?,
    };
    if output.overflowed {
        return Err(too_much());
    }
    if output.failed {
        return Err(Failure::plain("wrote stdout that could not be read"));
    }
    if !status.success() {
        // Stderr only explains a failure, so a descendant that holds it open costs the text alone.
        let said = stderr.recv_timeout(READER_GRACE).ok();
        return Err(Failure {
            reason: format!("exited unsuccessfully ({status})"),
            stderr: said,
        });
    }
    Ok(output.bytes)
}

/// The values a failure must not show: the reference name, and each passed credential.
fn hidden_values<'a>(name: &'a str, environment: &'a [ChildVariable]) -> Vec<&'a [u8]> {
    environment
        .iter()
        .filter(|variable| variable.secret)
        .map(|variable| variable.value.as_encoded_bytes())
        .chain([name.as_bytes()])
        .filter(|value| !value.is_empty())
        .collect()
}

/// The end of a program's stderr as one line: no hidden value, no control character, and at most
/// [`STDERR_EXCERPT`] bytes.
fn excerpt(said: &Captured, hidden: &[impl AsRef<[u8]>]) -> String {
    let bytes = &said.bytes[..];
    // Each byte of a hidden value is marked where it lies, so a value that holds or meets another
    // is hidden whole. No copy of the capture then holds a value outside the wiped buffer.
    let mut hide = vec![false; bytes.len()];
    for value in hidden.iter().map(AsRef::<[u8]>::as_ref) {
        for start in 0..bytes.len() {
            if bytes[start..].starts_with(value) {
                hide[start..start + value.len()].fill(true);
            }
        }
        // A capture that lost its start can begin with the end of a value.
        if said.overflowed {
            let ends = (1..value.len())
                .rev()
                .find(|length| bytes.starts_with(&value[value.len() - length..]));
            if let Some(length) = ends {
                hide[..length].fill(true);
            }
        }
    }
    let mut shown = Vec::with_capacity(bytes.len());
    for (index, byte) in bytes.iter().enumerate() {
        if !hide[index] {
            shown.push(*byte);
        } else if index == 0 || !hide[index - 1] {
            shown.extend_from_slice(REDACTED.as_bytes());
        }
    }
    let line = String::from_utf8_lossy(&shown)
        .split(|character: char| character.is_control() || character.is_whitespace())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut start = line.len().saturating_sub(STDERR_EXCERPT);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    line[start..].to_string()
}

/// `text` without one trailing `\n` or `\r\n`.
fn without_one_newline(text: &str) -> &str {
    match text.strip_suffix('\n') {
        Some(line) => line.strip_suffix('\r').unwrap_or(line),
        None => text,
    }
}

/// The string that `text` holds as one JSON string, with every other parsed copy wiped.
fn json_string(text: &str) -> std::result::Result<Zeroizing<String>, String> {
    let wrote = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::String(secret)) => return Ok(Zeroizing::new(secret)),
        Ok(mut other) => {
            let kind = match &other {
                serde_json::Value::Null => "the JSON value `null`",
                serde_json::Value::Bool(_) => "a JSON boolean",
                serde_json::Value::Number(_) => "a JSON number",
                serde_json::Value::Array(_) => "a JSON array",
                _ => "a JSON object",
            };
            wipe_value(&mut other);
            kind
        }
        Err(_) => "output that is not JSON",
    };
    Err(format!(
        "wrote {wrote}, and `output = \"json\"` reads one JSON string"
    ))
}

/// The value a reference names in `secret`: one string field, or the whole of a secret that is not
/// a JSON object.
fn select(
    secret: &str,
    field: Option<&str>,
) -> std::result::Result<Zeroizing<String>, &'static str> {
    match field {
        Some(field) => json_field(secret, field),
        None if is_json_object(secret) => {
            Err("returned a JSON object, so the reference must name one field with `#FIELD`")
        }
        None => Ok(Zeroizing::new(secret.to_owned())),
    }
}

/// One string field of a JSON object, with every other parsed copy wiped.
fn json_field(secret: &str, field: &str) -> std::result::Result<Zeroizing<String>, &'static str> {
    let mut parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(secret)
        .map_err(|_| "returned a secret that is not a JSON object, so it has no `#FIELD`")?;
    let found = parsed.remove(field);
    wipe_object(&mut parsed);
    match found {
        Some(serde_json::Value::String(found)) => Ok(Zeroizing::new(found)),
        Some(mut other) => {
            wipe_value(&mut other);
            Err("returned a JSON object whose `#FIELD` is not a string")
        }
        None => Err("returned a JSON object that has no `#FIELD` of that name"),
    }
}

/// Whether `secret` is a JSON object, with the parsed copy wiped.
fn is_json_object(secret: &str) -> bool {
    // An object starts with `{`, so any other secret is never copied by a parse.
    if !secret.trim_start().starts_with('{') {
        return false;
    }
    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(secret) {
        Ok(mut object) => {
            wipe_object(&mut object);
            true
        }
        Err(_) => false,
    }
}

/// Wipe every string a parsed JSON value holds.
fn wipe_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_value),
        serde_json::Value::Object(object) => wipe_object(object),
        _ => {}
    }
}

/// Wipe every string value a parsed JSON object holds.
fn wipe_object(object: &mut serde_json::Map<String, serde_json::Value>) {
    object.values_mut().for_each(wipe_value);
}

#[cfg(test)]
mod tests;
