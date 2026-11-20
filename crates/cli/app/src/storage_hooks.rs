//! The hooks that a run imports from a host file, and the per-run view in storage.
//!
//! | Step | What it does |
//! | --- | --- |
//! | [`import`] | Read the host file once, and keep each hook that runs one shell script. |
//! | [`apply`] | Replace the hooks of the copy in storage with the imported hooks, or remove them. |

use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};

use crate::error::Error;
use crate::host::{canonical, tilde};
pub(crate) use crate::lang::HookImport;
use crate::lang::{EVERY, HookValue};
use crate::storage_edit::shown;
use crate::storage_files::{Copy, Refusals, edit_in_storage};

/// The most bytes a host file or a copy may hold.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// The most bytes an imported script may hold.
const MAX_SCRIPT_BYTES: u64 = 64 * 1024;

/// The most hooks a run imports.
const MAX_HOOKS: usize = 64;

/// The most refused hooks a run lists one by one.
const MAX_LISTED_REFUSALS: usize = 20;

/// The most hooks a run inspects.
const MAX_INSPECTED: usize = 1024;

/// The shells that run an imported script.
const SCRIPT_SHELLS: &[&str] = &["sh", "bash", "zsh"];

/// What one row imports from the host for this run.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Imported {
    /// The value that the copy gets at the first key of the row's `key`, or `None` for no hooks.
    pub(crate) hooks: Option<Value>,
    /// Each script that an imported hook runs, canonical.
    pub(crate) scripts: Vec<PathBuf>,
    /// Each hook that is not imported, as `(hook, reason)`.
    pub(crate) refused: Vec<(String, String)>,
    /// Each line about the import as a whole.
    pub(crate) notes: Vec<String>,
    /// Whether the host file sets the row's `disable-key`, which the copy then sets too.
    pub(crate) disable_all: bool,
    /// Whether the host file could not be read, so the copy keeps its `disable-key` value.
    pub(crate) host_unread: bool,
}

/// Read `row`'s host file and keep each hook that runs one shell script.
pub(crate) fn import(row: &HookImport, refusals: &Refusals, home: &Path) -> Imported {
    let mut imported = Imported::default();
    let shown = tilde(home, &row.source);
    let settings = match row
        .refused
        .clone()
        .map_or(Ok(()), Err)
        .and_then(|()| refusals.check(&row.source))
        .and_then(|()| passes_no_writable_place(&row.source, "hooks file", refusals, home))
        .and_then(|()| read_json(&row.source, refusals))
    {
        Ok(Some(settings)) => settings,
        Ok(None) => return imported,
        Err(reason) => {
            imported.host_unread = true;
            imported
                .notes
                .push(format!("did not read {shown} for hooks: {reason}"));
            return imported;
        }
    };
    // The host's off switch only takes hooks away, so it reaches the copy with import off too.
    imported.disable_all = row
        .disable_key
        .as_ref()
        .is_some_and(|key| settings.get(key) == Some(&Value::Bool(true)));
    if !row.import {
        return imported;
    }
    if imported.disable_all {
        imported.notes.push(format!(
            "imported no hooks: {shown} sets {}",
            row.disable_key.as_deref().unwrap_or_default()
        ));
        return imported;
    }
    let Some((first, steps)) = row.key.split_first() else {
        return imported;
    };
    let Some(hooks) = settings.get(first) else {
        return imported;
    };
    if !matches!(hooks, Value::Object(_) | Value::Array(_)) {
        imported.notes.push(format!(
            "imported no hooks: `{}` in {shown} is not an object or a list",
            short(first, 40)
        ));
        return imported;
    }
    let mut walk = Walk {
        row,
        home,
        refusals,
        scripts: Vec::new(),
        count: 0,
        inspected: 0,
        refused: Bounded::default(),
    };
    imported.hooks = walk.keep(hooks, steps, &Label::default());
    imported.scripts = walk.scripts;
    imported.refused = walk.refused.items;
    if walk.refused.omitted > 0 {
        imported.notes.push(format!(
            "did not import {} more hooks",
            walk.refused.omitted
        ));
    }
    imported
}

/// One pass over the host's hooks: what it keeps, and what it refuses.
struct Walk<'a> {
    row: &'a HookImport,
    home: &'a Path,
    refusals: &'a Refusals,
    scripts: Vec<PathBuf>,
    count: usize,
    inspected: usize,
    refused: Bounded,
}

impl Walk<'_> {
    /// What the copy keeps of `value`, which `steps` lead from to each hook, or `None` when it
    /// holds no imported hook.
    fn keep(&mut self, value: &Value, steps: &[String], label: &Label) -> Option<Value> {
        let Some((step, rest)) = steps.split_first() else {
            return self.hook(value, label);
        };
        if step == EVERY {
            return match value {
                Value::Object(entries) => {
                    let kept: Map<String, Value> = entries
                        .iter()
                        .filter_map(|(key, entry)| {
                            let kept = self.keep(entry, rest, &label.named(key))?;
                            Some((key.clone(), kept))
                        })
                        .collect();
                    (!kept.is_empty()).then_some(Value::Object(kept))
                }
                Value::Array(items) => {
                    let kept: Vec<Value> = items
                        .iter()
                        .enumerate()
                        .filter_map(|(index, item)| {
                            let label = match rest {
                                [] => label.numbered(index),
                                _ => label.clone(),
                            };
                            self.keep(item, rest, &label)
                        })
                        .collect();
                    (!kept.is_empty()).then_some(Value::Array(kept))
                }
                _ => {
                    self.refuse(label, "it does not hold a list or an object of hooks");
                    None
                }
            };
        }
        let Some(above) = value.as_object() else {
            self.refuse(label, "it is not an object");
            return None;
        };
        let label = label.beside(above, &self.row.keep_above);
        if let Some(field) = above
            .keys()
            .find(|field| *field != step && !self.row.keep_above.contains(field))
        {
            let reason = format!(
                "the object above the hook holds `{}`, which box does not import",
                short(field, 40)
            );
            self.refuse(&label, &reason);
            return None;
        }
        if let Some(field) = self
            .row
            .keep_above
            .iter()
            .find(|field| above.get(*field).is_some_and(|kept| !kept.is_string()))
        {
            self.refuse(&label, &format!("`{field}` is not a string"));
            return None;
        }
        let Some(below) = above.get(step) else {
            self.refuse(
                &label,
                &format!("the object above the hook has no `{step}`"),
            );
            return None;
        };
        let below = self.keep(below, rest, &label)?;
        let mut kept: Map<String, Value> = above
            .iter()
            .filter(|(field, _)| *field != step)
            .map(|(field, kept)| (field.clone(), kept.clone()))
            .collect();
        kept.insert(step.clone(), below);
        Some(Value::Object(kept))
    }

    /// The imported form of the hook `value`, or `None` with its refusal listed.
    fn hook(&mut self, value: &Value, label: &Label) -> Option<Value> {
        self.inspected += 1;
        if self.inspected > MAX_INSPECTED {
            self.refused.omitted += 1;
            return None;
        }
        if self.count == MAX_HOOKS {
            self.refuse(label, &format!("box imports at most {MAX_HOOKS} hooks"));
            return None;
        }
        match convert(self.row, value, self.home, self.refusals) {
            Ok((hook, script)) => {
                self.count += 1;
                if !self.scripts.contains(&script) {
                    self.scripts.push(script);
                }
                Some(hook)
            }
            Err(reason) => {
                self.refuse(label, &reason);
                None
            }
        }
    }

    fn refuse(&mut self, label: &Label, reason: &str) {
        self.refused.push((label.0.clone(), reason.to_string()));
    }
}

/// How a report names a hook: each key that leads to it, each string beside it in parentheses,
/// and its place in its list. The command is left out, because its text can hold a secret.
#[derive(Clone, Default)]
struct Label(String);

impl Label {
    fn with(&self, part: &str) -> Self {
        match self.0.is_empty() {
            true => Self(part.to_string()),
            false => Self(format!("{} {part}", self.0)),
        }
    }

    /// The label below the key `key`.
    fn named(&self, key: &str) -> Self {
        self.with(&short(key, 40))
    }

    /// The label of the item at `index` of a list.
    fn numbered(&self, index: usize) -> Self {
        self.with(&format!("#{}", index + 1))
    }

    /// The label below `above`, with each string that `fields` name in it.
    fn beside(&self, above: &Map<String, Value>, fields: &[String]) -> Self {
        fields
            .iter()
            .filter_map(|field| above.get(field).and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .fold(self.clone(), |label, text| {
                label.with(&format!("({})", short(text, 40)))
            })
    }
}

/// The refusals a run lists, at most [`MAX_LISTED_REFUSALS`], and how many it leaves out.
#[derive(Default)]
struct Bounded {
    items: Vec<(String, String)>,
    omitted: usize,
}

impl Bounded {
    fn push(&mut self, (label, reason): (String, String)) {
        if self.items.len() < MAX_LISTED_REFUSALS {
            self.items.push((label, short(&reason, 300)));
        } else {
            self.omitted += 1;
        }
    }
}

/// `text` cut to at most `limit` characters.
fn short(text: &str, limit: usize) -> String {
    let shown = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_control() {
                    c.escape_default().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect()
    };
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", shown(&text[..end])),
        None => shown(text),
    }
}

/// The value at `path` below `object`.
fn at<'a>(object: &'a Map<String, Value>, path: &[String]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    rest.iter()
        .try_fold(object.get(first)?, |value, key| value.get(key))
}

/// Put `value` at `path` below `object`, with each object on the way.
fn put(object: &mut Map<String, Value>, path: &[String], value: Value) {
    match path {
        [] => {}
        [key] => {
            object.insert(key.clone(), value);
        }
        [key, rest @ ..] => {
            let below = object
                .entry(key.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if !below.is_object() {
                *below = Value::Object(Map::new());
            }
            if let Some(below) = below.as_object_mut() {
                put(below, rest, value);
            }
        }
    }
}

/// The first field of `hook`, below `above`, that no path in `named` names.
fn unnamed(
    hook: &Map<String, Value>,
    above: &[String],
    named: &[&[String]],
) -> Option<Vec<String>> {
    hook.iter().find_map(|(field, value)| {
        let here: Vec<String> = above.iter().cloned().chain([field.clone()]).collect();
        if named.contains(&here.as_slice()) {
            return None;
        }
        match value.as_object() {
            Some(below) if named.iter().any(|path| path.starts_with(&here)) => {
                unnamed(below, &here, named)
            }
            _ => Some(here),
        }
    })
}

/// A `[[storage.hooks.set]]` value with `script` where the row names the script.
fn filled(value: &HookValue, script: &str) -> Value {
    match value {
        HookValue::Text(parts) => Value::String(parts.join(script)),
        HookValue::Fixed(toml::Value::Integer(number)) => Value::from(*number),
        HookValue::Fixed(toml::Value::Float(number)) => Value::from(*number),
        HookValue::Fixed(toml::Value::Boolean(flag)) => Value::Bool(*flag),
        HookValue::Fixed(_) => Value::Null,
        HookValue::List(items) => {
            Value::Array(items.iter().map(|item| filled(item, script)).collect())
        }
    }
}

/// One host hook as `row` writes it, with the canonical script it runs.
fn convert(
    row: &HookImport,
    hook: &Value,
    home: &Path,
    refusals: &Refusals,
) -> Result<(Value, PathBuf), String> {
    let hook = hook
        .as_object()
        .ok_or_else(|| "the hook is not an object".to_string())?;
    if let Some((key, wanted)) = &row.only {
        match at(hook, key).and_then(Value::as_str) {
            Some(found) if found == wanted => {}
            Some(other) => {
                return Err(format!(
                    "a `{}` hook is not imported; box imports only a `{wanted}` hook that runs \
                     one script",
                    short(other, 40)
                ));
            }
            None => return Err(format!("the hook has no `{}`", shown(key))),
        }
    }
    let named: Vec<&[String]> = [row.command.as_slice()]
        .into_iter()
        .chain(row.args.as_deref())
        .chain(row.only.as_ref().map(|(key, _)| key.as_slice()))
        .chain(row.keep.iter().map(Vec::as_slice))
        .chain(row.drop.iter().map(|entry| entry.key.as_slice()))
        .collect();
    if let Some(field) = unnamed(hook, &[], &named) {
        return Err(format!(
            "the hook holds `{}`, which box does not import",
            short(&shown(&field), 80)
        ));
    }
    for entry in &row.drop {
        let (Some(wanted), Some(found)) = (&entry.equals, at(hook, &entry.key)) else {
            continue;
        };
        if found.as_str() != Some(wanted) {
            let found = match found.as_str() {
                Some(text) => format!("`{}`", short(text, 40)),
                None => "a value that is not a string".to_string(),
            };
            return Err(format!(
                "the hook's `{}` is {found}; box imports the hook only when it is `{wanted}`",
                shown(&entry.key)
            ));
        }
    }
    let command = at(hook, &row.command)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the hook has no `{}` string", shown(&row.command)))?;
    let written = match row.args.as_ref().and_then(|args| at(hook, args)) {
        None => script_of_shell_form(command, home)?,
        Some(args) => script_of_exec_form(command, args, home)?,
    };
    let script = script_path(&written, home, refusals)?;
    let argument = script
        .to_str()
        .ok_or_else(|| "the script's path is not UTF-8".to_string())?;
    let mut kept = Map::new();
    for field in &row.keep {
        if let Some(value) = at(hook, field) {
            put(&mut kept, field, value.clone());
        }
    }
    for setting in &row.set {
        put(&mut kept, &setting.key, filled(&setting.value, argument));
    }
    Ok((Value::Object(kept), script))
}

/// The script that a shell-form command runs: `SCRIPT`, or `sh SCRIPT`, `bash SCRIPT`, or `zsh
/// SCRIPT`, and nothing else.
fn script_of_shell_form(command: &str, home: &Path) -> Result<String, String> {
    let command = command.trim();
    let words = shell_words(command);
    match words.as_deref() {
        Some([script]) => Ok(script.clone()),
        Some([shell, script]) if is_script_shell(shell) => Ok(script.clone()),
        _ if names_a_path_with_a_space(command, home) => Err(SPACE_IN_PATH.to_string()),
        Some([program, _, ..]) if is_other_program(program, home) => Err(OTHER_PROGRAM.to_string()),
        Some([_, _, ..]) => Err(ARGUMENTS.to_string()),
        _ => Err(
            "an inline command is not imported; box imports only a hook that runs one script, \
             such as `~/hooks/format.sh`"
                .to_string(),
        ),
    }
}

/// Why a command that passes arguments is not imported.
const ARGUMENTS: &str =
    "the hook passes arguments to its program; box imports only a hook that runs one script";

/// Whether `program` is not sh, bash, or zsh and not a shell script: a bare name, or a file whose
/// start is not text or whose `#!` line names another program. A path that [`admit`] does not
/// open, such as an absent file or one that is not a regular file, is not one.
fn is_other_program(program: &str, home: &Path) -> bool {
    if is_script_shell(program) {
        return false;
    }
    let path = match program.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if program.contains('/') => PathBuf::from(program),
        None => return true,
    };
    let mut start = Vec::new();
    let read = admit(&path)
        .ok()
        .flatten()
        .is_some_and(|(file, ..)| file.take(256).read_to_end(&mut start).is_ok());
    let first = start
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    read && match first.strip_prefix(b"#!") {
        Some(line) => {
            let line = String::from_utf8_lossy(line);
            !line.split_whitespace().any(|word| {
                Path::new(word)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| SCRIPT_SHELLS.contains(&name))
            })
        }
        None => {
            start.contains(&0)
                || matches!(std::str::from_utf8(&start), Err(error) if error.error_len().is_some())
        }
    }
}

/// Why a command whose script path holds a space is not imported.
const SPACE_IN_PATH: &str = "the script's path holds a space, which the command that box writes \
     cannot carry; box imports only a script whose path holds letters, digits, and `/._-+@,`";

/// Why a command that starts a program other than a shell is not imported.
const OTHER_PROGRAM: &str = "the command starts a program other than sh, bash, or zsh; box \
     imports only a hook that runs one shell script";

/// Whether `command`, without its quotes and its leading shell, is the path of a file on the host
/// that holds a space and no other character outside a plain path.
fn names_a_path_with_a_space(command: &str, home: &Path) -> bool {
    let unquoted = command.replace('"', "");
    let path = match unquoted.split_once(' ') {
        Some((shell, rest)) if is_script_shell(shell) => rest.trim_start(),
        _ => unquoted.as_str(),
    };
    let path = path
        .strip_prefix("${HOME}/")
        .or_else(|| path.strip_prefix("$HOME/"))
        .or_else(|| path.strip_prefix("~/"))
        .map(|rest| home.join(rest))
        .or_else(|| path.starts_with('/').then(|| PathBuf::from(path)));
    path.is_some_and(|path| {
        path.to_str().is_some_and(|text| {
            text.contains(' ') && text.chars().all(|c| c == ' ' || is_plain_path_character(c))
        }) && std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_dir())
    })
}

/// The script that an exec-form command runs: `sh`, `bash`, or `zsh` with one argument, or a
/// script with none.
fn script_of_exec_form(command: &str, args: &Value, home: &Path) -> Result<String, String> {
    let args = args
        .as_array()
        .ok_or_else(|| "the hook's `args` is not a list".to_string())?;
    let args: Vec<&str> = args
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()
        .ok_or_else(|| "the hook's `args` holds a value that is not a string".to_string())?;
    match args.as_slice() {
        [] if shell_words(command).is_some_and(|words| words.len() == 1) => Ok(command.to_string()),
        [] => Err("the hook's command is not one script path".to_string()),
        [script] if is_script_shell(command) => Ok((*script).to_string()),
        _ if is_other_program(command, home) => Err(OTHER_PROGRAM.to_string()),
        _ => Err(ARGUMENTS.to_string()),
    }
}

/// Whether `program` names `sh`, `bash`, or `zsh`, bare or in `/bin`.
fn is_script_shell(program: &str) -> bool {
    let name = program
        .strip_prefix("/bin/")
        .or_else(|| program.strip_prefix("/usr/bin/"))
        .unwrap_or(program);
    SCRIPT_SHELLS.contains(&name)
}

/// Whether `c` may appear in a script's path: a character that a shell reads as itself, with no
/// quote and no placeholder character.
fn is_plain_path_character(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '@' | ',')
}

/// Split `text` into words where each word is plain or wholly in double quotes, with `$HOME` or
/// `${HOME}` only at a word's start. Anything a shell would expand or interpret gives `None`.
fn shell_words(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    for raw in text.split(' ').filter(|word| !word.is_empty()) {
        let word = match raw
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            Some(inner) => inner,
            None if raw.contains('"') => return None,
            None => raw,
        };
        let word = if let Some(rest) = word.strip_prefix("${HOME}/") {
            format!("~/{rest}")
        } else if let Some(rest) = word.strip_prefix("$HOME/") {
            format!("~/{rest}")
        } else {
            word.to_string()
        };
        let body = word.strip_prefix("~/").unwrap_or(&word);
        if body.is_empty() || !body.chars().all(is_plain_path_character) {
            return None;
        }
        words.push(word);
    }
    Some(words)
}

/// The canonical script that `written` names, checked: a regular file a box cannot write, of
/// plain characters and at most [`MAX_SCRIPT_BYTES`], whose `#!` line names a shell with no flags.
fn script_path(written: &str, home: &Path, refusals: &Refusals) -> Result<PathBuf, String> {
    if !written
        .strip_prefix("~/")
        .unwrap_or(written)
        .chars()
        .all(is_plain_path_character)
    {
        return Err("the hook's script is not one plain path".to_string());
    }
    let path = match written.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if written.starts_with('/') => PathBuf::from(written),
        None => {
            return Err(
                "the script is not a full path; box imports only a script named from `/` or `~/`"
                    .to_string(),
            );
        }
    };
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("the script's path holds `.` or `..`".to_string());
    }
    passes_no_writable_place(&path, "script", refusals, home)?;
    let script =
        canonical(&path).ok_or_else(|| format!("{} does not exist", tilde(home, &path)))?;
    let shown = tilde(home, &script);
    if !script
        .to_str()
        .is_some_and(|text| text.chars().all(is_plain_path_character))
    {
        return Err(format!(
            "{shown} holds a character that is not a letter, a digit, or one of `/._-+@,`"
        ));
    }
    if let Some(reason) = refusals.reach(&script) {
        return Err(format!(
            "{reason}; box imports no script that a box can change"
        ));
    }
    if let Some(reason) = refusals.protects(&script) {
        return Err(format!("{reason}; box imports no script from there"));
    }
    let (file, metadata) = admit_at(&script)
        .map_err(|reason| format!("{shown}: {reason}"))?
        .ok_or_else(|| format!("{shown} does not exist"))?;
    if metadata.len() > MAX_SCRIPT_BYTES {
        return Err(format!(
            "{shown} is more than {MAX_SCRIPT_BYTES} bytes, which a box's Shell reads"
        ));
    }
    let mut start = Vec::new();
    file.take(256)
        .read_to_end(&mut start)
        .map_err(|error| format!("{shown}: {error}"))?;
    let first = start
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    // A character the 256-byte cut leaves incomplete at the end is not an invalid byte.
    let binary = start.contains(&0)
        || matches!(std::str::from_utf8(&start), Err(error) if error.error_len().is_some());
    if !first.starts_with(b"#!") && binary {
        return Err(format!("{shown} is not a shell script"));
    }
    if let Some(line) = first.strip_prefix(b"#!") {
        let line = String::from_utf8_lossy(line);
        let words: Vec<&str> = line.split_whitespace().collect();
        let shell = match words.as_slice() {
            [program] => Path::new(program)
                .file_name()
                .and_then(|name| name.to_str()),
            [env, program]
                if Path::new(env).file_name().and_then(|n| n.to_str()) == Some("env") =>
            {
                Some(*program)
            }
            _ => None,
        };
        if !shell.is_some_and(|shell| SCRIPT_SHELLS.contains(&shell)) {
            return Err(format!(
                "{shown} starts with `#!{}`; box runs only a shell script whose `#!` line names \
                 sh, bash, or zsh with no flags",
                line.trim()
            ));
        }
    }
    Ok(script)
}

/// The most links one script path may pass through.
const MAX_LINKS: usize = 40;

/// Refuse `path` when reaching it passes through, or follows a link that lies in, a place that a
/// box can write, so a box cannot change which file the path names.
fn passes_no_writable_place(
    path: &Path,
    what_file: &str,
    refusals: &Refusals,
    home: &Path,
) -> Result<(), String> {
    let roots: Vec<(PathBuf, &str)> = refusals
        .roots
        .iter()
        .flat_map(|(root, what)| {
            let real = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            [(root.clone(), what.as_str()), (real, what.as_str())]
        })
        .collect();
    let identity = |path: &Path| {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path)
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()))
    };
    let root_identities: Vec<((u64, u64), PathBuf, &str)> = refusals
        .roots
        .iter()
        .filter_map(|(root, what)| identity(root).map(|id| (id, root.clone(), what.as_str())))
        .collect();
    let mut pending: std::collections::VecDeque<std::ffi::OsString> =
        std::collections::VecDeque::new();
    let mut current = PathBuf::from("/");
    let mut links = 0;
    let push_front = |pending: &mut std::collections::VecDeque<std::ffi::OsString>,
                      current: &mut PathBuf,
                      target: &Path| {
        let mut parts = Vec::new();
        for component in target.components() {
            match component {
                Component::RootDir => {
                    *current = PathBuf::from("/");
                    parts.clear();
                }
                Component::Normal(name) => parts.push(name.to_os_string()),
                Component::ParentDir => parts.push("..".into()),
                Component::CurDir | Component::Prefix(_) => {}
            }
        }
        for part in parts.into_iter().rev() {
            pending.push_front(part);
        }
    };
    push_front(&mut pending, &mut current, path);
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            current.pop();
            continue;
        }
        let next = current.join(&part);
        if let Some((root, what)) = roots
            .iter()
            .find(|(root, _)| next == *root || next.starts_with(root))
        {
            return Err(format!(
                "the path to the {what_file} passes through {}, which is {what}, {}; box reads no \
                 {what_file} that a box can change",
                tilde(home, &next),
                tilde(home, root)
            ));
        }
        match std::fs::symlink_metadata(&next) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(format!(
                        "the path to the {what_file} follows too many links"
                    ));
                }
                let target = std::fs::read_link(&next).map_err(|error| error.to_string())?;
                push_front(&mut pending, &mut current, &target);
            }
            Ok(_) => {
                // A root reached under another spelling, such as another letter case, is the same
                // folder.
                if let Some((_, root, what)) = identity(&next)
                    .and_then(|id| root_identities.iter().find(|(root_id, ..)| *root_id == id))
                {
                    return Err(format!(
                        "the path to the {what_file} passes through {}, which is {what}, {}; box \
                         reads no {what_file} that a box can change",
                        tilde(home, &next),
                        tilde(home, root)
                    ));
                }
                current = next;
            }
            Err(_) => current = next,
        }
    }
    Ok(())
}

/// The JSON object in `path`, or `None` when the file is absent, refused when the file box opened
/// lies in a refused root.
fn read_json(path: &Path, refusals: &Refusals) -> Result<Option<Map<String, Value>>, String> {
    let Some((file, _, real)) = admit(path)? else {
        return Ok(None);
    };
    refusals.reach(&real).map_or(Ok(()), |reason| {
        Err(format!("{reason}; box copies no file from there"))
    })?;
    let mut text = String::new();
    file.take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| error.to_string())?;
    parse_object(&text).map(Some)
}

/// [`admit`] for a path that must still be its own real path, which is the path box checked.
fn admit_at(path: &Path) -> Result<Option<(std::fs::File, std::fs::Metadata)>, String> {
    match admit(path)? {
        Some((_, _, real)) if real != path => Err("it changed while box read it".to_string()),
        admitted => Ok(admitted.map(|(file, metadata, _)| (file, metadata))),
    }
}

/// `path` opened by its real path without following a link, as a regular file with one link that
/// is still the file the real path names, with that real path, or `None` when it is absent.
fn admit(path: &Path) -> Result<Option<(std::fs::File, std::fs::Metadata, PathBuf)>, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let real = match std::fs::canonicalize(path) {
        Ok(real) => real,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&real)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("it is not a file".to_string());
    }
    if metadata.nlink() != 1 {
        return Err("it has another hard link".to_string());
    }
    let named = std::fs::metadata(&real).map_err(|error| error.to_string())?;
    if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino())
        || std::fs::canonicalize(path).ok().as_deref() != Some(real.as_path())
    {
        return Err("it changed while box read it".to_string());
    }
    Ok(Some((file, metadata, real)))
}

/// `text` as a JSON object no larger than [`MAX_SETTINGS_BYTES`].
fn parse_object(text: &str) -> Result<Map<String, Value>, String> {
    if text.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(format!("it is more than {MAX_SETTINGS_BYTES} bytes"));
    }
    match serde_json::from_str(text) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err("it is not a JSON object".to_string()),
        Err(error) => Err(format!("it is not JSON: {error}")),
    }
}

/// Make the copy's hooks what `imported` holds, through no link. Return a line when the run
/// replaced or removed hooks that the copy held.
pub(crate) fn apply(
    row: &HookImport,
    imported: &Imported,
    home: &Path,
) -> Result<Option<String>, Error> {
    let Some(owned) = row.key.first() else {
        return Ok(None);
    };
    let disable_all = imported.disable_all.then_some(Value::Bool(true));
    let wanted = imported.hooks.is_some() || disable_all.is_some();
    let keep_flag = imported.host_unread;
    if !wanted && std::fs::symlink_metadata(&row.target).is_err() {
        return Ok(None);
    }
    let copy = Copy {
        target: &row.target,
        relative: &row.relative,
        at: &row.at,
        create: wanted,
        limit: Some(MAX_SETTINGS_BYTES),
    };
    let in_storage = format!("{} in storage", row.relative);
    let after = imported.hooks.clone();
    let mut line = None;
    let edited = edit_in_storage(&copy, false, |text| {
        let mut settings = match text.map(parse_object) {
            Some(Ok(settings)) => settings,
            // The agent may still read a copy box cannot parse, so box keeps no hook it cannot see.
            Some(Err(reason)) => {
                return Err(Error::Set {
                    at: row.at.clone(),
                    reason: format!(
                        "{}: {reason}; box rewrites the hooks in this file on each run, so fix the \
                         file or delete it to let box copy it again",
                        tilde(home, &row.target)
                    ),
                });
            }
            None => Map::new(),
        };
        let before = settings.get(owned).cloned();
        let disabled = row
            .disable_key
            .as_ref()
            .and_then(|key| settings.get(key))
            .cloned();
        let disable_all = if keep_flag {
            disabled.clone()
        } else {
            disable_all.clone()
        };
        if before == after && disabled == disable_all {
            return Ok(None);
        }
        settings.remove(owned);
        if let Some(hooks) = &after {
            settings.insert(owned.clone(), hooks.clone());
        }
        if let Some(key) = &row.disable_key {
            settings.remove(key);
            if let Some(flag) = &disable_all {
                settings.insert(key.clone(), flag.clone());
            }
        }
        let before = before.filter(|before| Some(before) != after.as_ref());
        let target = tilde(home, &row.target);
        line = before.map(|_| match after {
            Some(_) => format!(
                "replaced the hooks in {target} with the hooks imported from {}",
                tilde(home, &row.source)
            ),
            None => format!("removed the hooks in {target}; this run imports none"),
        });
        let mut text =
            serde_json::to_string_pretty(&Value::Object(settings)).map_err(|error| Error::Set {
                at: row.at.clone(),
                reason: error.to_string(),
            })?;
        text.push('\n');
        if text.len() as u64 > MAX_SETTINGS_BYTES {
            return Err(Error::Set {
                at: row.at.clone(),
                reason: format!(
                    "{in_storage} would be more than {MAX_SETTINGS_BYTES} bytes with the imported hooks; box leaves it as it is"
                ),
            });
        }
        Ok(Some(text))
    });
    edited?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use serde_json::json;

    use super::*;
    use crate::lang::{HookDrop, HookSetting};

    /// Settings that resolve into a refused root when box opens them are refused, and not read.
    #[test]
    fn settings_that_resolve_into_a_refused_root_when_opened_are_refused() {
        let fixture = Fixture::new();
        let planted = fixture.workspace.join("settings.json");
        std::fs::write(&planted, r#"{"hooks": {}}"#).expect("settings");
        let linked = fixture.home.join(".agent/settings.json");
        symlink(&planted, &linked).expect("a link");
        let refused = read_json(&linked, &fixture.refusals()).expect_err("refused");
        assert!(refused.contains("the workspace"), "{refused}");
        let host = fixture.home.join(".agent/host.json");
        std::fs::write(&host, r#"{"hooks": {}}"#).expect("settings");
        assert!(
            read_json(&host, &fixture.refusals())
                .expect("read")
                .is_some()
        );
    }

    /// A target whose folder does not exist yet is created without following a link.
    #[test]
    fn a_nested_target_is_created_on_its_first_write() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        let mut row = fixture.row(true);
        row.target = fixture.storage.join("config/nested/deeper/settings.json");
        row.relative = "config/nested/deeper/settings.json".into();
        let imported = super::import(&row, &fixture.refusals(), &fixture.home);
        apply(&row, &imported, &fixture.home).expect("the first write creates the folders");
        let copy: Value =
            serde_json::from_str(&std::fs::read_to_string(&row.target).expect("the copy"))
                .expect("JSON");
        assert!(copy.get("hooks").is_some(), "{copy}");

        let mut linked = fixture.row(true);
        symlink(&fixture.workspace, fixture.storage.join("config/away")).expect("a link");
        linked.target = fixture.storage.join("config/away/new/settings.json");
        linked.relative = "config/away/new/settings.json".into();
        assert!(apply(&linked, &imported, &fixture.home).is_err());
        assert!(
            !fixture.workspace.join("new").exists(),
            "no folder made through a link"
        );
    }

    /// A script whose path no longer resolves to itself when box opens it is refused.
    #[test]
    fn a_script_path_that_moved_after_its_check_is_refused() {
        let fixture = Fixture::new();
        let real = fixture.home.join(".agent/hooks/real.sh");
        std::fs::write(&real, "#!/bin/bash\necho ok\n").expect("a script");
        let moved = fixture.home.join(".agent/hooks/moved.sh");
        symlink(&real, &moved).expect("a link");
        assert!(admit_at(&real).expect("admitted").is_some());
        assert_eq!(
            admit_at(&moved).err().as_deref(),
            Some("it changed while box read it")
        );
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        home: PathBuf,
        storage: PathBuf,
        workspace: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let home = directory.path().canonicalize().expect("canonical");
            let storage = home.join(".strands/box/storage/agent/default");
            let workspace = home.join("work/app");
            for folder in [
                storage.join("config"),
                workspace.clone(),
                home.join(".agent/hooks"),
            ] {
                std::fs::create_dir_all(folder).expect("a folder");
            }
            Self {
                _directory: directory,
                home,
                storage,
                workspace,
            }
        }

        fn refusals(&self) -> Refusals {
            Refusals {
                home: self.home.clone(),
                roots: vec![
                    (self.workspace.clone(), "the workspace".into()),
                    (self.storage.clone(), "the run's storage".into()),
                    (self.home.join(".strands/box"), "the box home".into()),
                ],
                shipped: None,
                protected: Vec::new(),
            }
        }

        fn row(&self, import: bool) -> HookImport {
            let path = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
            HookImport {
                source: self.home.join(".agent/settings.json"),
                refused: None,
                target: self.storage.join("config/settings.json"),
                relative: "config/settings.json".into(),
                at: "storage.hooks[0]".into(),
                import,
                key: path(&["hooks", "*", "*", "hooks", "*"]),
                keep_above: vec!["matcher".into()],
                only: Some((path(&["type"]), "command".into())),
                command: path(&["command"]),
                args: Some(path(&["args"])),
                keep: ["type", "timeout", "onFailure", "statusMessage"]
                    .iter()
                    .map(|field| path(&[field]))
                    .collect(),
                drop: vec![HookDrop {
                    key: path(&["shell"]),
                    equals: Some("bash".into()),
                }],
                set: vec![
                    HookSetting {
                        key: path(&["command"]),
                        value: HookValue::Text(vec!["bash".into()]),
                    },
                    HookSetting {
                        key: path(&["args"]),
                        value: HookValue::List(vec![
                            HookValue::Text(vec!["-c".into()]),
                            HookValue::Text(vec![". ".into(), String::new()]),
                        ]),
                    },
                ],
                disable_key: Some("disableAllHooks".into()),
            }
        }

        /// A row for a file that holds a list of hooks, each with its command below `action`.
        fn flat_row(&self) -> HookImport {
            let path = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
            HookImport {
                key: path(&["on_event", "*"]),
                keep_above: Vec::new(),
                only: Some((path(&["action", "kind"]), "shell".into())),
                command: path(&["action", "run"]),
                args: None,
                keep: vec![path(&["event"]), path(&["action", "kind"])],
                drop: vec![HookDrop {
                    key: path(&["note"]),
                    equals: None,
                }],
                set: vec![HookSetting {
                    key: path(&["action", "run"]),
                    value: HookValue::Text(vec![". ".into(), String::new()]),
                }],
                disable_key: None,
                ..self.row(true)
            }
        }

        fn host(&self, settings: Value) {
            std::fs::write(
                self.home.join(".agent/settings.json"),
                serde_json::to_string(&settings).expect("JSON"),
            )
            .expect("host settings");
        }

        fn script(&self, name: &str, text: &str) -> PathBuf {
            let path = self.home.join(".agent/hooks").join(name);
            std::fs::write(&path, text).expect("a script");
            path
        }

        fn import(&self, import: bool) -> Imported {
            super::import(&self.row(import), &self.refusals(), &self.home)
        }

        fn copy(&self) -> Value {
            serde_json::from_str(
                &std::fs::read_to_string(self.storage.join("config/settings.json"))
                    .expect("the copy"),
            )
            .expect("JSON")
        }

        fn apply(&self, imported: &Imported) -> Result<Option<String>, Error> {
            super::apply(&self.row(true), imported, &self.home)
        }
    }

    fn command(command: &str) -> Value {
        json!({"type": "command", "command": command})
    }

    fn one_hook(event: &str, matcher: &str, handler: Value) -> Value {
        json!({"hooks": {event: [{"matcher": matcher, "hooks": [handler]}]}})
    }

    /// A script hook becomes what the row's `set` states, with the script's real path, and keeps
    /// the fields beside it and the fields that the row keeps.
    #[test]
    fn a_script_hook_becomes_the_set_form_with_its_real_path() {
        let fixture = Fixture::new();
        let script = fixture.script("format.sh", "#!/bin/bash\nexit 0\n");
        let mut handler = command("~/.agent/hooks/format.sh");
        handler["timeout"] = json!(30);
        handler["onFailure"] = json!("block");
        fixture.host(one_hook("PostToolUse", "Edit|Write", handler));

        let imported = fixture.import(true);

        assert!(imported.refused.is_empty(), "{:?}", imported.refused);
        assert_eq!(imported.scripts, vec![script.clone()]);
        assert_eq!(
            imported.hooks.expect("hooks"),
            json!({"PostToolUse": [{"matcher": "Edit|Write", "hooks": [{
                "type": "command",
                "command": "bash",
                "args": ["-c", format!(". {}", script.display())],
                "timeout": 30,
                "onFailure": "block",
            }]}]})
        );
    }

    /// Each accepted spelling of one script names the same file.
    #[test]
    fn each_spelling_of_one_script_is_accepted() {
        let fixture = Fixture::new();
        let script = fixture.script("x.sh", "echo hi\n");
        let absolute = script.to_str().unwrap().to_string();
        for spelling in [
            json!({"type": "command", "command": "~/.agent/hooks/x.sh"}),
            json!({"type": "command", "command": "$HOME/.agent/hooks/x.sh"}),
            json!({"type": "command", "command": "\"${HOME}/.agent/hooks/x.sh\""}),
            json!({"type": "command", "command": format!("bash {absolute}")}),
            json!({"type": "command", "command": format!("/bin/sh {absolute}")}),
            json!({"type": "command", "command": "bash", "args": [absolute.clone()]}),
            json!({"type": "command", "command": absolute.clone(), "args": []}),
        ] {
            fixture.host(one_hook("Stop", "", spelling.clone()));
            let imported = fixture.import(true);
            assert!(
                imported.refused.is_empty(),
                "{spelling}: {:?}",
                imported.refused
            );
            assert_eq!(imported.scripts, vec![script.clone()], "{spelling}");
        }
    }

    /// An inline command, an argument, and every other hook type are refused with a reason.
    #[test]
    fn an_inline_command_and_other_hook_types_are_refused_with_a_reason() {
        let fixture = Fixture::new();
        let script = fixture.script("check.sh", "#!/bin/bash\nexit 0\n");
        fixture.script("tool.py", "#!/usr/bin/env python3\nprint(1)\n");
        std::fs::write(
            fixture.home.join(".agent/hooks/binary"),
            b"\x7fELF\x02\x00\xff",
        )
        .expect("a program");
        let cases = [
            (
                command("jq -r .tool_input.file_path | xargs prettier --write"),
                "inline command",
            ),
            (command("echo $(cat)"), "inline command"),
            (command("bash -c 'rm -rf /tmp/x'"), "inline command"),
            (
                command("\"$PROJECT_DIR\"/.agent/hooks/p.sh"),
                "inline command",
            ),
            (
                command("~/.agent/hooks/check.sh --strict"),
                "the hook passes arguments to its program",
            ),
            (
                command("~/.agent/hooks/check.sh PreToolUse"),
                "the hook passes arguments to its program",
            ),
            (
                json!({"type": "command", "command": script.to_str().unwrap(), "args": ["PreToolUse"]}),
                "the hook passes arguments to its program",
            ),
            (
                command("bash ~/.agent/hooks/check.sh PreToolUse"),
                "the hook passes arguments to its program",
            ),
            (
                command("node ~/.agent/hooks/check.js"),
                "starts a program other than sh, bash, or zsh",
            ),
            (
                command("~/.agent/hooks/tool.py ~/.agent/hooks/check.sh"),
                "starts a program other than sh, bash, or zsh",
            ),
            (
                command("~/.agent/hooks/binary ~/.agent/hooks/check.sh"),
                "starts a program other than sh, bash, or zsh",
            ),
            (
                json!({"type": "command", "command": "bash", "args": ["-c", "true"]}),
                "passes arguments",
            ),
            (
                json!({"type": "command", "command": "node", "args": [script.to_str().unwrap()]}),
                "starts a program other than sh, bash, or zsh",
            ),
            (
                json!({"type": "command", "command": "~/.agent/hooks/check.sh", "shell": "powershell"}),
                "the hook's `shell` is `powershell`; box imports the hook only when it is `bash`",
            ),
            (
                json!({"type": "command", "command": "~/.agent/hooks/check.sh", "shell": 5}),
                "the hook's `shell` is a value that is not a string",
            ),
            (
                json!({"type": "http", "url": "https://example.com/hook"}),
                "`http` hook",
            ),
            (
                json!({"type": "prompt", "prompt": "check it"}),
                "`prompt` hook",
            ),
            (
                json!({"type": "agent", "prompt": "check it"}),
                "`agent` hook",
            ),
            (
                json!({"type": "mcp_tool", "server": "s", "tool": "t"}),
                "`mcp_tool` hook",
            ),
            (
                json!({"type": "command", "command": "~/.agent/hooks/check.sh", "env": {}}),
                "holds `env`",
            ),
            (command(".agent/hooks/check.sh"), "not a full path"),
            (command("~/.agent/hooks/absent.sh"), "does not exist"),
        ];
        for (handler, reason) in cases {
            fixture.host(one_hook("PreToolUse", "Bash", handler.clone()));
            let imported = fixture.import(true);
            assert_eq!(imported.hooks, None, "{handler}");
            assert_eq!(imported.scripts, Vec::<PathBuf>::new(), "{handler}");
            let [(hook, why)] = imported.refused.as_slice() else {
                panic!("{handler}: one refusal, got {:?}", imported.refused);
            };
            assert!(hook.starts_with("PreToolUse (Bash)"), "{hook}");
            assert!(why.contains(reason), "{handler}: {why}");
        }
    }

    /// A script that is not a plain shell script, or one a box can write, is refused.
    #[test]
    fn a_script_that_is_not_a_plain_shell_script_or_that_a_box_can_write_is_refused() {
        let fixture = Fixture::new();
        fixture.script("hook.py", "#!/usr/bin/env python3\nprint(1)\n");
        fixture.script("strict.sh", "#!/bin/bash -e\nfalse\n");
        fixture.script("big.sh", &"#".repeat(MAX_SCRIPT_BYTES as usize + 1));
        let in_project = fixture.workspace.join("hook.sh");
        std::fs::write(&in_project, "exit 0\n").expect("a project script");
        let linked = fixture.home.join(".agent/hooks/linked.sh");
        symlink(&in_project, &linked).expect("a link");
        for (written, reason) in [
            (
                "~/.agent/hooks/hook.py".to_string(),
                "#!/usr/bin/env python3",
            ),
            ("~/.agent/hooks/strict.sh".to_string(), "no flags"),
            ("~/.agent/hooks/big.sh".to_string(), "more than"),
            (in_project.to_str().unwrap().to_string(), "the workspace"),
            ("~/.agent/hooks/linked.sh".to_string(), "the workspace"),
        ] {
            fixture.host(one_hook("Stop", "", command(&written)));
            let imported = fixture.import(true);
            assert_eq!(imported.scripts, Vec::<PathBuf>::new(), "{written}");
            let [(_, why)] = imported.refused.as_slice() else {
                panic!("{written}: one refusal, got {:?}", imported.refused);
            };
            assert!(why.contains(reason), "{written}: {why}");
        }
    }

    /// A script in a path that a secret source protects is refused, as written or through a link,
    /// because the run would permit the agent's Shell to read it.
    #[test]
    fn a_script_in_a_path_that_a_secret_source_protects_is_refused() {
        let fixture = Fixture::new();
        let vault = fixture.home.join(".agent/hooks/vault");
        std::fs::create_dir_all(&vault).expect("a vault folder");
        std::fs::write(vault.join("x.sh"), "#!/bin/bash\nexit 0\n").expect("a script");
        symlink(
            vault.join("x.sh"),
            fixture.home.join(".agent/hooks/linked.sh"),
        )
        .expect("a link");
        fixture.script("plain.sh", "#!/bin/bash\nexit 0\n");
        let refusals = Refusals {
            protected: vec![crate::storage_files::Protected {
                path: vault.clone(),
                key: "[protect] paths",
                source: "the plugin @box/1password".to_string(),
            }],
            ..fixture.refusals()
        };
        let refused = "~/.agent/hooks/vault/x.sh lies in ~/.agent/hooks/vault, a path that \
                       the plugin @box/1password lists in `[protect] paths`, which the box keeps \
                       from every workload; box imports no script from there";
        for (written, wanted) in [
            ("~/.agent/hooks/vault/x.sh", Some(refused)),
            ("~/.agent/hooks/linked.sh", Some(refused)),
            ("~/.agent/hooks/plain.sh", None),
        ] {
            fixture.host(one_hook("Stop", "", command(written)));
            let imported = super::import(&fixture.row(true), &refusals, &fixture.home);
            let why: Vec<&str> = imported
                .refused
                .iter()
                .map(|(_, why)| why.as_str())
                .collect();
            assert_eq!(why, wanted.into_iter().collect::<Vec<_>>(), "{written}");
            assert_eq!(
                imported.scripts.len(),
                usize::from(wanted.is_none()),
                "{written}"
            );
        }
    }

    /// A script whose real path holds a space, a quote, or another character that a shell does not
    /// read as itself, or that has another hard link, is refused, so no path changes the command
    /// that holds it.
    #[test]
    fn a_script_whose_real_path_is_not_plain_or_that_has_another_hard_link_is_refused() {
        let fixture = Fixture::new();
        for folder in [
            "${PROJECT_DIR}",
            "a b",
            "x;y",
            "it's",
            "q\"q",
            "$(id)",
            "a\nb",
        ] {
            let real = fixture.home.join("odd").join(folder);
            std::fs::create_dir_all(&real).expect("a folder");
            std::fs::write(real.join("s.sh"), "exit 0\n").expect("a script");
            let link = fixture.home.join(".agent/hooks/odd");
            let _ = std::fs::remove_file(&link);
            symlink(&real, &link).expect("a link");
            fixture.host(one_hook("Stop", "", command("~/.agent/hooks/odd/s.sh")));
            let imported = fixture.import(true);
            assert_eq!(imported.scripts, Vec::<PathBuf>::new(), "{folder}");
            assert!(
                imported.refused[0].1.contains("is not a letter"),
                "{folder}: {:?}",
                imported.refused
            );
        }
        let script = fixture.script("linked.sh", "exit 0\n");
        std::fs::hard_link(&script, fixture.home.join("elsewhere.sh")).expect("a hard link");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/linked.sh")));
        let imported = fixture.import(true);
        assert!(
            imported.refused[0].1.contains("hard link"),
            "{:?}",
            imported.refused
        );
    }

    /// A file with no `#!` line that is not text, such as a compiled program, is refused.
    #[test]
    fn a_compiled_program_is_not_imported_as_a_script() {
        let fixture = Fixture::new();
        let path = fixture.home.join(".agent/hooks/notify");
        std::fs::write(&path, b"\x7fELF\x02\x01\x01\x00\x00\x00").expect("a program");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/notify")));
        let imported = fixture.import(true);
        assert_eq!(imported.scripts, Vec::<PathBuf>::new());
        assert!(
            imported.refused[0].1.contains("is not a shell script"),
            "{:?}",
            imported.refused
        );
    }

    /// Host settings with another hard link are not read, so a writable alias of the file cannot
    /// name what the agent gets to read.
    #[test]
    fn host_settings_with_another_hard_link_are_not_read() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        std::fs::hard_link(
            fixture.home.join(".agent/settings.json"),
            fixture.workspace.join("settings.json"),
        )
        .expect("a hard link");
        let imported = fixture.import(true);
        assert_eq!(imported.scripts, Vec::<PathBuf>::new());
        assert!(
            imported.notes[0].contains("another hard link"),
            "{:?}",
            imported.notes
        );
    }

    /// Many refused handlers under a long matcher keep a bounded report.
    #[test]
    fn a_long_matcher_with_many_refused_hooks_keeps_a_bounded_report() {
        let fixture = Fixture::new();
        let handlers: Vec<Value> = (0..MAX_INSPECTED + 10).map(|_| Value::Null).collect();
        fixture.host(
            json!({"hooks": {"Stop": [{"matcher": "m".repeat(100_000), "hooks": handlers}]}}),
        );
        let imported = fixture.import(true);
        assert_eq!(imported.refused.len(), MAX_LISTED_REFUSALS);
        assert!(
            imported
                .refused
                .iter()
                .all(|(hook, why)| hook.len() < 120 && why.len() < 320)
        );
        assert_eq!(
            imported.notes,
            vec![format!(
                "did not import {} more hooks",
                MAX_INSPECTED + 10 - MAX_LISTED_REFUSALS
            )]
        );
    }

    /// A rewrite whose result would pass the size limit is refused, and the copy stays as it was.
    #[test]
    fn a_rewrite_over_the_size_limit_leaves_the_copy_alone() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let mut handler = command("~/.agent/hooks/x.sh");
        handler["statusMessage"] = json!("s".repeat(600_000));
        fixture.host(one_hook("Stop", "", handler));
        let copy = fixture.storage.join("config/settings.json");
        let before = format!("{{\"pad\":\"{}\"}}", "p".repeat(600_000));
        std::fs::write(&copy, &before).expect("a copy");
        let error = fixture.apply(&fixture.import(true)).expect_err("too large");
        assert!(error.to_string().contains("would be more than"), "{error}");
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), before);
    }

    /// An exec-form command that is not one script path is refused without its text.
    #[test]
    fn an_exec_form_command_is_refused_without_its_text() {
        let fixture = Fixture::new();
        fixture.host(one_hook(
            "Stop",
            "",
            json!({"type": "command", "command": "curl -H token-246 https://example.com", "args": []}),
        ));
        let imported = fixture.import(true);
        let [(hook, why)] = imported.refused.as_slice() else {
            panic!("one refusal, got {:?}", imported.refused);
        };
        assert!(
            !hook.contains("token-246") && !why.contains("token-246"),
            "{why}"
        );
        assert!(why.contains("not one script path"), "{why}");
    }

    /// Neither a malformed event's name nor an exec-form argument is echoed in full.
    #[test]
    fn refusal_labels_never_carry_long_or_unchecked_text() {
        let fixture = Fixture::new();
        let event = format!("E{}token-246", "e".repeat(200));
        fixture.host(json!({"hooks": {event: "not a list"}}));
        let imported = fixture.import(true);
        assert!(imported.refused[0].0.len() < 60, "{:?}", imported.refused);
        assert!(!imported.refused[0].0.contains("token-246"));

        fixture.host(one_hook(
            "Stop",
            "",
            json!({"type": "command", "command": "bash", "args": ["/tmp/x;curl -H token-246"]}),
        ));
        let imported = fixture.import(true);
        let [(_, why)] = imported.refused.as_slice() else {
            panic!("one refusal, got {:?}", imported.refused);
        };
        assert!(!why.contains("token-246"), "{why}");
    }

    /// A text script whose multi-byte character spans the inspected prefix is still a script.
    #[test]
    fn a_text_script_with_a_character_across_the_inspected_prefix_is_imported() {
        let fixture = Fixture::new();
        let mut text = "# notify when done\n".to_string();
        text.push_str(&"e".repeat(255 - text.len()));
        text.push_str("\u{2014} osascript -e 'display notification \"done\"'\n");
        let script = fixture.script("notify.sh", &text);
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/notify.sh")));
        let imported = fixture.import(true);
        assert!(imported.refused.is_empty(), "{:?}", imported.refused);
        assert_eq!(imported.scripts, vec![script]);
    }

    /// At most a fixed number of refusals are listed, each without its command text.
    #[test]
    fn refusals_are_capped_and_never_show_the_command() {
        let fixture = Fixture::new();
        let handlers: Vec<Value> = (0..MAX_LISTED_REFUSALS + 5)
            .map(|_| command("curl -H 'Authorization: token-246' https://example.com"))
            .collect();
        fixture.host(json!({"hooks": {"Stop": [{"hooks": handlers}]}}));
        let imported = fixture.import(true);
        assert_eq!(imported.refused.len(), MAX_LISTED_REFUSALS);
        assert!(
            imported
                .notes
                .contains(&"did not import 5 more hooks".to_string())
        );
        assert!(
            imported
                .refused
                .iter()
                .all(|(hook, why)| !hook.contains("token-246") && !why.contains("token-246"))
        );
        assert_eq!(imported.refused[0].0, "Stop #1");
    }

    /// A link at the hooks folder names only the one file, never the folder it points into.
    #[test]
    fn a_link_at_the_hooks_folder_grants_only_the_named_file() {
        let fixture = Fixture::new();
        std::fs::remove_dir(fixture.home.join(".agent/hooks")).expect("remove the folder");
        let elsewhere = fixture.home.join("Documents/private");
        std::fs::create_dir_all(&elsewhere).expect("a folder");
        std::fs::write(elsewhere.join("secret.txt"), "token").expect("a secret");
        std::fs::write(elsewhere.join("fmt.sh"), "exit 0\n").expect("a script");
        symlink(&elsewhere, fixture.home.join(".agent/hooks")).expect("a link");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/fmt.sh")));

        let imported = fixture.import(true);

        assert_eq!(imported.scripts, vec![elsewhere.join("fmt.sh")]);
        let hooks = imported.hooks.expect("hooks");
        assert_eq!(
            hooks["Stop"][0]["hooks"][0]["args"],
            json!(["-c", format!(". {}", elsewhere.join("fmt.sh").display())])
        );
    }

    /// A script path that passes through a link a box can write is refused, whether the link sits
    /// in the written path or behind another link, so a box cannot point a grant at a host file.
    #[test]
    fn a_script_path_through_a_writable_link_is_refused() {
        let fixture = Fixture::new();
        let private = fixture.home.join("Documents/private");
        std::fs::create_dir_all(&private).expect("a folder");
        std::fs::write(private.join("x.sh"), "exit 0\n").expect("a private file");
        symlink(&private, fixture.workspace.join("link")).expect("a workspace link");
        for written in ["~/work/app/link/x.sh", "~/.agent/hooks/via/x.sh"] {
            if written.contains("via") {
                symlink(
                    fixture.workspace.join("link"),
                    fixture.home.join(".agent/hooks/via"),
                )
                .expect("a link into the workspace");
            }
            fixture.host(one_hook("Stop", "", command(written)));

            let imported = fixture.import(true);

            assert!(
                imported.scripts.is_empty(),
                "{written}: {:?}",
                imported.scripts
            );
            assert!(imported.hooks.is_none(), "{written}");
            assert!(
                imported
                    .refused
                    .iter()
                    .any(|(_, why)| why.contains("passes through") && why.contains("workspace")),
                "{written}: {:?}",
                imported.refused
            );
        }
    }

    /// Settings reached through a link a box can write are not read, so a box cannot pick which
    /// host settings supply the grants. A trusted link to the settings still reads.
    #[test]
    fn settings_through_a_writable_link_are_not_read() {
        let fixture = Fixture::new();
        let other = fixture.home.join("other");
        std::fs::create_dir_all(&other).expect("a folder");
        let secret = fixture.home.join("secret");
        std::fs::create_dir_all(&secret).expect("a folder");
        std::fs::write(secret.join("id"), "exit 0\n").expect("a host file");
        let settings = one_hook("Stop", "", command(secret.join("id").to_str().unwrap()));
        std::fs::write(other.join("settings.json"), settings.to_string()).expect("settings");
        symlink(&other, fixture.workspace.join("cfg")).expect("a workspace link");
        symlink(fixture.workspace.join("cfg"), fixture.home.join(".agent2")).expect("a link");
        let mut row = fixture.row(true);
        row.source = fixture.home.join(".agent2/settings.json");

        let imported = super::import(&row, &fixture.refusals(), &fixture.home);

        assert!(imported.scripts.is_empty(), "{:?}", imported.scripts);
        assert!(imported.host_unread);
        assert!(
            imported
                .notes
                .iter()
                .any(|note| note.contains("passes through"))
        );

        let trusted = fixture.home.join(".agent3");
        symlink(&other, &trusted).expect("a trusted link");
        row.source = trusted.join("settings.json");
        let imported = super::import(&row, &fixture.refusals(), &fixture.home);
        assert_eq!(imported.scripts, vec![secret.join("id")]);
    }

    /// The walk follows relative links from the link's own folder, takes `..` in a link target,
    /// meets a refused root entered by its real spelling, and stops at a link loop.
    #[test]
    fn the_walk_resolves_links_as_the_kernel_does() {
        let fixture = Fixture::new();
        let hooks = fixture.home.join(".agent/hooks");
        std::fs::create_dir_all(hooks.join("real")).expect("a folder");
        std::fs::write(hooks.join("real/x.sh"), "exit 0\n").expect("a script");
        symlink("real", hooks.join("rel")).expect("a relative link");
        symlink("real/../real", hooks.join("up")).expect("a link with ..");
        let refusals = fixture.refusals();
        for written in [hooks.join("rel/x.sh"), hooks.join("up/x.sh")] {
            assert!(
                passes_no_writable_place(&written, "script", &refusals, &fixture.home).is_ok(),
                "{}",
                written.display()
            );
        }

        // A refused root named through a link, entered by its real spelling.
        let real_workspace = fixture.home.join("real-workspace");
        std::fs::create_dir_all(&real_workspace).expect("a folder");
        let named = fixture.home.join("named-workspace");
        symlink(&real_workspace, &named).expect("a link");
        let mut through = fixture.refusals();
        through
            .roots
            .push((named.clone(), "a linked workspace".into()));
        assert!(
            passes_no_writable_place(
                &real_workspace.join("x.sh"),
                "script",
                &through,
                &fixture.home
            )
            .is_err()
        );

        // A relative link inside the workspace is resolved from the link's folder.
        std::fs::create_dir_all(fixture.workspace.join("sub")).expect("a folder");
        symlink("../sub", hooks.join("away")).expect("a link");
        symlink(fixture.workspace.join("sub"), hooks.join("into")).expect("a link");
        assert!(
            passes_no_writable_place(&hooks.join("into/x.sh"), "script", &refusals, &fixture.home)
                .is_err()
        );

        symlink("loop-b", hooks.join("loop-a")).expect("a link");
        symlink("loop-a", hooks.join("loop-b")).expect("a link");
        let looped = passes_no_writable_place(
            &hooks.join("loop-a/x.sh"),
            "script",
            &refusals,
            &fixture.home,
        )
        .expect_err("a loop stops");
        assert!(looped.contains("too many links"), "{looped}");
    }

    /// A refused root reached under another spelling of the same folder, such as another letter
    /// case on a case-insensitive volume, is refused by its identity.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_root_under_another_letter_case_is_refused() {
        let fixture = Fixture::new();
        std::fs::write(fixture.workspace.join("x.sh"), "exit 0\n").expect("a script");
        let upper = PathBuf::from(
            fixture
                .workspace
                .to_str()
                .expect("UTF-8")
                .replace("/work/app", "/WORK/APP"),
        );
        if std::fs::metadata(upper.join("x.sh")).is_err() {
            eprintln!("skipping: this volume tells letter case apart");
            return;
        }
        let refused = passes_no_writable_place(
            &upper.join("x.sh"),
            "script",
            &fixture.refusals(),
            &fixture.home,
        )
        .expect_err("the same folder under another case is refused");
        assert!(refused.contains("the workspace"), "{refused}");
    }

    /// When the host settings cannot be read, the copy keeps its `disableAllHooks`, and the note
    /// shows with the option off too.
    #[test]
    fn an_unreadable_host_keeps_the_copys_disable_all_hooks() {
        let fixture = Fixture::new();
        fixture.host(json!({"disableAllHooks": true}));
        let first = fixture.import(false);
        fixture.apply(&first).expect("apply");
        assert_eq!(fixture.copy()["disableAllHooks"], json!(true));
        std::fs::write(fixture.home.join(".agent/settings.json"), "{ not json").expect("break");
        let unread = fixture.import(false);
        assert!(unread.host_unread);
        assert!(
            !unread.notes.is_empty(),
            "the note shows with the option off"
        );
        fixture.apply(&unread).expect("apply");
        assert_eq!(fixture.copy()["disableAllHooks"], json!(true));
    }

    /// A copy box cannot parse stops the run with its path and what to do, because the agent may
    /// still read hooks in it.
    #[test]
    fn a_copy_box_cannot_parse_stops_the_run_and_says_what_to_do() {
        let fixture = Fixture::new();
        std::fs::write(fixture.storage.join("config/settings.json"), "{ not json").expect("copy");
        let imported = fixture.import(false);
        let error = fixture
            .apply(&imported)
            .expect_err("the run stops")
            .to_string();
        assert!(error.contains("delete it"), "{error}");
        assert!(error.contains("settings.json"), "{error}");
    }

    /// A label prints control characters escaped.
    #[test]
    fn a_label_escapes_control_characters() {
        let above = json!({"matcher": "a\nbox: fake"});
        let label = Label::default()
            .named("Stop\u{1b}[31m")
            .beside(above.as_object().unwrap(), &["matcher".to_string()]);
        assert!(!label.0.chars().any(char::is_control), "{}", label.0);
    }

    /// A row with another layout imports a list of hooks whose command lies below a key of the
    /// hook, and writes the command as one string.
    #[test]
    fn a_flat_list_with_a_nested_command_becomes_one_command_string() {
        let fixture = Fixture::new();
        let script = fixture.script("done.sh", "exit 0\n");
        fixture.host(json!({
            "theme": "dark",
            "on_event": [
                {"event": "stop", "note": "mine", "action": {"kind": "shell", "run": "~/.agent/hooks/done.sh"}},
                {"event": "start", "action": {"kind": "http", "run": "https://example.com"}},
                {"event": "edit", "action": {"kind": "shell", "run": "~/.agent/hooks/done.sh", "cwd": "/"}},
                {"event": "save", "extra": 1, "action": {"kind": "shell", "run": "~/.agent/hooks/done.sh"}},
            ],
        }));
        let row = fixture.flat_row();

        let imported = super::import(&row, &fixture.refusals(), &fixture.home);

        assert_eq!(imported.scripts, vec![script.clone()]);
        assert_eq!(
            imported.hooks,
            Some(json!([{
                "event": "stop",
                "action": {"kind": "shell", "run": format!(". {}", script.display())},
            }]))
        );
        let refused: Vec<(&str, &str)> = imported
            .refused
            .iter()
            .map(|(hook, why)| (hook.as_str(), why.as_str()))
            .collect();
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert_eq!(refused[0].0, "#2");
        assert!(refused[0].1.contains("a `http` hook"), "{refused:?}");
        assert!(refused[1].1.contains("holds `action.cwd`"), "{refused:?}");
        assert!(refused[2].1.contains("holds `extra`"), "{refused:?}");

        super::apply(&row, &imported, &fixture.home).expect("apply");
        assert_eq!(fixture.copy()["on_event"], imported.hooks.clone().unwrap());
        assert_eq!(
            fixture.copy().get("theme"),
            None,
            "only the hooks reach the copy"
        );
    }

    /// A command whose script path holds a space is refused with a reason of its own, quoted or
    /// not, with or without a shell before it.
    #[test]
    fn a_script_path_with_a_space_is_refused_with_its_own_reason() {
        let fixture = Fixture::new();
        let folder = fixture.home.join(".agent/my hooks");
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::write(folder.join("x.sh"), "exit 0\n").expect("a script");
        for written in [
            "~/.agent/my hooks/x.sh",
            "\"$HOME/.agent/my hooks/x.sh\"",
            "bash \"~/.agent/my hooks/x.sh\"",
        ] {
            fixture.host(one_hook("Stop", "", command(written)));
            let imported = fixture.import(true);
            assert_eq!(imported.hooks, None, "{written}");
            assert!(
                imported.refused[0]
                    .1
                    .contains("the script's path holds a space"),
                "{written}: {:?}",
                imported.refused
            );
        }
        fixture.host(one_hook("Stop", "", command("~/.agent/no such/x.sh")));
        let imported = fixture.import(true);
        assert!(
            imported.refused[0]
                .1
                .contains("passes arguments to its program"),
            "{:?}",
            imported.refused
        );
    }

    /// A first word that is a named pipe, a terminal, or a link to one is refused with the
    /// arguments reason, and the import does not wait to open it.
    #[test]
    fn a_first_word_that_is_not_a_regular_file_is_refused_without_waiting() {
        use std::os::unix::ffi::OsStrExt as _;
        let fixture = Fixture::new();
        let pipe = fixture.home.join(".agent/hooks/pipe.sh");
        let name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).expect("a C string");
        // SAFETY: `name` is a valid C string, and the test owns its parent directory.
        assert_eq!(unsafe { nix::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        symlink(&pipe, fixture.home.join(".agent/hooks/linked.sh")).expect("a link");
        for written in [
            "~/.agent/hooks/pipe.sh PreToolUse",
            "~/.agent/hooks/linked.sh PreToolUse",
            "/dev/tty PreToolUse",
        ] {
            fixture.host(one_hook("Stop", "", command(written)));
            let (row, refusals, home) =
                (fixture.row(true), fixture.refusals(), fixture.home.clone());
            let (done, imported) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(super::import(&row, &refusals, &home));
            });
            let imported = imported
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("{written}: the import waits to open the first word"));
            assert_eq!(imported.hooks, None, "{written}");
            assert!(
                imported.refused[0]
                    .1
                    .contains("passes arguments to its program"),
                "{written}: {:?}",
                imported.refused
            );
        }
    }

    /// A field that the row drops is accepted and does not reach the copy.
    #[test]
    fn a_dropped_field_is_accepted_and_left_out() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let mut handler = command("~/.agent/hooks/x.sh");
        handler["shell"] = json!("bash");
        fixture.host(one_hook("Stop", "", handler));
        let imported = fixture.import(true);
        assert!(imported.refused.is_empty(), "{:?}", imported.refused);
        let hooks = imported.hooks.expect("hooks");
        assert_eq!(hooks["Stop"][0]["hooks"][0].get("shell"), None);
    }

    /// An object above a hook that holds a field the row does not name is refused, and so is one
    /// whose kept field is not a string.
    #[test]
    fn an_object_above_a_hook_with_a_field_the_row_does_not_name_is_refused() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let handler = command("~/.agent/hooks/x.sh");
        for (group, reason) in [
            (
                json!({"matcher": "Bash", "extra": true, "hooks": [handler.clone()]}),
                "holds `extra`",
            ),
            (
                json!({"matcher": 5, "hooks": [handler.clone()]}),
                "`matcher` is not a string",
            ),
            (json!({"matcher": "Bash"}), "has no `hooks`"),
        ] {
            fixture.host(json!({"hooks": {"PreToolUse": [group.clone()]}}));
            let imported = fixture.import(true);
            assert_eq!(imported.hooks, None, "{group}");
            let [(_, why)] = imported.refused.as_slice() else {
                panic!("{group}: one refusal, got {:?}", imported.refused);
            };
            assert!(why.contains(reason), "{group}: {why}");
        }
    }

    /// A hook without the field that `only` names is refused, and a first key that holds no
    /// container imports nothing with a note.
    #[test]
    fn a_hook_without_the_only_field_and_a_first_key_of_another_kind_import_nothing() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook(
            "Stop",
            "",
            json!({"command": "~/.agent/hooks/x.sh"}),
        ));
        let imported = fixture.import(true);
        assert_eq!(imported.hooks, None);
        assert!(
            imported.refused[0].1.contains("the hook has no `type`"),
            "{:?}",
            imported.refused
        );

        fixture.host(json!({"hooks": "none"}));
        let imported = fixture.import(true);
        assert_eq!(imported.hooks, None);
        assert!(
            imported.notes[0].contains("`hooks` in")
                && imported.notes[0].contains("is not an object or a list"),
            "{:?}",
            imported.notes
        );
    }

    /// A `set` row writes a number and a boolean as they are, and a `"*"` step takes the keys of
    /// an object, with a key of `key` straight below the first one.
    #[test]
    fn a_set_number_and_boolean_reach_a_hook_that_an_object_names() {
        let fixture = Fixture::new();
        let script = fixture.script("x.sh", "exit 0\n");
        fixture.host(json!({"hooks": {"by_name": {
            "format": {"run": "~/.agent/hooks/x.sh"},
            "lint": {"run": "echo inline"},
        }}}));
        let path = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
        let row = HookImport {
            key: path(&["hooks", "by_name", "*"]),
            keep_above: Vec::new(),
            only: None,
            command: path(&["run"]),
            args: None,
            keep: Vec::new(),
            drop: Vec::new(),
            set: vec![
                HookSetting {
                    key: path(&["run"]),
                    value: HookValue::Text(vec![". ".into(), String::new()]),
                },
                HookSetting {
                    key: path(&["limit", "seconds"]),
                    value: HookValue::Fixed(toml::Value::Integer(5)),
                },
                HookSetting {
                    key: path(&["quiet"]),
                    value: HookValue::Fixed(toml::Value::Boolean(true)),
                },
            ],
            disable_key: None,
            ..fixture.row(true)
        };

        let imported = super::import(&row, &fixture.refusals(), &fixture.home);

        assert_eq!(
            imported.hooks,
            Some(json!({"by_name": {"format": {
                "run": format!(". {}", script.display()),
                "limit": {"seconds": 5},
                "quiet": true,
            }}}))
        );
        assert_eq!(imported.refused.len(), 1, "{:?}", imported.refused);
        assert_eq!(imported.refused[0].0, "lint");
    }

    /// A row with no `disable-key` reads no off switch and leaves that key of the copy alone.
    #[test]
    fn a_row_with_no_disable_key_mirrors_no_off_switch() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let mut settings = one_hook("Stop", "", command("~/.agent/hooks/x.sh"));
        settings["disableAllHooks"] = json!(true);
        fixture.host(settings);
        let mut row = fixture.row(true);
        row.disable_key = None;

        let imported = super::import(&row, &fixture.refusals(), &fixture.home);

        assert!(!imported.disable_all);
        assert_eq!(imported.scripts.len(), 1);
        super::apply(&row, &imported, &fixture.home).expect("apply");
        assert_eq!(fixture.copy().get("disableAllHooks"), None);
    }

    /// `disableAllHooks` imports nothing.
    #[test]
    fn disable_all_hooks_imports_nothing() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let mut settings = one_hook("Stop", "", command("~/.agent/hooks/x.sh"));
        settings["disableAllHooks"] = json!(true);
        fixture.host(settings);

        let imported = fixture.import(true);

        assert_eq!(imported.hooks, None);
        assert_eq!(imported.scripts, Vec::<PathBuf>::new());
        assert!(
            imported.notes[0].contains("disableAllHooks"),
            "{:?}",
            imported.notes
        );
        assert!(imported.disable_all);

        fixture.apply(&imported).expect("apply");
        assert_eq!(fixture.copy(), json!({"disableAllHooks": true}));
        fixture.apply(&fixture.import(false)).expect("apply");
        assert_eq!(
            fixture.copy(),
            json!({"disableAllHooks": true}),
            "the host's disableAllHooks reaches the copy with import off too"
        );
        fixture.host(json!({}));
        fixture.apply(&fixture.import(false)).expect("apply");
        assert_eq!(
            fixture.copy(),
            json!({}),
            "the copy follows the host on each run"
        );
    }

    /// With the row off, nothing is read and nothing is imported.
    #[test]
    fn hooks_are_off_unless_the_row_imports() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        assert_eq!(fixture.import(false), Imported::default());
    }

    /// An agent's edit to the copy's hooks is replaced on the next run, and the rest stays.
    #[test]
    fn an_agent_edit_to_the_copys_hooks_does_not_survive_the_next_run() {
        let fixture = Fixture::new();
        let script = fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        std::fs::write(
            fixture.storage.join("config/settings.json"),
            serde_json::to_string(&json!({
                "theme": "dark",
                "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "bash", "args": ["/tmp/planted.sh"]}]}]},
            }))
            .unwrap(),
        )
        .expect("an edited copy");

        let line = fixture.apply(&fixture.import(true)).expect("apply");

        assert!(line.expect("a line").starts_with("replaced the hooks"));
        let copy = fixture.copy();
        assert_eq!(copy["theme"], "dark");
        assert_eq!(
            copy["hooks"],
            json!({"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "bash", "args": ["-c", format!(". {}", script.display())]}]}]})
        );
    }

    /// With the row off, the copy's hooks are removed, whoever wrote them.
    #[test]
    fn turning_import_off_removes_the_copys_hooks() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.storage.join("config/settings.json"),
            r#"{"theme":"dark","hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash","args":["/x.sh"]}]}]}}"#,
        )
        .expect("a copy");

        let line = fixture.apply(&fixture.import(false)).expect("apply");

        assert!(line.expect("a line").starts_with("removed the hooks"));
        assert_eq!(fixture.copy(), json!({"theme": "dark"}));
        assert_eq!(fixture.apply(&fixture.import(false)).expect("apply"), None);
    }

    /// A copy that does not exist is created only when there are hooks.
    #[test]
    fn an_absent_copy_is_created_only_for_hooks() {
        let fixture = Fixture::new();
        assert_eq!(fixture.apply(&Imported::default()).expect("apply"), None);
        assert!(!fixture.storage.join("config/settings.json").exists());

        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        fixture.apply(&fixture.import(true)).expect("apply");
        assert!(fixture.copy()["hooks"]["Stop"].is_array());
    }

    /// `box` reads the host settings and never writes them.
    #[test]
    fn the_host_settings_are_never_written() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        fixture.host(one_hook("Stop", "", command("~/.agent/hooks/x.sh")));
        let host = fixture.home.join(".agent/settings.json");
        let before = (
            std::fs::read(&host).unwrap(),
            std::fs::metadata(&host).unwrap().modified().unwrap(),
        );

        fixture.apply(&fixture.import(true)).expect("apply");
        fixture.apply(&fixture.import(false)).expect("apply");

        let after = (
            std::fs::read(&host).unwrap(),
            std::fs::metadata(&host).unwrap().modified().unwrap(),
        );
        assert_eq!(before, after);
    }

    /// A link or a hard link at the copy stops the rewrite, and nothing is written through it.
    #[test]
    fn a_linked_copy_is_refused_and_never_written_through() {
        let fixture = Fixture::new();
        let host = fixture.home.join(".agent/settings.json");
        fixture.host(json!({"theme": "host"}));
        let copy = fixture.storage.join("config/settings.json");
        symlink(&host, &copy).expect("a link");
        let error = fixture
            .apply(&fixture.import(false))
            .expect_err("a link is refused");
        assert!(error.to_string().contains("link"), "{error}");

        std::fs::remove_file(&copy).unwrap();
        std::fs::hard_link(&host, &copy).expect("a hard link");
        let error = fixture
            .apply(&fixture.import(false))
            .expect_err("a hard link is refused");
        assert!(error.to_string().contains("hard link"), "{error}");
        assert_eq!(
            std::fs::read_to_string(&host).unwrap(),
            r#"{"theme":"host"}"#
        );
    }

    /// The host file, the copy, and the hook count are each bounded.
    #[test]
    fn the_settings_size_and_the_hook_count_are_bounded() {
        let fixture = Fixture::new();
        fixture.script("x.sh", "exit 0\n");
        let handlers: Vec<Value> = (0..MAX_HOOKS + 3)
            .map(|_| command("~/.agent/hooks/x.sh"))
            .collect();
        fixture.host(json!({"hooks": {"Stop": [{"hooks": handlers}]}}));
        let imported = fixture.import(true);
        let kept = imported.hooks.clone().expect("hooks");
        assert_eq!(
            kept["Stop"][0]["hooks"].as_array().unwrap().len(),
            MAX_HOOKS
        );
        assert_eq!(imported.refused.len(), 3);
        assert!(imported.refused[0].1.contains("at most"));

        std::fs::write(
            fixture.home.join(".agent/settings.json"),
            format!(
                "{{\"pad\":\"{}\"}}",
                "x".repeat(MAX_SETTINGS_BYTES as usize)
            ),
        )
        .unwrap();
        let imported = fixture.import(true);
        assert_eq!(imported.hooks, None);
        assert!(
            imported.notes[0].contains("more than"),
            "{:?}",
            imported.notes
        );

        std::fs::copy(
            fixture.home.join(".agent/settings.json"),
            fixture.storage.join("config/settings.json"),
        )
        .unwrap();
        let error = fixture
            .apply(&Imported::default())
            .expect_err("an oversized copy is refused");
        assert!(error.to_string().contains("more than"), "{error}");
    }
}
