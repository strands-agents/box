//! [`SecretSourceCommand`]: the declaration of one host program that prints one secret.

use std::path::{Path, PathBuf};

use crate::{CredentialError, Result};

/// The text in a declared argument that the reference body replaces.
pub(crate) const SECRET_REFERENCE_TOKEN: &str = "{ref}";

/// The schemes Box Core owns, which no declaration may claim.
const RESERVED_SECRET_SCHEMES: &[&str] = &[
    "env",
    "file",
    "aws",
    "credsd",
    "secret",
    "cmd",
    "oauth2",
    "aws-signed",
    "strip-phantom",
];

/// How a declared program's stdout becomes the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretSourceOutput {
    /// Stdout is the secret.
    Text,
    /// Stdout is one JSON string, and the decoded string is the secret.
    Json,
}

/// One declared secret source: a scheme, and one host program that reads a secret for it.
#[derive(Debug)]
pub struct SecretSourceCommand {
    scheme: String,
    program: PathBuf,
    arguments: Vec<String>,
    output: SecretSourceOutput,
    pass_env: Vec<String>,
    pass_secret_env: Vec<String>,
}

impl SecretSourceCommand {
    /// The one protocol a declaration may name.
    pub const PROTOCOL: &str = "box.secret-source.v1";

    /// Declare `command` (the program, then its arguments) as the source for `scheme`.
    pub fn new(scheme: &str, protocol: &str, command: &[String]) -> Result<Self> {
        Self::check_scheme(scheme)?;
        if protocol != Self::PROTOCOL {
            return Err(refused(
                scheme,
                format!(
                    "names the protocol {protocol:?}, and this box supports only {:?}",
                    Self::PROTOCOL
                ),
            ));
        }
        let Some((program, arguments)) = command.split_first() else {
            return Err(refused(scheme, "has an empty command".to_string()));
        };
        let program = PathBuf::from(program);
        if !program.is_absolute() {
            return Err(refused(
                scheme,
                format!("names the program {program:?}, which is not an absolute path"),
            ));
        }
        if !arguments
            .iter()
            .any(|argument| argument.contains(SECRET_REFERENCE_TOKEN))
        {
            return Err(refused(
                scheme,
                format!(
                    "has no `{SECRET_REFERENCE_TOKEN}` in its arguments, so each reference would \
                     read one secret"
                ),
            ));
        }
        Ok(Self {
            scheme: scheme.to_string(),
            program,
            arguments: arguments.to_vec(),
            output: SecretSourceOutput::Text,
            pass_env: Vec::new(),
            pass_secret_env: Vec::new(),
        })
    }

    /// Refuse a scheme that no declaration can claim: a reserved one, or one that is not well formed.
    pub fn check_scheme(scheme: &str) -> Result<()> {
        let mut characters = scheme.chars();
        let well_formed = characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
            && characters.all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '+' | '.' | '-')
            });
        if !well_formed {
            return Err(CredentialError::Credential(format!(
                "a secret source cannot claim the scheme {scheme:?}: a scheme is a lowercase \
                 letter, then lowercase letters, digits, `+`, `.`, or `-`"
            )));
        }
        if RESERVED_SECRET_SCHEMES.contains(&scheme) {
            return Err(CredentialError::Credential(format!(
                "a secret source cannot claim the scheme {scheme:?}, which the box reserves \
                 (reserved: {})",
                RESERVED_SECRET_SCHEMES.join(", ")
            )));
        }
        Ok(())
    }

    /// Say how the program's stdout becomes the secret: `text` (the default) or `json`.
    pub fn output(mut self, output: &str) -> Result<Self> {
        self.output = match output {
            "text" => SecretSourceOutput::Text,
            "json" => SecretSourceOutput::Json,
            other => {
                return Err(refused(
                    &self.scheme,
                    format!("names the output {other:?}, and an output is `text` or `json`"),
                ));
            }
        };
        Ok(self)
    }

    /// Name the operator's plain settings that the program receives when they are set.
    pub fn pass_env<I, S>(mut self, names: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.pass_env = pass_list(&self.scheme, "pass-env", names)?;
        Ok(self)
    }

    /// Name the operator's credentials that the program receives when they are set.
    pub fn pass_secret_env<I, S>(mut self, names: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.pass_secret_env = pass_list(&self.scheme, "pass-secret-env", names)?;
        Ok(self)
    }

    /// The scheme this declaration claims.
    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The absolute path of the program.
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    /// The program's arguments, as declared.
    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// How stdout becomes the secret.
    pub(crate) fn output_form(&self) -> SecretSourceOutput {
        self.output
    }

    /// Whether either pass list names the variable `name`.
    pub(crate) fn passes(&self, name: &str) -> bool {
        self.pass_env
            .iter()
            .chain(&self.pass_secret_env)
            .any(|entry| entry_matches(entry, name))
    }

    /// Whether `pass-secret-env` names the variable `name`.
    pub(crate) fn passes_as_secret(&self, name: &str) -> bool {
        self.pass_secret_env
            .iter()
            .any(|entry| entry_matches(entry, name))
    }
}

/// Whether one pass-list entry names `name`: an exact name, or a prefix that ends with `*`.
fn entry_matches(entry: &str, name: &str) -> bool {
    match entry.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => entry == name,
    }
}

/// One checked pass list, refused when an entry has no effect or passes every variable.
fn pass_list<I, S>(scheme: &str, list: &str, names: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    names
        .into_iter()
        .map(|name| {
            let name = name.into();
            // The text after `=` can be a value, so a refusal shows only the text before it.
            let start = name.split(['=', '\0']).next().unwrap_or_default();
            let problem = if name.is_empty() {
                Some("names no variable")
            } else if start.len() < name.len() {
                Some("holds `=` or a NUL, and no variable name holds one")
            } else if name == "*" {
                Some("passes the whole environment")
            } else if name == "PATH" {
                Some("has no effect, because each program gets a fixed `PATH`")
            } else if name == "HOME" {
                Some("has no effect, because each program gets the operator's `HOME`")
            } else if name.strip_suffix('*').unwrap_or(&name).contains('*') {
                Some("holds `*` before its end, and only a last `*` makes a prefix")
            } else {
                None
            };
            let Some(problem) = problem else {
                return Ok(name);
            };
            let entry = if start.len() < name.len() {
                format!("an entry that starts with {start:?}")
            } else {
                format!("the entry {name:?}")
            };
            Err(refused(
                scheme,
                format!("has {entry} in `{list}`, which {problem}"),
            ))
        })
        .collect()
}

/// The refusal of one declaration, named by its scheme.
fn refused(scheme: &str, reason: String) -> CredentialError {
    CredentialError::Credential(format!("the secret source {scheme:?} {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    fn declaration(scheme: &str) -> Result<SecretSourceCommand> {
        SecretSourceCommand::new(
            scheme,
            SecretSourceCommand::PROTOCOL,
            &command(&["/opt/tool", "read", "{ref}"]),
        )
    }

    fn refusal(result: Result<SecretSourceCommand>) -> String {
        let error = result.expect_err("the declaration is refused");
        assert!(!error.is_soft(), "a refused declaration fails closed");
        error.to_string()
    }

    #[test]
    fn the_reserved_schemes_are_the_nine_the_box_owns() {
        assert_eq!(
            RESERVED_SECRET_SCHEMES,
            [
                "env",
                "file",
                "aws",
                "credsd",
                "secret",
                "cmd",
                "oauth2",
                "aws-signed",
                "strip-phantom"
            ]
        );
    }

    #[test]
    fn the_reference_token_is_ref_in_braces() {
        assert_eq!(SECRET_REFERENCE_TOKEN, "{ref}");
    }

    #[test]
    fn each_reserved_scheme_is_refused_by_name() {
        for scheme in RESERVED_SECRET_SCHEMES {
            assert_eq!(
                refusal(declaration(scheme)),
                format!(
                    "credential error: a secret source cannot claim the scheme {scheme:?}, which \
                     the box reserves (reserved: env, file, aws, credsd, secret, cmd, oauth2, \
                     aws-signed, strip-phantom)"
                )
            );
        }
    }

    #[test]
    fn op_and_an_unreserved_scheme_are_accepted() {
        for scheme in ["op", "aws-secretsmanager", "vault2", "a+b.c"] {
            let declared = declaration(scheme).expect("the scheme is free to declare");
            assert_eq!(declared.scheme(), scheme);
            SecretSourceCommand::check_scheme(scheme).expect("the check agrees");
        }
    }

    #[test]
    fn a_malformed_scheme_is_refused() {
        for scheme in ["", "Op", "1password", "-op", "op://", "o p", "op_cli", "öp"] {
            assert_eq!(
                refusal(declaration(scheme)),
                format!(
                    "credential error: a secret source cannot claim the scheme {scheme:?}: a \
                     scheme is a lowercase letter, then lowercase letters, digits, `+`, `.`, or `-`"
                )
            );
        }
    }

    #[test]
    fn another_protocol_is_refused() {
        for protocol in ["", "box.secret-source.v2", "BOX.SECRET-SOURCE.V1"] {
            let result = SecretSourceCommand::new("op", protocol, &command(&["/opt/op", "{ref}"]));
            assert_eq!(
                refusal(result),
                format!(
                    "credential error: the secret source \"op\" names the protocol {protocol:?}, \
                     and this box supports only \"box.secret-source.v1\""
                )
            );
        }
    }

    #[test]
    fn an_empty_command_is_refused() {
        let result = SecretSourceCommand::new("op", SecretSourceCommand::PROTOCOL, &[]);
        assert_eq!(
            refusal(result),
            "credential error: the secret source \"op\" has an empty command"
        );
    }

    #[test]
    fn a_program_that_is_not_an_absolute_path_is_refused() {
        for program in ["op", "./op", "bin/op", ""] {
            let result = SecretSourceCommand::new(
                "op",
                SecretSourceCommand::PROTOCOL,
                &command(&[program, "read", "{ref}"]),
            );
            assert_eq!(
                refusal(result),
                format!(
                    "credential error: the secret source \"op\" names the program {program:?}, \
                     which is not an absolute path"
                )
            );
        }
    }

    #[test]
    fn a_command_with_no_reference_token_in_its_arguments_is_refused() {
        for arguments in [
            &["/opt/tool"][..],
            &["/opt/tool", "read", "op://{REF}"],
            &["/opt/tool", "read", "{ ref }", "${ref"],
            &["/opt/{ref}", "read"],
        ] {
            let result =
                SecretSourceCommand::new("op", SecretSourceCommand::PROTOCOL, &command(arguments));
            assert_eq!(
                refusal(result),
                "credential error: the secret source \"op\" has no `{ref}` in its arguments, so \
                 each reference would read one secret",
                "for {arguments:?}"
            );
        }
    }

    #[test]
    fn the_command_splits_into_the_program_and_its_arguments() {
        let declared = declaration("op").expect("valid");
        assert_eq!(declared.program(), Path::new("/opt/tool"));
        assert_eq!(declared.arguments(), ["read", "{ref}"]);
    }

    #[test]
    fn the_output_is_text_unless_json_is_named() {
        let declared = declaration("op").expect("valid");
        assert_eq!(declared.output_form(), SecretSourceOutput::Text);
        let text = declaration("op").and_then(|declared| declared.output("text"));
        assert_eq!(
            text.expect("text is an output").output_form(),
            SecretSourceOutput::Text
        );
        let json = declaration("op").and_then(|declared| declared.output("json"));
        assert_eq!(
            json.expect("json is an output").output_form(),
            SecretSourceOutput::Json
        );
    }

    #[test]
    fn another_output_is_refused() {
        for output in ["", "JSON", "yaml"] {
            let result = declaration("op").and_then(|declared| declared.output(output));
            assert_eq!(
                refusal(result),
                format!(
                    "credential error: the secret source \"op\" names the output {output:?}, and \
                     an output is `text` or `json`"
                )
            );
        }
    }

    #[test]
    fn a_pass_list_entry_that_has_no_effect_or_passes_every_variable_is_refused() {
        let no_effect = "has no effect, because each program gets";
        let inner_star = "holds `*` before its end, and only a last `*` makes a prefix";
        let not_a_name = "holds `=` or a NUL, and no variable name holds one";
        for (entry, named, problem) in [
            ("", "the entry \"\"", "names no variable".to_string()),
            (
                "*",
                "the entry \"*\"",
                "passes the whole environment".to_string(),
            ),
            (
                "PATH",
                "the entry \"PATH\"",
                format!("{no_effect} a fixed `PATH`"),
            ),
            (
                "HOME",
                "the entry \"HOME\"",
                format!("{no_effect} the operator's `HOME`"),
            ),
            (
                "AWS_*_KEY",
                "the entry \"AWS_*_KEY\"",
                inner_star.to_string(),
            ),
            ("**", "the entry \"**\"", inner_star.to_string()),
            // The text after `=` can be a value, so the refusal does not show it.
            (
                "TOKEN=s3cret",
                "an entry that starts with \"TOKEN\"",
                not_a_name.to_string(),
            ),
            (
                "=s3cret",
                "an entry that starts with \"\"",
                not_a_name.to_string(),
            ),
            (
                "A\0B",
                "an entry that starts with \"A\"",
                not_a_name.to_string(),
            ),
        ] {
            let plain = declaration("op").and_then(|declared| declared.pass_env([entry]));
            assert_eq!(
                refusal(plain),
                format!(
                    "credential error: the secret source \"op\" has {named} in `pass-env`, which \
                     {problem}"
                )
            );
            let secret = declaration("op").and_then(|declared| declared.pass_secret_env([entry]));
            assert_eq!(
                refusal(secret),
                format!(
                    "credential error: the secret source \"op\" has {named} in \
                     `pass-secret-env`, which {problem}"
                )
            );
        }
    }

    #[test]
    fn a_name_passes_by_exact_match_or_by_a_prefix_that_ends_with_a_star() {
        let declared = declaration("op")
            // A name that only starts with `HOME` or `PATH` is free to pass.
            .and_then(|declared| {
                declared.pass_env(["OP_ACCOUNT", "ÜBER", "HOMEBREW_PREFIX", "PATH_INFO"])
            })
            .and_then(|declared| declared.pass_secret_env(["OP_SESSION_*", "OP_CONNECT_TOKEN"]))
            .expect("valid");
        let passed: Vec<(&str, bool, bool)> = [
            "OP_ACCOUNT",
            "OP_ACCOUNT_2",
            "OP_SESSION_",
            "OP_SESSION_abc",
            "OP_SESSION",
            "OP_CONNECT_TOKEN",
            "op_account",
            "ÜBER",
            "HOMEBREW_PREFIX",
            "PATH_INFO",
            "GITHUB_TOKEN",
        ]
        .into_iter()
        .map(|name| (name, declared.passes(name), declared.passes_as_secret(name)))
        .collect();
        assert_eq!(
            passed,
            [
                ("OP_ACCOUNT", true, false),
                ("OP_ACCOUNT_2", false, false),
                ("OP_SESSION_", true, true),
                ("OP_SESSION_abc", true, true),
                ("OP_SESSION", false, false),
                ("OP_CONNECT_TOKEN", true, true),
                ("op_account", false, false),
                ("ÜBER", true, false),
                ("HOMEBREW_PREFIX", true, false),
                ("PATH_INFO", true, false),
                ("GITHUB_TOKEN", false, false),
            ]
        );
    }
}
