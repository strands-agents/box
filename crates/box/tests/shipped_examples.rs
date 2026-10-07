//! Every config file under `examples/` must parse against the config keys box accepts.
//!
//! **This test exists because renaming one key broke a shipped example and nothing
//! noticed**, twice. The parser, its unit tests, the README, and both README guards went
//! green while a shipped config still carried the superseded key, so the one config an
//! operator is most likely to copy failed to load:
//!
//! ```text
//! strands-box: error: cannot parse config file …/strands-box.toml:
//! TOML parse error at line 49, column 1
//!    |
//! 49 | endpoint   = "bedrock-mantle.us-east-2.api.aws"
//!    | ^^^^^^^^
//! ```
//!
//! `documented_inputs.rs` covers the README against the parser. Nothing covered the
//! examples, and an example is a stronger promise than a table: an operator runs it
//! verbatim.
//!
//! Reads the files and compares key names rather than invoking `configure`, for two
//! reasons. The config module is `[[bin]]`-private, so a test cannot call the parser. And
//! `configure` resolves credentials and starts a daemon, which is not this test's subject
//! and would make it need a live environment.

use std::path::{Path, PathBuf};

#[path = "support/parser_source.rs"]
mod parser_source;

use parser_source::{accepted_keys, config_source, repository_root};

#[path = "support/fixture.rs"]
mod fixture;

// `CARGO_BIN_EXE_strands-box`, which cargo supplies. The first version derived the path from
// `current_exe()` by climbing two levels, on the theory that reaching into the fixture would drag in
// box creation and a daemon. That was wrong: `box_binary` is a free function with no side effect,
// and the hand-derived path guesses a target layout that a `--target` triple or a non-default
// profile breaks — quietly, reporting only "spawn strands-box run" and naming no example.
use fixture::box_binary;

/// One shipped config, with where it came from and the policy file beside it.
struct Shipped {
    /// Repo-relative, so a failure names the example rather than a temporary path.
    label: String,
    text: String,
    /// The `policy.dw` beside a config *file*. A config written inline has none.
    policy: Option<PathBuf>,
}

/// Collect every shipped config box itself reads under `examples/`.
///
/// A box config is a file named `box.toml` or `box.toml.in`, or a `box.toml` an example's `run.sh`
/// writes with a heredoc, because a config that exists only inside a script is one no test ever
/// parsed. A `.toml` under another name is a workload's own file: a harness keeps its configuration
/// beside the box that runs it, and box's deserializer is the wrong reader for it.
///
/// **Every file with one of those names, with no content filter**, because a filter on `[egress.a]`
/// was itself the hole: it skipped the examples declaring no egress table, so a malformed one added
/// to any of them shipped undetected. Measured: `[[egress.target]]` passed both sweeps and
/// `config check` printed `config OK`. Only `every_shipped_example_config_parses` reaches box's
/// deserializer, and only for the configs this returns.
///
/// A directory holding a `Cargo.toml` is a Rust helper crate, with manifests and build output rather
/// than box configurations, and the sweep skips it.
fn shipped_configs(root: &Path) -> Vec<Shipped> {
    let mut found = Vec::new();
    let mut pending = vec![root.join("examples")];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Rust helper crates contain manifests and build output, not box configurations.
                if path.join("Cargo.toml").is_file() {
                    continue;
                }
                pending.push(path);
                continue;
            }
            let label = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let is_template = path.file_name().is_some_and(|name| name == "box.toml.in");
            if is_template || path.file_name().is_some_and(|name| name == "box.toml") {
                found.push(Shipped {
                    label,
                    text: std::fs::read_to_string(&path).expect("read the example config"),
                    policy: Some(path.with_file_name(if is_template {
                        "policy.dw.in"
                    } else {
                        "policy.dw"
                    })),
                });
            } else if path.file_name().is_some_and(|name| name == "run.sh") {
                let script = std::fs::read_to_string(&path).expect("read the example script");
                for text in inline_configs(&script) {
                    found.push(Shipped {
                        label: format!("{label} (an inline box.toml)"),
                        text,
                        policy: None,
                    });
                }
            }
        }
    }
    found.sort_by(|left, right| left.label.cmp(&right.label));
    found
}

/// Each `box.toml` a script writes with a heredoc, as the shell would write it.
fn inline_configs(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut lines = script.lines();
    while let Some(line) = lines.next() {
        let Some((target, delimiter)) = line.split_once("<<") else {
            continue;
        };
        if !target.contains("cat >") || !target.contains("box.toml") {
            continue;
        }
        let delimiter = delimiter.trim().trim_matches(['"', '\'']);
        let mut body = String::new();
        for line in lines.by_ref() {
            if line.trim() == delimiter {
                break;
            }
            body.push_str(line);
            body.push('\n');
        }
        found.push(as_written(&body));
    }
    found
}

/// A heredoc body as the shell writes it, with every variable given one fixed value.
///
/// A real value would make this depend on the environment. One placeholder keeps the TOML shape,
/// which is the whole subject, and it is a legal box name so the parser reaches its own verdict.
fn as_written(body: &str) -> String {
    const PLACEHOLDER: &str = "example-box";
    let mut written = String::with_capacity(body.len());
    let mut characters = body.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => written.extend(characters.next()),
            '$' => {
                let braced = characters.peek() == Some(&'{');
                if braced {
                    characters.next();
                }
                while characters
                    .peek()
                    .is_some_and(|next| next.is_alphanumeric() || *next == '_')
                {
                    characters.next();
                }
                if braced && characters.peek() == Some(&'}') {
                    characters.next();
                }
                written.push_str(PLACEHOLDER);
            }
            _ => written.push(character),
        }
    }
    written
}

/// Every key an example assigns must be a field the parser declares.
#[test]
fn every_shipped_example_uses_only_keys_the_parser_accepts() {
    let root = repository_root();
    // Every record, because one `box.toml` assigns top-level keys plus `[egress.b]`,
    // `[agent]`, and `[[mcp]]` keys in the same file. `accepted_keys` asserts it found one
    // key from each, so this cannot pass vacuously.
    let accepted = accepted_keys(&config_source());

    let examples = shipped_configs(&root);
    assert!(
        !examples.is_empty(),
        "found no shipped `box.toml` under {}/examples — either the examples moved, or the key \
         `shipped_configs` matches on was renamed and this test is checking nothing",
        root.display()
    );

    let mut unknown = Vec::new();
    for example in &examples {
        // Check the configuration's egress tables against the parser.
        let mut in_box_table = example.label.ends_with("strands-box.toml");
        for (number, line) in example.text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') {
                // Accept both TOML table header forms.
                let header = trimmed.trim_start_matches('[');
                in_box_table = header.starts_with("egress");
                continue;
            }
            if !in_box_table {
                continue;
            }
            let Some((key, _)) = trimmed.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty()
                || !key
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
            {
                continue;
            }
            if !accepted.iter().any(|field| field == key) {
                unknown.push(format!("{}:{}: `{key}`", example.label, number + 1));
            }
        }
    }

    assert!(
        unknown.is_empty(),
        "shipped examples assign config keys the parser refuses, so running them fails at \
         `configure`: {unknown:#?}"
    );
}

/// **Every shipped example must actually PARSE, not merely use known key names.**
///
/// The key-name comparison above cannot catch a wrong *type*, a missing required field, or a table
/// nested at the wrong depth. It compared names against `config.rs`'s field list and reported
/// success on a `[[credential]]` whose `destinations` was still a bare string rather than an array,
/// and on a file that had lost its `[agent]` table. Measured: both examples were only ever
/// really parsed when their `run.sh` was executed by hand, and one of them failed there.
///
/// The parser is `[[bin]]`-private, so this reaches it the way an operator does — by driving `run`
/// from a copy of the example, in a throwaway home. A parse failure is what `run` reports first, so
/// this needs neither a daemon that stays up nor a real credential.
#[test]
fn every_shipped_example_config_parses() {
    let root = repository_root();
    let examples = shipped_configs(&root);
    assert!(
        !examples.is_empty(),
        "found no shipped config under {}/examples, so this test is checking nothing",
        root.display()
    );

    for example in &examples {
        let home = tempfile::tempdir().expect("a throwaway operator home");
        let workspace = home.path().join("workspace");
        let dot = workspace.join(".strands-box");
        std::fs::create_dir_all(&dot).expect("the workspace's .strands-box");

        let box_directory = home.path().join("box");
        std::fs::create_dir(&box_directory).expect("the caller-owned box directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&box_directory, std::fs::Permissions::from_mode(0o700))
                .expect("the caller-owned box directory is private");
        }
        let mut document: toml::Value = toml::from_str(&example.text).expect("the example is TOML");
        let table = document
            .as_table_mut()
            .expect("the example is a TOML table");
        table.insert(
            "box_dir".to_string(),
            toml::Value::String(box_directory.display().to_string()),
        );
        // The workspace is the agent's, so the derived copy points the example's `[agent]` at the
        // throwaway one rather than at the placeholder its script substitutes.
        table
            .entry("agent")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("`[agent]` is a table")
            .insert(
                "workspace".to_string(),
                toml::Value::String(workspace.display().to_string()),
            );
        let config = dot.join("box.toml");
        std::fs::write(
            &config,
            toml::to_string(&document).expect("serialize the derived box config"),
        )
        .expect("write the derived box config");
        // The example's own policy, beside it, with the workspace path substituted the way its
        // `run.sh` does. A policy that will not load is a different failure, and
        // `policy/tests/shipped_examples.rs` already covers it.
        match example.policy.as_deref().filter(|path| path.is_file()) {
            Some(authored) => {
                let text = std::fs::read_to_string(authored).expect("read the example policy");
                std::fs::write(
                    dot.join("policy.dw"),
                    text.replace("PROJECT_PATH", &workspace.display().to_string()),
                )
                .expect("write the substituted policy");
            }
            // A config written inline names a policy its script writes beside it. One permit is
            // enough here, because only the config's own parse verdict is asserted below.
            None => std::fs::write(
                dot.join("policy.dw"),
                "permit(principal, action == Box::Action::\"shell:exec\", resource);\n",
            )
            .expect("write a placeholder policy"),
        }

        let output = std::process::Command::new(box_binary())
            .arg("run")
            .arg("--config")
            .arg(&config)
            .current_dir(&workspace)
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", home.path().join(".local/state"))
            // The examples declare an `env://` credential, and an unset variable is refused before
            // a box tree exists — which is the box working, not a parse failure. Set so the run
            // reaches the parser's verdict rather than stopping short of it.
            .env("AWS_BEARER_TOKEN_BEDROCK", "parse-check-only")
            .output()
            .expect("spawn strands-box run");
        let reported = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        // Only a *parse* verdict is asserted. A later failure — no daemon, no network — is not
        // this test's subject, and asserting success would make it need a live environment.
        for refusal in [
            "cannot parse config file",
            "unknown field",
            "missing field",
            "invalid type",
        ] {
            assert!(
                !reported.contains(refusal),
                "the shipped example {} does not parse: {reported}",
                example.label
            );
        }
    }
}
