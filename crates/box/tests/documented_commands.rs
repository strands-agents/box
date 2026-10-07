//! The README's synopsis must name the verbs the CLI actually has.
//!
//! **This exists because the README documented a CLI that never existed on this revision.**
//! Its synopsis and its one worked example were both:
//!
//! ```text
//! strands-box [--config <path> | --policy <path>] [--name <name>] -- <workload> [args...]
//! ```
//!
//! There is no verbless form. Running it prints `error: unexpected argument '--policy'
//! found`, so an operator following the README got a usage error before anything ran. The
//! verbs arrived with the box restructure and the README kept the pre-restructure shape.
//!
//! Two directions are checked, because the earlier README failures were one of each: it
//! *advertised* a form the parser rejects, and it *omitted* `cp` entirely.

use std::path::Path;

/// Read the `Command` enum's variants out of the argv parser's source.
fn declared_verbs(config: &str) -> Vec<String> {
    let body = config
        .split_once("pub(crate) enum Command {")
        .expect("cli.rs declares `enum Command`")
        .1
        .split_once("\n}")
        .expect("the enum closes")
        .0;
    body.lines()
        .filter_map(|line| {
            let name = line
                .trim()
                .strip_suffix(" {")
                .or(line.trim().strip_suffix(','))?;
            // A variant name is one CamelCase word here; skip attributes and doc comments.
            (!name.is_empty()
                && name.starts_with(|character: char| character.is_ascii_uppercase())
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphabetic()))
            .then(|| name.to_ascii_lowercase())
        })
        .collect()
}

/// The README's synopsis block names exactly the CLI's verbs, and no others.
#[test]
fn the_readme_synopsis_names_every_verb_and_only_real_verbs() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(crate_root.join("README.md")).expect("read README.md");
    // `src/command/cli.rs`, which owns the clap derives. They lived in `config.rs` until the
    // argv parser was split out of it; this read followed them.
    let config =
        std::fs::read_to_string(crate_root.join("src/command/cli.rs")).expect("read cli.rs");

    let verbs = declared_verbs(&config);
    assert!(
        verbs.contains(&"run".to_string()) && verbs.contains(&"policy".to_string()),
        "the variant reader found neither `run` nor `policy`, so it is matching nothing \
         and this test would pass vacuously: {verbs:?}"
    );

    // Every `strands-box <verb>` the README spells, anywhere in the file.
    let mut documented = Vec::new();
    for line in readme.lines() {
        for (index, _) in line.match_indices("strands-box ") {
            let rest = &line[index + "strands-box ".len()..];
            let word = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches(|character: char| !character.is_ascii_alphabetic());
            if !word.is_empty() && word.chars().all(|character| character.is_ascii_lowercase()) {
                documented.push(word.to_string());
            }
        }
    }

    // `help` is clap's own and needs no documenting; `daemon`, if present, is internal.
    let expected: Vec<&String> = verbs
        .iter()
        .filter(|verb| *verb != "help" && *verb != "daemon")
        .collect();
    for verb in &expected {
        assert!(
            documented.iter().any(|word| word == *verb),
            "the CLI has a `{verb}` verb the README never spells — an operator cannot \
             discover it. Documented: {documented:?}"
        );
    }

    // The other direction: the README must not advertise a verb the parser rejects. This is
    // the failure that shipped — the synopsis had no verb at all where one is required.
    for word in &documented {
        // Words that follow `strands-box` in prose rather than in a command line.
        if ["daemon", "help", "executable", "run-alias", "sock-alias"].contains(&word.as_str()) {
            continue;
        }
        assert!(
            verbs.iter().any(|verb| verb == word),
            "the README spells `strands-box {word}`, which is not a verb the parser \
             accepts — an operator copying it gets a usage error. Real verbs: {verbs:?}"
        );
    }
}
