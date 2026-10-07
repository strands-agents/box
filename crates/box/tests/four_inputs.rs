//! The four-input rule, enforced rather than asserted in prose.
//!
//! `box/AGENTS.md` says `--work-dir`, `--bind`, `--read-path`, and `--home` "must keep
//! reaching the workload as its own argv; the test asserting that is the guard on this
//! rule, not a formality." **That test did not exist.** The crate contract named a guard
//! nobody had written, so the rule was a convention with a citation.
//!
//! It was found while a design decision was claiming the rule "survived the library surface
//! unamended, and the guard test needed no edit" — which was trivially true of a test
//! that was never written. The claim is only worth making if the guard exists, so here
//! it is.
//!
//! Reads the argv parser's source rather than invoking the binary, because the assertion
//! is about which flags box *declares*.
//!
//! **Both tests are proven to fire, and each catches what the other misses.** Measured by
//! injecting a fifth field into `ConfigFile`, once per spelling:
//!
//! | Injected field | `the_withheld_flags_…` | `the_config_record_…` |
//! |---|---|---|
//! | `pub(crate) work_dir: Option<PathBuf>` | **fails**, naming `--work-dir` | **fails** |
//! | `mount: Option<PathBuf>` | passes | **fails**, printing the five-field list |
//! | `pub(crate) mount: Option<PathBuf>` | passes | **fails** |
//!
//! Neither test subsumes the other. The first knows the four withheld flag names and
//! nothing else, so a fifth input under an unlisted name walks past it. The second knows
//! only the expected field list, so it catches any new field but cannot say which rule the
//! field breaks. Keep both.
//!
//! **The third row is there because it used to read `passes | passes`.** This test kept its
//! own field extractor, which split on the first `:` — so `pub(crate) mount:` produced
//! `"pub(crate) mount"`, failed the lowercase filter, and was dropped without a word. A
//! fifth input in the spelling `config.rs` actually uses for its fields evaded *both*
//! guards, in the file whose own header calls that spelling load-bearing. It now calls
//! `parser_source::fields_of`, which takes the last token before the colon.
//!
//! # The configuration holds eight keys, and the four inputs still stand
//!
//! `policy` and credentials are authority, `name` and `box_dir` select state, and `[agent] command`
//! plus the trailing argv select the workload. `[mcp]`, `[telemetry]`, and `[tool]` are keys and not
//! additional inputs: none decides which requests are governed.
//!
//! `[agent] env` names variables the box adds to the composed environment. It cannot name a
//! reserved variable, so it cannot reach proxy routing, CA trust, or the fixed identity, and it
//! makes no path reachable. `[agent.filesystem]` IS reach the policy does not judge, disclosed on
//! stderr at startup; it grants no authority over which requests are governed.
//!
//! `mcp` declares which local MCP servers exist, with a program and its argv. The configuration
//! selects which servers can start, and `shell:spawn` decides each start. `mcp:call` decides each
//! request on the stream the server answers. An entry selects and identifies; it grants no request on its own.
//!
//! **The sharpest thing about `mcp` is where it lives.** The trusted `run` process starts the
//! declared program outside containment. The selected configuration is loaded as an authority
//! source, and both interpreters refuse mutations to that filesystem identity.
//!
//! `[[bind]]` was the previous fifth key and is gone. The shared operator home removed the case
//! for it: both interpreters already see the whole home beneath the deny floor, so there is
//! nothing left for a bind to make reachable.
//!
//! `configuration_keys_are_not_command_line_flags` carries the other half — **no `--env`,
//! `--credential`, or `--bind` flag, and none of them on the argv parser.** It is a separate test
//! because the field-name sweep scans the whole file, so it cannot tell a record's key from a flag.
//!
//! # What this does NOT cover
//!
//! Both tests read the **CLI parser and the TOML record**. They guard the process interface.
//! Runtime tests separately prove that the selected configuration supplies the state and workload
//! paths.

use std::path::Path;

#[path = "support/parser_source.rs"]
mod parser_source;

use parser_source::fields_of;

/// None of the four withheld flags may become an argument box parses.
///
/// Each names a host path or a mechanism value, and each must reach the workload as its
/// own argv. If box ever declares one, the boundary gained a fifth input.
#[test]
fn the_withheld_flags_are_not_box_arguments() {
    // **Two surfaces, each read as itself.** A raw line sweep over the whole config source reported
    // `--home` because `target_for` takes a private parameter spelled `home: Option<&Path>`. A
    // function parameter is not an input, so the flag half reads the argv parser and the key half
    // reads the record field lists.
    let cli = parser_source::cli_source();
    let config = parser_source::config_source();
    let keys: Vec<String> = [
        "struct ConfigFile {",
        "pub(crate) struct Record {",
        "pub(crate) struct ProcessSpec {",
        "pub(crate) struct Filesystem {",
        "pub(crate) struct EgressEntry {",
    ]
    .iter()
    .flat_map(|declaration| fields_of(&config, declaration))
    .collect();
    assert!(
        keys.iter().any(|key| key == "policy"),
        "the field reader found nothing, so this passes vacuously: {keys:?}"
    );

    // `bind` is absent from this list because it is now a config key.
    for withheld in ["work-dir", "read-path", "home"] {
        let underscored = withheld.replace('-', "_");
        // clap derives a long flag from the field name, so either spelling shows up.
        let declared_as_a_flag = cli.lines().any(|line| {
            let line = line.trim();
            line.contains(&format!("long = \"{withheld}\""))
                || line
                    .trim_start_matches("pub ")
                    .trim_start_matches("pub(crate) ")
                    .starts_with(&format!("{underscored}:"))
        });
        assert!(
            !declared_as_a_flag,
            "box declares `--{withheld}`, which names a host path or a mechanism value. The four \
             inputs are policy, credentials, name, and workload; this would be a fifth. It must \
             reach the workload as its own argv instead."
        );
        assert!(
            !keys.contains(&underscored),
            "a record carries `{underscored}`, which names a host path or a mechanism value, so it \
             would be a fifth input under a config key rather than a flag."
        );
    }
}

/// The wire record carries exactly the four inputs and nothing else.
///
/// `ConfigFile` is `deny_unknown_fields`, so its field set *is* the operator-facing
/// surface. A fifth field is a fifth input whatever it is called.
/// **The stored record carries every key the authored file accepts.**
///
/// The two types declare one document shape twice — all ten field names are shared — so a key
/// added to `ConfigFile` and forgotten in `Record` is silently dropped when `configure` stores the
/// box. The operator's setting vanishes with no refusal, and nothing observed it until this test.
///
/// They are not mergeable: `Record` must carry a `version` and an authored file must not, and serde
/// refuses `#[serde(flatten)]` beside `deny_unknown_fields`. So the agreement is asserted instead.
#[test]
fn the_stored_record_carries_every_authored_key() {
    let config = parser_source::config_source();
    let authored = fields_of(&config, "struct ConfigFile {");
    let stored = fields_of(&config, "pub(crate) struct Record {");

    // A reader matching nothing would pass vacuously on both sides.
    assert!(
        authored.contains(&"policy".to_string()) && stored.contains(&"policy".to_string()),
        "the field reader found nothing: authored={authored:?} stored={stored:?}"
    );

    for key in &authored {
        assert!(
            stored.contains(key),
            "`Record` has no `{key}`, so `configure` drops that authored key and the operator's \
             setting disappears with no refusal: authored={authored:?} stored={stored:?}"
        );
    }

    // The record's one addition, which is what makes a stale format a refusal.
    assert!(
        stored.contains(&"version".to_string()),
        "`Record` must carry `version`, or a record written by an older build loads silently"
    );
}

#[test]
fn the_config_record_carries_only_the_four_inputs() {
    let config = parser_source::config_source();

    // The field list is only the operator-facing surface because unknown keys are
    // refused. Assert that, or this test passes with its premise removed.
    assert!(
        config.contains("#[serde(deny_unknown_fields)]"),
        "ConfigFile must keep `deny_unknown_fields`, or its field set stops being the \
         whole config surface and a fifth input can arrive unnamed"
    );

    // Uses the shared extractor rather than a local one. The local version split on the
    // first `:`, so a field spelled `pub(crate) mount:` yielded `"pub(crate) mount"`, failed
    // the lowercase filter, and was silently dropped — a fifth input walked past this test
    // and past the flag-name test above. `fields_of` takes the last token before the colon,
    // which is why it sees the visibility-qualified spelling.
    let mut fields = fields_of(&config, "struct ConfigFile {");
    fields.sort_unstable();

    assert_eq!(
        fields,
        [
            "agent",
            "box_dir",
            "egress",
            "mcp",
            "name",
            "policy",
            "telemetry",
            "tool"
        ],
        "the config record must carry exactly these eight keys. `policy` and `egress` are \
         authority, `name` and `box_dir` are state, `agent` is the workload, `tool` is every \
         host binary the Shell may start, and `mcp` and `telemetry` grant no reach. A process's \
         `filesystem` lists ARE reach the policy does not judge — that is the whole of what they \
         buy, so they are argued rather than hidden: an unmodified coding agent's `Read`, `Write`, \
         and `Edit` issue direct syscalls, and containment denied every one. They are not a fifth \
         *input*, because they grant no authority over which requests are governed: every access \
         the Strands Shell and Monty make is still an `fs:*` decision on the one Policy, the \
         deny-only floors still sit beneath them, and absent lists grant nothing. What they cost \
         is stated in the startup disclosure the box prints for every grant they name. A NINTH \
         field changes the input contract and must update this guard."
    );
}

/// **`telemetry` is a config key and not a fifth input, and this states the argument.**
///
/// The test for an input is **authority**, not spelling: does the key decide which requests are
/// governed, or grant the workload reach the policy does not judge? `telemetry` does neither.
///
/// - **It is a destination, not a decision.** Every target names where records go. No target can
///   make a request permitted, refuse one, or change which gate answers. `Collector::record` runs
///   after the effective decision and returns nothing, so a recorder cannot move one.
/// - **It grants the workload no reach.** The records leave the box's own trusted process. They
///   land under the box root, which `ReachFloor` refuses to the workload whatever a `permit` says,
///   or at an operator-named destination the workload cannot see. The collector's port is a
///   *producer*: the agent posts and reads back one constant, so the port discloses nothing.
/// - **Its secret is a reference, exactly as `[egress.a]`'s is.** `env://NAME` or `secret://NAME`,
///   never a value, and the box resolves it in its own process. The workload's composed
///   environment carries the endpoint and no credential.
///
/// What would make it an input, and each is refused elsewhere: a destination the *workload* could
/// choose (`materialize_box_keys` drops the key, asserted below); a value pasted into the file
/// (`telemetry_secret_name` refuses a reference with no scheme); or a target that could suppress a
/// record (there is no such shape — the collector has no route that removes one).
#[test]
fn telemetry_names_a_destination_and_grants_nothing() {
    let config = parser_source::config_source() + &parser_source::cli_source();

    // No flag, for the reason every other configuration key has none: the file and the typed line
    // must not give two answers about one box.
    assert!(
        !config.contains("long = \"telemetry\""),
        "box declares `--telemetry`. This is configuration, so it belongs in the file an operator \
         reviews rather than on a line a caller varies per run."
    );

    // A reference, never a literal. `box.toml` sits inside the workspace it governs.
    assert!(
        config.contains("fn telemetry_secret_uri"),
        "the secret reference must go through one normalizer, or a pasted vendor key reaches the file"
    );
    for scheme in ["ENV_SCHEME", "TELEMETRY_ALIAS_SCHEME"] {
        assert!(
            config.contains(scheme),
            "the normalizer must name the {scheme} constant rather than re-spelling a literal"
        );
    }

    // **The value is dereferenced through `credentials`, not through `std::env::var`.** That is the
    // stronger property, and the one that matters: the `env://` source carries a denylist —
    // `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `LD_PRELOAD` and the rest — and reading the
    // variable directly bypassed it, so `secret://AWS_SECRET_ACCESS_KEY` resolved and shipped the
    // operator's AWS key to a vendor endpoint. Asserted on the source rather than behaviourally,
    // because a behavioural test proves only that today's build refuses today's names.
    // Scoped to the function by its closing brace at that indent, not by a character count. A count
    // is what made the first version of this check pass or fail on how long a comment was.
    // Anchored on `resolved_secret`, which is where the resolve lives: `config_for` used to hold
    // it inline, and both copies then derived the target by hand until they drifted.
    let telemetry_block = config
        .split_once("fn resolved_secret")
        .expect("record/config/telemetry.rs declares `fn resolved_secret`")
        .1;
    let telemetry_block = telemetry_block
        .split_once("\n}\n")
        .expect("the function closes")
        .0;
    assert!(
        telemetry_block.contains("Backend::local()") && telemetry_block.contains("Locator::"),
        "a telemetry secret must resolve through `credentials`, which owns the `env://` denylist"
    );
    // **Comment lines are stripped first.** The code carries a comment naming `std::env::var` to say
    // it is NOT used, and a raw substring sweep read that as the call it forbids — the check failed
    // on its own documentation. Every absence assertion over source text needs this.
    let telemetry_code: String = telemetry_block
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !telemetry_code.contains("std::env::var"),
        "reading the variable directly bypasses that denylist, which is how an ambient AWS \
         credential became exfiltrable through a vendor header"
    );

    // The observer reports and returns nothing, so it cannot be a second authority. Read from
    // policy's own source, because that is where the seam is declared.
    let observe = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../policy/src/observe.rs"),
    )
    .expect("read policy's observe.rs");
    // **One exact signature, not an `A || B`.** The earlier form accepted either an old shape or
    // the substring `"decision: &Decision);"`, and the old shape stopped existing — so the whole
    // assertion rested on a substring that matches any declaration ending that way, including one
    // that adds `Request<'_>` back or takes extra arguments. It pinned nothing it claimed to.
    assert!(
        observe.contains("fn observed(&self, action: &str, resource: &str, decision: &Decision)"),
        "the observer must receive the action, the resource and a `&Decision`, and return nothing, \
         or it becomes a second authority that can substitute a verdict: {observe}"
    );
    // It must not receive the request itself, or it could re-read what was judged.
    assert!(
        !observe.contains("request: &Request"),
        "the observer takes the action and resource already extracted, never the `Request`: \
         {observe}"
    );
}

/// `[env]` and `[[credential]]` are config keys; neither is a command-line flag.
///
/// **The file and the typed line must not give two answers about one box.** `run` needs no
/// argument beyond the program, so authority that varies per box belongs in the file an operator
/// reviews and checks in. A flag would let a caller vary it per invocation, which is how a config
/// key becomes a fifth *input*.
///
/// The field-name sweep above cannot state this, because it reads the whole of `config.rs` and a
/// record's own field would satisfy it. This one reads the argv parser alone.
///
/// This replaced the same pairing over `[[bind]]`. That key is gone: the shared operator home
/// means the interpreters already see the whole home beneath the deny floor, so there is nothing
/// left for a bind to make reachable. The half of the rule that survives is asserted below — no
/// `bind` on the record and none on the parser.
#[test]
fn configuration_keys_are_not_command_line_flags() {
    // Both files, for the reason `the_withheld_flags_are_not_box_arguments` states: a flag
    // declaration in `cli.rs` must not escape a scan of `config.rs`.
    let config = parser_source::config_source() + &parser_source::cli_source();

    for withheld in ["env", "egress", "credential", "bind", "mcp"] {
        assert!(
            !config.contains(&format!("long = \"{withheld}\"")),
            "box declares `--{withheld}`. This is configuration, so it belongs in the file an \
             operator reviews rather than on a line a caller varies per run."
        );
    }

    // The argv parser's own declarations. A field on a *record* must not vouch for one on the
    // command line, which is the whole reason this check is scoped.
    let parser = config
        .split_once("pub(crate) enum Command {")
        .expect("cli.rs declares `enum Command`")
        .1
        .split_once("\n}\n")
        .expect("the enum closes")
        .0;
    // Matched as a field token rather than as a substring, because a doc comment mentioning one
    // of these words would otherwise report a declared argument.
    for withheld in ["env", "credential", "credentials", "bind"] {
        assert!(
            !parser.split_whitespace().any(|token| {
                let token = token.trim_end_matches(',');
                token == format!("{withheld}:") || token == format!("\"{withheld}\"")
            }),
            "the argv parser declares `{withheld}`. It is configuration, never a flag or a \
             positional."
        );
    }
}
