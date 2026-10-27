# cargo-report pack corpus

Each row is one command line, and what the shell grammar of `../valid/cargo-report.pack.toml` reads
it as. `Fields` lists, in TOML, each field that does not hold its default: a Bool `false`, an
empty set, or an absent string. `—` means none. An `unmodeled` row has no fields and no effects.

| Command line | Action | Fields | Effects | Note |
|---|---|---|---|---|
| `cargo version` | version | — | — | An action with no global options |
| `cargo --config net.offline=true version` | unmodeled | — | — | A global option before an action whose usage has no `[global options]` |
| `cargo +stable version` | unmodeled | — | — | A toolchain before an action whose usage has no `[+<toolchain>]` |
| `cargo report other` | report | kind = "other" | — | The shorter spelling, with an operand |
| `cargo report future-incompatibilities --id 3` | report_future_incompatibilities | id = "3" | network | The longest spelling, and not `report` with an operand |
| `cargo report -q future-incompatibilities` | report_future_incompatibilities | quiet = true | network | An `anywhere` option between the command words |
| `cargo +stable report future-incompatibilities` | unmodeled | — | — | The longest spelling has no `[+<toolchain>]` |
| `cargo +stable report` | report | toolchain = "stable" | — | A toolchain before an action that has one |
