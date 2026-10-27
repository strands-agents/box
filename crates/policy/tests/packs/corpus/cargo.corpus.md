# cargo pack corpus

Each row is one command line, and what the shell grammar of `../valid/cargo.pack.toml` reads
it as. `Fields` lists, in TOML, each field that does not hold its default: a Bool `false`, an
empty set, or an absent string. `—` means none. An `unmodeled` row has no fields and no effects.
Rows marked "verified" were checked against cargo 1.98.

| Command line | Action | Fields | Effects | Note |
|---|---|---|---|---|
| `cargo test` | test | — | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo t` | test | — | execute_built_code, network, run_build_scripts, update_lockfile | An alias. A `[alias] t` in `.cargo/config.toml` can redefine `t`, and the parser cannot see it (L1) |
| `cargo +stable test` | test | toolchain = "stable" | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo +nightly -Zunstable-options t --locked` | test | locked = true, toolchain = "nightly", unstable = ["unstable-options"] | execute_built_code, network, run_build_scripts |  |
| `cargo --locked build` | build | locked = true | network, run_build_scripts | A global option before the command |
| `cargo build --locked` | build | locked = true | network, run_build_scripts | An `anywhere` global option after the command |
| `cargo test --frozen` | test | frozen = true | execute_built_code, run_build_scripts |  |
| `cargo build --offline` | build | offline = true | run_build_scripts, update_lockfile | `--offline` alone can still rewrite Cargo.lock |
| `cargo b -r -p strands-box` | build | package = ["strands-box"], release = true | network, run_build_scripts, update_lockfile |  |
| `cargo build -rp strands-box` | build | package = ["strands-box"], release = true | network, run_build_scripts, update_lockfile |  |
| `cargo build -p=strands-box` | unmodeled | — | — | Short value option with `=` (clap reads `strands-box`, verified; git would read `=strands-box`) |
| `cargo build --manifest-path=crates/x/Cargo.toml` | build | manifest_path = "crates/x/Cargo.toml" | network, run_build_scripts, update_lockfile |  |
| `cargo --manifest-path x/Cargo.toml build` | unmodeled | — | — | Not a global option; cargo refuses it too (verified) |
| `cargo test -p box --all-features -- --nocapture` | test | all_features = true, package = ["box"], test_args = ["--nocapture"] | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo test parser -- --test-threads=1` | test | test_args = ["--test-threads=1"], testname = "parser" | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo test foo bar` | unmodeled | — | — | Too many operands: `[-- <test_args>...]` is reached only after `--` (cargo: "unexpected argument", verified) |
| `cargo test --no-run` | test | no_run = true | network, run_build_scripts, update_lockfile |  |
| `cargo test -F a,b -F c` | test | features = ["a,b", "c"] | execute_built_code, network, run_build_scripts, update_lockfile | Values are not split |
| `cargo test --relea` | unmodeled | — | — | No prefix matching (cargo refuses it too, verified) |
| `cargo run --release -- --port 8080` | run | program_args = ["--port", "8080"], release = true | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo run app --release` | run | program_args = ["--release", "app"] | execute_built_code, network, run_build_scripts, update_lockfile | From the first operand on, every word goes to the program, so the build is not a release build (verified) |
| `cargo run -- -- y` | run | program_args = ["--", "y"] | execute_built_code, network, run_build_scripts, update_lockfile | The first `--` is the separator (verified) |
| `cargo r --bin server` | run | bin = "server" | execute_built_code, network, run_build_scripts, update_lockfile |  |
| `cargo update` | update | — | network, update_lockfile |  |
| `cargo update -p serde --precise 1.0.200` | update | package = ["serde"], precise = "1.0.200" | network, update_lockfile |  |
| `cargo update serde tokio` | update | spec = ["serde", "tokio"] | network, update_lockfile |  |
| `cargo update -n` | update | dry_run = true | network |  |
| `cargo update --locked` | update | locked = true | network | Cargo then refuses to write |
| `cargo add serde -F derive` | add | dependency = ["serde"], features = ["derive"] | modify_manifest, network, update_lockfile |  |
| `cargo add --locked tokio` | add | dependency = ["tokio"], locked = true | modify_manifest, network |  |
| `cargo add --dry-run anyhow` | add | dependency = ["anyhow"], dry_run = true | network |  |
| `cargo add` | unmodeled | — | — | Required operand `<dependency>...` missing |
| `cargo add evil --git https://example.com/evil.git` | add | dependency = ["evil"], git = "https://example.com/evil.git" | modify_manifest, network, update_lockfile |  |
| `cargo rm serde` | remove | dependency = ["serde"] | modify_manifest, update_lockfile |  |
| `cargo publish` | publish | — | network, publish_crate, run_build_scripts |  |
| `cargo publish -n` | publish | dry_run = true | network, run_build_scripts | `-n` (verified) |
| `cargo publish --dry-run --no-verify` | publish | dry_run = true, no_verify = true | network |  |
| `cargo install ripgrep --locked` | install | crate = ["ripgrep"], locked = true | install_binary, network, run_build_scripts |  |
| `cargo install --list` | install | list = true | — |  |
| `cargo clippy --all-targets -- -D warnings` | clippy | all_targets = true, clippy_args = ["-D", "warnings"] | network, run_build_scripts, update_lockfile |  |
| `cargo clippy --fix --allow-dirty` | clippy | allow_dirty = true, fix = true | modify_sources, network, run_build_scripts, update_lockfile |  |
| `cargo fmt` | fmt | — | modify_sources |  |
| `cargo fmt --check` | fmt | check = true | — |  |
| `cargo fmt -- --check` | fmt | rustfmt_args = ["--check"] | — | A `when` entry on an operand |
| `cargo -vv test` | test | verbose = true | execute_built_code, network, run_build_scripts, update_lockfile | A flag with no value, given twice in one cluster |
| `cargo --config 'build.rustc-wrapper="/tmp/x"' build` | build | config = ['build.rustc-wrapper="/tmp/x"'] | network, override_config, run_build_scripts, update_lockfile |  |
| `cargo build --config net.offline=true` | build | config = ["net.offline=true"] | network, override_config, run_build_scripts, update_lockfile | The parser does not read config values: update_lockfile stays |
| `cargo -v +stable test` | unmodeled | — | — | `+<toolchain>` is honoured only as the first argument (rustup) |
| `cargo -C sub build` | build | directory = "sub" | network, run_build_scripts, update_lockfile | Cargo refuses without nightly `-Z unstable-options`, verified; harmless |
| `cargo build -C sub` | unmodeled | — | — | `-C` is before-only (cargo: "unexpected argument", verified) |
| `cargo tset` | unmodeled | — | — | An unknown subcommand |
| `cargo nextest run` | unmodeled | — | — | External subcommand `cargo-nextest` |
| `cargo build -- x` | unmodeled | — | — | Build has no operands |
| `cargo + test` | unmodeled | — | — | An empty toolchain |
| `cargo +stable` | unmodeled | — | — | A toolchain and no command word |
| `cargo test -vq` | test | quiet = true, verbose = true | execute_built_code, network, run_build_scripts, update_lockfile | `anywhere` global options in a cluster after the command |
