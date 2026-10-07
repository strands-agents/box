<!-- Modified by Amazon. Original source: https://github.com/strands-agents/shell. Local changes are recorded in crates/shell/UPSTREAM.md. -->

# AGENTS.md

This document provides context, patterns, and guidelines for AI coding assistants working in this repository. For human contributors, see [CONTRIBUTING.md](./CONTRIBUTING.md).

> **Reading this inside `box`?** This directory is a *vendored* copy of the upstream `strands-shell` crate at a pinned revision. It carries the Rust crate (`src/`, `tests/`, `strands-shell-macros/`) and nothing else: the `python/` wrapper, `tests/python/`, `scripts/`, and `.github/` are not vendored, so the commands and paths in the Python, WASM, and CI sections below describe the upstream repository rather than this tree. Read [`UPSTREAM.md`](./UPSTREAM.md) for the pinned revision, what is excluded, and every local change to the vendored source.

## Product Overview

**Strands Shell** is a Bourne-compatible shell for AI agents that runs entirely in-process. It implements a complete operating-system environment inside a single userspace process — inspired by BusyBox and Toybox — but it never calls `fork`/`exec` or makes direct system calls. Every operation flows through a pluggable `Kernel` trait, giving callers fine-grained control over what an agent can see and do (files, network destinations) without containers, microVMs, or firewalls.

It is a Rust crate that compiles to several targets from one source of truth:

- **Native binary** (`strands-shell`) and a Rust library
- **Python** extension module (`strands-shell` on PyPI), via [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/)
- **Node.js** native addon (`@strands-agents/shell` on npm), via [napi-rs](https://napi.rs/)
- **WASM** module targeting `wasm32-wasip2`

## Architecture

The crate is the single source of truth; every binding wraps the same core.

- **`Kernel` trait (`src/os.rs`) is the security boundary.** All filesystem, process, and network effects go through a `Kernel` implementation. There is no `fork`/`exec` and no direct syscalls. The bundled implementation is `VfsKernel` (`src/vfs_kernel.rs`), backed by an in-process virtual filesystem (`src/vfs.rs`); callers can supply their own (S3-backed, database-backed, etc.) via `Shell::builder().kernel(...)`, which applies the builder's limits to the resulting shell.
- **In-process VFS with binds.** Directories are mounted into the VFS as *binds* — `copy` mode snapshots files into the VFS at build time; `direct` mode passes reads/writes through to the host, mediated by the kernel. Bind configuration lives in `src/vfs_config.rs`.
- **Commands are split in two:**
  - **Builtins** in `src/builtins/` — things that mutate shell state (`cd`, `export`, `alias`, `set`, control-flow helpers, etc.). They are dispatched by name in `src/builtins/mod.rs` (`lookup()` matches the builtin name to its function).
  - **Isolated commands** in `src/commands/` — coreutils-style programs (`cat`, `grep`, `sed`, `curl`, `jq`, …) that take a mediated kernel handle (`&Mediated`) plus args and produce output. Each is registered with the `#[command("name")]` proc-macro from `strands-shell-macros`.
- **Parser / executor:** `src/parser.rs` parses shell syntax; `src/exec.rs` evaluates it (pipelines, redirections, expansions, control flow).
- **Bindings:** `src/python.rs` (PyO3, the `strands_shell._native` module) and `src/js.rs` (napi-rs). They are intentionally parallel in shape — keep them in sync semantically. The customer-facing Python surface (the `Shell`, `Bind`, `Cred`, `Limits` classes and typed errors) lives in the pure-Python wrapper at `python/strands_shell/__init__.py`.
- **WASM entry:** `src/wasm_main.rs` reads commands from WASI stdin and writes to WASI stdout/stderr; each instance runs in isolated linear memory.
- **MCP:** `src/mcp.rs` is the built-in MCP *server* (exposes the shell as tools); `src/mcp_client.rs` is the MCP *client* (servers configured under `[[mcp]]` become Lua modules).

### The `#[command(...)]` macro

A new isolated command is a function annotated with the proc-macro:

```rust
#[command("ls")]
async fn cmd_ls(os: &Mediated, args: &[String]) -> CommandResult {
    // ...
    Ok(0)
}
```

The first parameter is `&Mediated` (`src/mediate.rs`), not a bare `&dyn Kernel`: a
command reaches the kernel only through the admission layer. The return type is
`CommandResult` — `Result<i32, Box<dyn Error + Send + Sync>>` (`src/commands/mod.rs`).

The macro (defined in `strands-shell-macros/src/lib.rs`) registers the command via `inventory` on native targets and feeds the static lookup table used on WASM. Builtins are *not* registered this way — add them to the `match` in `src/builtins/mod.rs`.

## Build & Test Commands

Use the same commands as [CONTRIBUTING.md](./CONTRIBUTING.md#development-environment) so they don't drift. The Rust toolchain is required for every workflow because all bindings build from the crate.

### Rust (shell core)

```bash
cargo build                              # build the library and binaries
cargo test --workspace --all-targets     # unit + integration tests
cargo fmt                                # format
cargo clippy --workspace --all-targets   # lint
cargo doc --workspace --no-deps --open   # API reference
```

Integration tests live in `tests/`: `shell_integration.rs`, `curl_integration.rs`, `lua_integration.rs`, `mcp_integration.rs`, `vfs_unit.rs`, `config.rs`, `effect_interceptor.rs`, `kernel_effect_interception.rs`, `in_mount_symlink_admission.rs`, and `channel_writer_inheritance.rs`. Three of them cover the admission seam — `effect_interceptor.rs`, `kernel_effect_interception.rs`, and `in_mount_symlink_admission.rs`. Read those three before you change `src/mediate.rs` or `src/effect.rs`. `channel_writer_inheritance.rs` covers a different thing: a caller's channel writer must reach a builtin's output.

### Python bindings

```bash
python -m venv .venv && source .venv/bin/activate
pip install maturin pytest
maturin develop --features python        # build + install into the venv
pytest tests/python -v                   # run the Python test suite
```

Python sources are under `python/strands_shell/`; the compiled module is `strands_shell._native`. Tests: `tests/python/*.py`.

### Node.js bindings

```bash
npm install            # install dependencies
npm run build          # release build of the native addon
npm run build:debug    # faster debug build for local development
npm test               # run the Node.js test suite (tests/js/*.mjs)
```

### WASM module

```bash
./scripts/build-wasm.sh --release        # needs wasi-sdk >= 32
```

See [CONTRIBUTING.md](./CONTRIBUTING.md#wasm-module) for which features are available under WASM (no PyO3, no MCP server, no `--config`). WASM is a build target, not a published release artifact.

### CI merge gate

`.github/workflows/ci.yml` runs the Rust suite (`cargo test --workspace --all-targets` + `cargo doc` with `-D warnings`) across Linux/macOS, the Python matrix (`maturin develop --release` + `pytest tests/python`), the Node matrix (`npm run build:debug` + `npm test`), and a security-audit job. Don't open a PR with known failures in the bindings you touched.

## Key Conventions

### Rename scope — the `lash` persona is intentional, do NOT rename it

The identifiers `lash`, `/bin/lash`, `USER=lash`, `/home/lash`, `LASH_UID`, and `LASH_GID` are an **intentional emulated-POSIX persona**. They define the *simulated* Unix environment the shell presents to commands and scripts — the default user, home directory, and uids/gids inside the VFS — not the product name. **Do not "fix" them to `strands-shell`.** They appear by design in `src/os.rs`, `src/vfs.rs`, `src/vfs_config.rs`, and `src/vfs_kernel.rs`. Renaming them changes the emulated environment and breaks tests and scripts that expect a stable POSIX identity.

The product is "Strands Shell"; the simulated Unix user is "lash". These are different things and both are correct.

### Imports

All `use` statements go at the **top of the file** (Rust modules, Python wrapper, JS tests alike). Do not move imports into functions.

### Adding commands

- A coreutils-style command goes in `src/commands/` and is registered with `#[command("name")]`.
- A state-mutating builtin goes in `src/builtins/` and is added to the `lookup()` match in `src/builtins/mod.rs`.
- If a command should appear under WASM too, make sure it's reachable through the WASM lookup path (the macro handles native registration via `inventory` automatically).

### Bindings stay in sync

`src/python.rs` and `src/js.rs` mirror each other. A change to one binding's surface (new method, renamed argument, error mapping) should be reflected in the other unless there's a language-specific reason not to. Node methods are camelCase and return Promises; bytes are `Uint8Array`. Python methods are snake_case; bytes are `bytes`.

### Match surrounding style

Make the smallest reasonable change. Prefer simple, clean solutions over clever ones. Match the formatting of surrounding code. Comments explain *what* the code does or *why* it exists — never temporal context ("recently changed", "used to be"). Run `cargo fmt` and `cargo clippy` on any Rust you touch.

## Security-Sensitive Code

Strands Shell is an **in-process mediation layer**: the `Kernel` boundary is the whole product. Treat changes to the following as security-critical and preserve their guarantees:

- **`src/commands/curl.rs`** and HTTP request handling — `curl`/`http_request` must keep blocking SSRF and metadata-service access (RFC1918, link-local, loopback, IMDS/ECS-task-role) both up front in `check_url_safe` and at DNS-resolution time via `SafeResolver`.
- **`src/mediate.rs`** — the admission layer, and the only route to a `Kernel`. It resolves each path, presents the effect, then acts on the *same* resolved identity. Admission lives here rather than in a kernel so that a caller-supplied kernel is governed identically; do not add a path that reaches the trait around it.
- **`src/vfs_kernel.rs`** (incl. `SafeResolver` and bind-path mediation) — file access must stay confined to explicitly bound paths; `readonly` and `direct`/`copy` semantics must hold. It performs effects and authorizes nothing. A consumer depends on the `direct`/`copy` distinction: `strands-box` always builds with `bind_direct`, and `verify_direct_binds` refuses to start when a realized bind is not Direct. `bind`'s `Copy` default is correct for upstream and wrong there, because a snapshot diverges from a home the workload and a second interpreter are both editing.
- **The effect seam** (`src/effect.rs`) — every effect is presented for admission before it happens, and admission is the only authorization authority. `Kernel`'s path methods take `Resolved`, which only `Kernel::resolve` can mint, so an unresolved path cannot reach an effect. Do not add a path-taking trait method over `&str`. The shell holds no allowlist and no credentials of its own. **The Shell raises no network attempt, deliberately.** `EffectAttempt` has four variants — `ShellRun`, `ShellSpawn`, `Filesystem`, and `FilesystemPair` — and no network variant. Egress authorization belongs to the boundary the workload is confined to, so one request yields one decision. There is also **no `HttpTransport` seam.** `src/os.rs` states the reason in place of the seam: a trait every embedding must wire up correctly can route anywhere, including around the boundary it exists to enforce. Two network controls remain in the kernel and neither authorizes anything — the embedder's blanket `network_enabled` switch (`ShellBuilder::disable_network`) and the SSRF floor, both deny-only and both unconditional.

A bypass of filesystem mediation, the effect-admission seam, or SSRF protection is a **security issue**, not a normal bug. If you find or risk one, follow [SECURITY.md](./SECURITY.md) — do not open a public issue, and never weaken these controls to make a test pass.

### One decision on the resolved command, and `shell:exec` is gone

The old single `shell:exec` action is **removed, not renamed**, and two actions on the
**resolved** command replace it. These are this crate's effect labels; the box maps `shell:run`
to its Cedar action `shell:exec`, and `shell:spawn` keeps its name.

- **`shell:run`** — the decision when the Shell implements the resolved program.
- **`shell:spawn`** — the decision when it does not and a host binary runs instead
  (`src/effect.rs`, `EffectAttempt::ShellSpawn`, raised through the passthrough path). A
  `permit` naming it grants the binary the kernel rather than this Shell's VFS, so no `fs:*`
  attempt is raised for what it does.

The two are mutually exclusive: one resolved command line raises exactly one of them.
`EffectAttempt::ShellRun` carries `command`, `program`, `args`, and `cwd`; `ShellSpawn` adds a
required `program_path`. `command` is the canonical line rebuilt from the **expanded** words,
not the submitted spelling — `X=rm; $X -rf x` arrives as `rm -rf x`.

**A command line is judged once, after the Shell parses it, expands it, and resolves its first
word to a program.** There is exactly one admission point: `run_pipeline`
(`src/exec.rs:2777`), immediately after the loop that applies every alias, multicall, and
shebang rewrite. `execute`, `execute_with_reader`, `execute_sourced`, and `capture_output` are
**no longer admission points**, and each states that in its own doc comment. Every stage of a
pipeline is admitted before any stage runs, so a refusal in one stage stops the pipeline.

**The pre-expansion residual is CLOSED, 2026-08-12.** It was real, and the measurement was
this. With an interceptor denying anything containing `LAUNDERED`:

```sh
W=LAUND; X=ERED; printf "${W}${X}"      # printed LAUNDERED, status 0 (2026-08-09)
```

Admission saw the submission before parameter expansion, so a variable carried text no rule
matched. Admission now runs after expansion, so the attempt names `printf` with the assembled
argument. `a_denied_command_substitution_does_not_run` in
`tests/kernel_effect_interception.rs` denies the **expanded** form and is the pin.

**Coverage got finer, not coarser.** The old text gate sat at a funnel chosen because
`sh <file>`, `.`/`source`, a trap body, `find -exec`, `xargs`, and Lua's `io.popen` all reach
the evaluator through it. Resolution is now the funnel: each of those routes resolves every
command it runs, so each command gets its **own** decision instead of inheriting one taken over
the whole submission.

**What the old caution still buys.** A rule may still read `command`, and one effect still has
many spellings, so a `command like` pattern is still a weak match. The decision now also
carries `program`, which is the resolved identity a rule needs: `alias safe=rm` makes the
spelling `safe`, and the `alias` builtin raises no decision of its own. Write a rule on
`program` rather than on `command`.

**If you re-measure anything in this area, run a no-substitution control first.** An
earlier investigation first reported the pre-expansion leak as a command-substitution
bypass, because every probe payload wrapped the assembled text in `$(…)`. Removing the
substitution leaked identically, which is what found the real cause.

### Command substitution: each command inside it gets its own decision

**`capture_output` is no longer an admission point** (`src/exec.rs:1700`). It once held a
separate text gate, because `$(…)` and backticks evaluate command text without passing through
`execute_sourced` or `execute_with_reader`.

**The event that gate existed to add is now automatic.** The substituted text is parsed and run
like any other, so each command inside it reaches `run_pipeline` and raises its own resolved
decision. The old gate judged the substitution's *unexpanded* source text, which was always a
literal substring of the already-judged submission — so it closed no laundering hole. Post-
resolution admission closes that too; see the previous section.

**The counting property is what to keep, and the absolute number changed.** Before the old gate,
ten substitutions in one submission produced one decision where ten through `eval`, `xargs`, or
`source` produced eleven, so anything counting command decisions saw substitution fan-out as
nothing. The count across all three routes is now **ten, not eleven**: the eleventh was the
submission itself, and no decision is taken over a submission any more.

Three guards in `tests/kernel_effect_interception.rs`, and each asserts a stronger property
than it did:

- `command_substitution_is_admitted_as_its_own_event` matches the **exact** admission entry
  (`shell:run printf SUBSTITUTED`). A `contains` match passes on the outer command's own entry
  and proves nothing, which is how two earlier drafts passed against a build with no gate at
  all. Do not relax it to `contains`.
- `a_denied_command_substitution_does_not_run` denies the **expanded** form, whose marker
  appears nowhere in the submitted text. This is the test that pins the closed residual.
- `substitution_fan_out_is_counted_like_every_other_route` asserts parity with `eval` and
  `source` at ten each. Parity is the assertion; the absolute count is not.

**A reported status must be one the capture path actually computed.** Each resolved command
inside a substitution now reports its own status against its own permit, and the substitution
itself reports none — `capture_admitted` returns a status that `capture_output` discards
(`src/exec.rs:1706`). The rule stays because `run_capturing_status` is still what the outer
status and `$?` read. Reporting an outcome is what exposed that `run_capturing`'s compound arms
(`Group`, `Subshell`, `If`, `While`/`Until`, `For`, `Case`) all returned a hardcoded `0` — so
`X=$(if true; then false; fi)` reported success for a failed command. Each arm now threads its
real status out via `run_capturing_status`; if you add an arm, thread the status rather than
returning `0`. Still wrong and left alone: `X=$(exit 42)` reports `127`, because the capture
path has no `exit` arm and resolves it as an unknown command.

## Creating a High-Quality PR

If you are an agent opening a PR on behalf of a contributor, the human is the author and is accountable for everything you submit. A small, focused change that its author fully understands is the single biggest predictor of a fast review and an accepted PR. (See [CONTRIBUTING.md](./CONTRIBUTING.md#using-ai-tools) for the human-facing version.)

- **Understand before you submit.** The contributor must be able to explain why every line works and defend the design. If you produced code you cannot explain plainly, simplify or explain it before opening the PR.
- **Keep it small and focused.** One logical change per PR. A branch that spans the Rust core, the Python binding, and the Node binding is usually several PRs — unless the change is a single cross-cutting surface (e.g. one new method that must exist in both bindings).
- **Open an issue first for anything significant**, so maintainers can align on the approach before time is invested.
- **Don't pad the change.** No drive-by reformatting, unrelated refactors, or speculative abstractions.
- **Run the relevant checks before opening.** Run the test suite(s) for the bindings you touched and make sure the change passes the `ci.yml` merge gate locally. Don't open a PR with known lint, type, or test failures.
- **Actually exercise the change.** Automated checks confirm the code is *valid*, not that the feature *works*. Run the behavior end to end — a script, the CLI, a REPL snippet — and confirm it does what the PR claims, including edge cases.
- **Self-review the diff** end to end as if you were the reviewer, and confirm you can truthfully check every box in the [PR template](./.github/PULL_REQUEST_TEMPLATE.md) — including the item attesting that you have reviewed and understand every line of code in the PR, including any generated by AI tools.

### Commit and PR title conventions

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) — this is enforced by `.github/workflows/pr-title.yml`. Allowed types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. Keep the title short; let the body carry the *why*.

## Things to Do

- Keep imports at the top of every file.
- Register coreutils-style commands with `#[command("name")]`; add builtins to `src/builtins/mod.rs`.
- Keep `src/python.rs` and `src/js.rs` in sync when changing the binding surface.
- Run `cargo fmt` and `cargo clippy --workspace --all-targets` on any Rust you touch.
- Run the test suite for the bindings you changed before opening a PR.
- Use Conventional Commit PR titles.

## Things NOT to Do

- **Don't rename the `lash` persona** (`lash`, `/bin/lash`, `USER=lash`, `/home/lash`, `LASH_UID`, `LASH_GID`) — it is the intentional emulated-POSIX identity, not the product name.
- Don't add `fork`/`exec` or direct syscalls — all effects must go through the `Kernel`.
- Don't weaken SSRF guards, bind-path mediation, or the effect-admission seam to make something pass.
- Don't put `use` statements inside functions.
- Don't let the Python and Node bindings drift apart without a stated reason.
- Don't open a PR with a title that fails the conventional-commits check.

## Additional Resources

- [CONTRIBUTING.md](./CONTRIBUTING.md) — human contributor guidelines, full development environment setup
- [SECURITY.md](./SECURITY.md) — vulnerability reporting
- [README.md](./README.md) — product overview, configuration, supported commands
- [Command Reference](https://strandsagents.com/docs/user-guide/shell/commands/) — per-command status and known gaps
- [Strands Agents Documentation](https://strandsagents.com/)
