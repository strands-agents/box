# Containment

`strands-box-containment` applies an irreversible operating-system boundary
to the calling process. The crate also provides `strands-box-contain-trampoline`, which applies
the boundary before executing a target command.

Audience: Rust developers composing contained workloads and operators verifying
host enforcement.

## Public Interface

The public API describes one complete request and applies it once:

| Item | Role |
|------|------|
| `ContainmentConfig` | Complete validated request: path grants, network, process reach modes, and an explicit backend override. Fields are private, and the type *is* the wire format — it serializes itself, and each field that holds an invariant validates itself on load. |
| `ContainmentConfig::allow` | Grant one `Operation` at one `Scope` on one path. A path needing read and write takes two calls. |
| `ContainmentConfig::prepare_filesystem_path` / `allow_prepared` | Resolve a path's identity once, inspect it, then consume that same identity in a grant — the TOCTOU-free route for a path the caller must also use for something else. |
| `PreparedFilesystemPath` | Opaque existing path identity prepared once by containment. Callers read its canonical path and its kind, then consume it in a grant. |
| `Operation`, `Scope` | The grant vocabulary: `Exec`/`Read`/`Write`/`Connect`/`Metadata` by `File`/`Dir`/`Root`. |
| `Network`, and the signal, process-info, IPC and backend-override enums | Typed arguments for `ContainmentConfig` builders. |
| `Containment::apply(&config, egress_handoff)` | Detect the host backend and irreversibly contain the calling process. |
| `ContainmentError`, `Platform` | Matchable failure and platform values. |

The crate root exports **13 names**: `Containment`, `ContainmentConfig`,
`ContainmentError`, `Platform`, `PreparedFilesystemPath`, `Operation`, `Scope`,
`Network`, `BackendOverride`, `IpcMode`, `ProcessInfoMode`, `SignalMode`, and
`home_relative_path_refusal`. The last one is the deny-only floor's own predicate,
which judges a `~/`-relative spelling at authoring time so a caller that holds no
resolved path still gets the one refusal this crate owns.
Two further items are not in that count:
`pub type Result<T>`, an alias over `ContainmentError`; and `pub mod
test_support`, which exists only behind the non-default `test-support` feature.
Every other module is private, so this list is the whole API rather than a
selection from it.

### `apply` takes two arguments

```rust,ignore
use containment::{Containment, ContainmentConfig, Network, Operation, Scope};

// The macOS profile needs three things: a localhost port, at least one exec
// grant, and at least one write root. A path that is both read and written is
// two grants, and the kernel takes the union.
let config = ContainmentConfig::new()
    .set_network(Network::localhost().connect(proxy_port))?
    .allow(&workload, Operation::Exec, Scope::File)?
    .allow(&home, Operation::Read, Scope::Root)?
    .allow(&home, Operation::Write, Scope::Root)?;

// The second argument is `Option<&std::os::unix::net::UnixStream>`.
Containment::apply(&config, None)?;
```

The second argument is the egress handoff, and it is not a second entry point.
A backend that must *create* the workload's egress endpoint returns that
endpoint through the stream. The macOS backend passes `None`, because it pins a
localhost port that already exists. The Linux namespace launcher **refuses**
`Network::Localhost` when the handoff is absent, rather than binding an endpoint
that nothing can accept on.

A successful `apply` returns `()`. Kernel enforcement remains active until the
process exits and is inherited by child processes and across `exec`. There is no
status flag, no post-apply report, and no tier report: `apply` either contains
the process or returns a `ContainmentError`. Treat every error as incomplete
containment — terminate the process, do not execute the workload, and do not
reuse the process.

### Grants describe access, not callers

A grant is a path, one `Operation`, and one `Scope` — nothing about who asked for
it. Backends render a grant by its cell, so the same `allow` call serves a
composition layer and an ordinary caller alike, and no caller can obtain a
widening it could not also write as a plain grant. This is also why there is one
`apply` rather than one entry point per backend: a request that describes only
access has nothing backend-specific left to dispatch on.

**Nine cells are legal and six are refused by the vocabulary itself**, so no
backend ever sees a pair it cannot render. `Exec` at `Dir` or `Root` is refused
because a directory authorizes however many programs it holds; `Write` at `Dir`
because writing a directory's entries is a grant on its children; `Connect`
at either directory scope because a socket grant names one existing file; and
`Metadata` at `File` because a file's metadata comes with the exec or read grant
that names it.

One operation per grant is what keeps exec-without-read expressible, and the
macOS profile depends on it: it grants `process-exec` on the workload and no read
at all.

A grant carries two spellings and they are not interchangeable. Every emitted
rule renders the canonical `resolved` identity, because that is what the kernel
checks — a rule naming a symlink spelling matches no operation and would read as
a grant while enforcing nothing. The caller's `original` spelling is kept only so
validation can re-resolve it and prove it still lands on the same identity, which
is what closes the window between authorization and apply.

## macOS Profile

The macOS backend always applies
[`src/backend/macos/seatbelt-agent.sb`](src/backend/macos/seatbelt-agent.sb). The file is
the complete readable policy; Rust replaces one placeholder per cell, plus the
localhost-port placeholder, and renders each path as the grant's canonical
spelling. The profile names no path of a harness's own — not `/`, not `/etc`, not
`/private/tmp`, and not `/dev/null` — so each of those reaches the profile as an
ordinary grant or not at all. Each write root's own identity is pinned: two denies on the root literal,
`file-write-unlink` and `file-write-create`, refuse removal, rename-aside, and
putting anything back at that name. Every write *inside* the root stays
permitted.

The backend is a recognizer for that one file. Each grant is identified by its
shape:

| cell | profile rule |
|------|--------------|
| `Exec` + `File` | `process-exec` on that literal, plus `file-read-metadata` on the same literal, and no other read |
| `Read` + `File` | `file-read*` on that literal |
| `Read` + `Dir` | `file-read-metadata` on the literal and its ancestors, plus its entries, and no descendant read |
| `Read` + `Root` | ancestor metadata, and `file-read*` over the subtree |
| `Metadata` + `Dir` | `file-read-metadata` on the literal and its ancestors, and no data rule at all |
| `Metadata` + `Root` | ancestor metadata, and `file-read-metadata` over the subtree |
| `Write` + `File` | `file-write*` on that literal |
| `Write` + `Root` | `file-write*` over the subtree, and two denies pinning the root's own identity |
| `Connect` + `File` | `network-outbound` on that socket path |

**One block per cell, and every cell repeats.** The profile has a placeholder per
cell, and the renderer appends one grant's rules to one of them — so there is no
role to recognize and no combination to detect. Seatbelt takes the union of every
`allow`, which is why a path granted both read and write reaches two blocks and
needs no third.

**No count bounds any block.** The caller's grants state the outer boundary for a
command, so a limit here would refuse a composition the caller authorized at a
layer that cannot see what was asked for. `every_repeatable_rule_renders_one_rule_per_grant`
pins that thirty grants of a kind render thirty rules.

`Read` at `Dir` scope is the cell for a directory the workload stands in and reads
nothing inside. `chdir` succeeds and a relative path resolves, because the rule
covers the literal and its ancestors, and no descendant is granted at all.

`Metadata` is the cell for a path the workload stats and never reads. At `Dir`
scope it renders the literal's own metadata plus its ancestors, and at `Root`
scope the subtree's metadata plus its ancestors. Neither renders a data rule, so a
file's bytes stay unreadable and a directory stays unlistable. `Metadata` at
`File` scope is refused, because an exec or read grant on a file already carries
that file's metadata.

### The minimum process authority the profile grants

An execute grant renders exactly two lines on one canonical literal, and the
profile grants the unscoped fork once:

```scheme
(allow process-exec (literal "<granted executable>"))
(allow file-read-metadata (literal "<granted executable>"))
(allow process-fork)
```

Three properties of that block:

- **The paired `file-read-metadata` is required, and it is not a widening.** A
  `PATH` search stats each candidate before it execs it. A program that can be
  executed but cannot be stat'd is reported as "command not found", so exec
  authority alone leaves the grant present and unreachable. The rule is
  **metadata only** — never `file-read*` — so the file's size and mode become
  visible and its bytes stay unreadable. Execute-without-read still holds.
- **`process-fork` is unscoped, and SBPL cannot scope it.** `posix_spawn` and
  `fork` need the operation, and the profile offers no effective path, argv,
  one-shot, or child-count filter for it. The exact exec literals scope the
  subsequent exec; they do not scope the fork. So a contained process can create
  processes without limit, and process exhaustion is an unbounded residual.
  Closing it needs a separate resource boundary. Descendants inherit the profile,
  so the fork expands no filesystem, network, or exec authority.
- **The crate recognizes an execute grant by its shape, not by the role the
  caller assigns it.** An alias is
  simply a second execute-only file, so the profile needs no `{{EXECUTABLE_PATH}}`
  or `{{SHELL_PATH}}` placeholder and the crate needs no role-named builder. The
  one placeholder the executables share is `{{EXEC_FILE}}`, which expands to
  the pair above once per grant, in grant order.

No cell inspects a file's contents, so this crate never checks *what a file is*.
`Read` + `File` is the same shape whatever the file holds. The proxy trust
bundle's contents check therefore lives in `box`, which knows which path is its
CA: it demands a regular file, within a size cap, carrying a `BEGIN CERTIFICATE`
block and no `PRIVATE KEY` block. Without that check the grant would give the
workload read access to any readable file — a private key included.

A grant is also refused when it is too broad to be a grant at all: a system tree
such as `/usr` or `/Library`, the whole filesystem, the home namespace, or a
credential store. Entries are compared canonically, because a grant carries its
resolved path.

A row of that floor may name the cells it lets through, because **a workload may
stat what it cannot read**. Five rows do: `/` permits `Read` + `Dir` and
`Metadata` + `Dir`; `/etc` and `/private/etc` permit `Metadata` + `Dir`; and
`/tmp` and `/private/tmp` permit `Metadata` + `Root`. Every other cell on those
paths stays refused, and a row that names no cell refuses all nine.

Matching is equality, not containment. A grant carrying more access than the
profile enforces would be honored only in part, and one carrying less would be
over-enforced; either way the config and the enforcement disagree, and the
profile is a checked-in file that cannot be adjusted to match. So any other shape
— a writable file, an executable directory — is refused rather than widened or
narrowed to fit. Direct network access, extra bind ports, and any non-isolated
reach mode are refused as well. There is no second profile and no
supervisor-side mode switch.

### Every cell repeats, and two are required

The profile emits one rule block per grant, and the second block means exactly what
the first does. **No cell is singular.** `Read` at `File` scope was, holding the proxy
trust bundle — a *role*, in a crate whose own rule is that a grant states what it
authorizes and never who asked. That check moved to `box`, which knows which path is
its CA, and the cell became repeatable like the rest.

Two cells are **required**, because a profile without them describes a workload that
cannot start: at least one `Exec` + `File`, and at least one `Write` + `Root`. A
config missing either is refused rather than rendered with an empty placeholder.

This is how a composition plumbs more than one executable — an agent plus a
Shell alias, say — without any new vocabulary, since an alias is simply a second
execute-only file.

Grants are also checked against each other, not only one at a time — and that check
is a **floor beneath every backend**, in `src/floors.rs`, rather than a step inside
one renderer. Every `allow` is permissive, so a request whose grants disagree about a
path would enforce the widest reading. Three combinations are refused: an exec grant
inside a write root, whose union is write-then-execute on a path the workload can
rewrite; a read root that *contains* a write root, whose union is a writable tree; and
two write roots that nest, where the union is the outer one and the inner grant
enforces nothing it appears to. Exec inside a *read* root stays legal — that is how an
interpreter runs from its own install tree, and the bytes cannot change under it.

The floor was the macOS renderer's own check, so the Linux backend enforced no part of
it: that backend grants exec by leaving a path runnable in the mount view, and a
writable bind over the same path is the identical defect.

A repeated rule is not a widening. Every emitted line names one canonical literal, so
N grants authorize exactly N paths; there is no wildcard, and one path granted the
same operation twice is refused rather than emitting a duplicate.

A pathname-socket grant is connect-only on one **existing** socket file. Every
other socket shape is refused: a directory scope would authorize a socket that
does not exist yet, and `ConnectBind` would let the contained process create a
socket at the granted path and accept on it, turning an egress route into an
ingress one. The rendered block holds no `system-socket` rule, because no
`system-socket` rule gates `socket(2)` for AF_UNIX, AF_INET, or AF_INET6.

## `strands-box-contain-trampoline`

The supervisor generates the config file with `ContainmentConfig::to_json`,
computes the SHA-256 digest of those exact bytes, and invokes an open-file-bound
trampoline image:

```text
strands-box-contain-trampoline --config <file> --config-sha256 <64-lowercase-hex> \
  [--target-env-fd <fd>] [--setup-status-fd <fd>] [--relay-control-fd <fd>] \
  -- <command> [args...]
```

The first three flags are required, and each may appear only once.
`--setup-status-fd` and `--relay-control-fd` are optional. `--setup-status-fd`
names an inherited descriptor for compact pre-exec failure reporting, and must
not be `0`, `1`, or `2`. `--relay-control-fd` carries the workload's egress
listener back to the box, and is Linux-only.

The digest and target-environment carrier are supervisor-owned internal launch
metadata, not `ContainmentConfig` fields or user policy.
`strands-box-contain-trampoline` starts with an empty ambient environment, reads the exact config
bytes, and unlinks the config file. Failure to unlink is a pre-apply refusal.
It then verifies the digest before parsing, loads and validates the config, and
calls `Containment::apply`. The supervisor retains the temporary directory only
through helper read/unlink, not for the workload lifetime. Only after apply
succeeds does the trampoline install the target environment and execute the
command in the same process.

The caller finds `strands-box-contain-trampoline` beside its own executable and
nowhere else; no configuration key names another path. The caller assumes its
package or update channel installed the intended image, and this launch path does
not verify that provenance. The public
embedded marker is only an artifact-kind and misconfiguration check; a
malicious file can copy it. Linux
duplicates the validated open identity with `F_DUPFD_CLOEXEC` to a dynamically
allocated descriptor at least `3`, keeps it reserved through `Command` stdio
and exec setup, and executes `/proc/self/fd/<fd>`. `CLOEXEC` closes the
descriptor when `strands-box-contain-trampoline` is entered, so it is not inherited by the
trampoline target. macOS, where `/dev/fd` execution returns `ENOTSUP`, copies
exact bytes from the opened descriptor into a private mode-`0700` executable
image and executes only that image. These platform-specific branches prevent a
post-open pathname replacement from changing the executed bytes; they do not
make a forged marker authentic. The original trampoline pathname is never
reopened for exec. The launcher also supplies the working directory,
standard input, standard output, and standard error.

After a successful `exec`, the process reports the target command's exit
status. Pre-exec failures use these exit codes:

| Code | Meaning |
|------|---------|
| `2` | Invocation, config loading, or platform support validation failed before apply. An unsupported platform refused fail-closed reports this code. |
| `3` | Containment validation or kernel apply failed. |
| `4` | Containment succeeded and target execution failed. |

## Platform Support

The production facade selects on the platform and, on Linux, on the architecture:

| host | selection |
|------|-----------|
| macOS | Seatbelt, and the one checked-in profile above. |
| Linux, ARM64 (`aarch64`) | The namespace launcher under `src/backend/linux/namespace/`. |
| Linux, any other architecture | `ContainmentError::PlatformUnsupported`, carrying the reason. |
| Windows and other targets | `ContainmentError::PlatformUnsupported`. |

Landlock was considered as the Linux mechanism and rejected: it restricts the calling process in
place and expresses no right that denies all network, which is the default mode, so a contained
child would keep unrestricted network. The launcher builds the filesystem view the workload sees and
forks into it instead.

On Linux, `apply` returns in a different process than the one that called it.
The launcher unshares a PID namespace and forks twice: the caller waits, a
reaper becomes namespace PID 1, and the workload is namespace PID 2, where
`apply` returns `Ok`. No post-apply code may depend on `getpid()` being stable
across the call. The exit status propagates outward unchanged.

Run the macOS enforcement proof on a macOS host:

```sh
cargo test -p strands-box-containment --all-features --test contains_exec_target
```

Run the Linux enforcement proof on a Linux host:

```sh
cargo test -p strands-box-containment --all-features --test contains_exec_target_linux
```

`--all-features` is required, not a convenience. The macOS proof drives the
`containment-test-probe` helper binary, and that binary is gated on the
non-default `test-support` feature. Without the feature the test does not
compile.
