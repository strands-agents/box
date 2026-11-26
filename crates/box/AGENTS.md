# Box Core guidance

## The box contract

The root [interface freeze](../../AGENTS.md#strands-box-is-interface-frozen) applies here.
Read [configuration](../../docs/user/config.md) for the surface, and the relevant
[design page](../../docs/design/README.md) before changing composition.

- The four inputs are policy, credentials, name, and workload. A new source of authority is a
  fifth input regardless of its spelling. `--work-dir`, `--bind`, `--read-path`, and `--home`
  must keep reaching the workload as its own argv (`tests/four_inputs.rs`).
- `box_dir` selects a box; the name labels it. Core owns no namespace of boxes and cannot enumerate
  ones it was not handed. The caller owns stopping the process and removing the directory.
- `HOME` and `workspace` grant no filesystem access. Direct filesystem lists bypass `fs:*`
  policy and must be disclosed. A tool gets its own lists, never the agent's. Linux writable binds
  also read; `contain_egress = false` bypasses the gateway and needs its residual-risk disclosure.
- Reading harness configuration can expose live login tokens. Writing it can plant hooks that
  [run later outside Box](../../docs/cli/limitations.md#the-agent-can-plant-code-that-runs-outside-the-box-later).
- Keep this box's private tree unreachable from agent and tools. A declared home must neither lie
  inside trusted state nor enclose `box_dir`. Preserve `the_boxs_own_private_tree_is_unreachable_from_inside`
  and `a_tool_grant_cannot_expose_the_box_directory`.
- The box is the credential boundary. Per-process credential selection cannot enforce isolation:
  the gateway and broker cannot distinguish callers within one box. Use another box for that split.
- Public library additions must not expose policy engines, environment overlays, proxy handles, or
  resolved host paths. Decision notifications are copies and must never block an authorization.
- A run event carries only the code from `BoxError::code`, the code its stderr line prints; never
  a path or message. Send it only at the exit points in `lib.rs` and `command::execute`
  (`box_library.rs::event_tests`).
- Keep credential-path floors in containment. The Shell and Monty are outside OS containment;
  their `Reach` checks and policy are separate controls, not sandbox grants.

## Startup and identity traps

- Leave absent tools out once, before consumers build reach or secret-source checks. Re-resolving a
  left-out tool later admits a file the workload planted (`a_file_planted_at_a_left_out_tools_path_never_runs_with_its_reach`).
- Check secret-source programs and protected paths before committing a new box record or running a
  source. Fetch telemetry secrets before opening telemetry, then route secrets after secret-free
  preflights. Consume `RouteSecrets` to open vaults and close declared sources; do not add another
  backend or a way around those steps. A first-run telemetry fetch failure can still leave a record
  with no history and require removing that box directory.
- Protect every symbolic link on the route to a secret-source program. Protecting only the final
  inode lets the workload redirect the next run. Interpreter arguments and files a source loads
  itself are outside that protection; do not claim the whole command is pinned.
  Extending protection to intermediate links of ordinary tool commands or files named by later
  `command` arguments needs explicit approval.
- Adding a runtime check comparing process-table `env` or `command` values with
  `pass-secret-env` values needs approval.
  That rejected check copied secrets into memory and missed values in other encodings.
- `box_dir` retains its authored spelling. Callers and fixtures should canonicalize it on macOS:
  `/var` and `/private/var` can otherwise disagree between environment and grants.
- Keep trampoline validation and execution on the opened identity. The embedded marker identifies
  an artifact kind, not an authenticated publisher. Alias images may be hard links to the installed
  binary; changing an alias's mode can change the installation.
- Configured commands with hard links need the full workload-write-reach check, including directory
  moves. A read-only path alone proves nothing about another name for the inode. Keep the conservative
  scan fallback when the Linux mount shortcut cannot prove safety (`run/commands` and `record/layout`).

## Broker traps

- Build each Shell on its own connection thread. Shell is `!Send`; `ShellSpec` is `Send`. A shared
  `LocalSet` lets a non-yielding Lua call starve every connection. Share policy history, never mutable
  interpreter state, and never reload policy when constructing a request's Shell.
- Aliases derive the socket from their own path, never an argument or cwd. Keep the alias image
  client-only. Python aliases send argument words for the trusted Shell to quote; direct Python-mode
  `Open` is refused because it bypasses `shell:exec` admission.
- Stream stdin after `Run`; waiting for EOF first hangs harnesses that leave the pipe open.
  Send `InputEof` when input ends, and close by dropping the sender, not sending an empty frame.
  Input failure or truncation must not look like a clean EOF on a partial command.
- Feed a spawned program's stdin concurrently with its output. Empty input uses `/dev/null`:
  an empty pipe changes tools such as `rg`. On cancellation, kill the spawn before closing its feed.
- Drain output during the Call. Afterwards use `drain_ready`, never await `next_chunk`: the live
  Shell retains its senders. Match completion by Call sequence, not reused Program ID
  (`a_reused_program_id_never_reports_a_closed_calls_status`).
- Both interpreters must report the same `~`-relative paths in requests and outcomes. Different
  spellings can bypass a `forbid` or silently break a temporal match. Effects use the approved host
  identity, not the reported spelling.
- `Reach::approve` returns the approved path, not a boolean. Preserve
  `a_dangling_symlink_cannot_be_written_through` and `an_intra_home_symlink_cannot_launder_a_scoped_read`.
  A failed `canonicalize` does not prove that a dangling symlink is absent.
- Route Shell and Monty network effects through the gateway. These interpreters share the trusted
  process with secrets and the CA key; they have no OS boundary of their own. Shell embeds Lua,
  and Monty uses unsafe code, so neither is an unsafe-free parser.

## Hardening and Linux transport

Keep hardening unconditional. `PR_SET_DUMPABLE=0` protects same-uid memory reads, not root or an
exec'd child; `RLIMIT_CORE=0` survives exec but only prevents core files. macOS `PT_DENY_ATTACH`
refuses debugger attachment. None wipes copied plaintext or prevents swapping. `mlockall` was
measured to fail or starve heap growth under finite limits; do not add it as a blanket fix.

A socket keeps the network namespace in which it was created. `netns_relay` therefore needs the
listener descriptor created inside the workload namespace; a host port or a re-bind cannot replace
it. The relay decides no destinations. Keep `TCP_NODELAY` on both sides of each splice, including
telemetry splices, under the root TCP rule.

For native filesystem forwarding, the containment supervisor alone receives kernel notifications.
Box uses its listener copy only to validate and complete forwarded requests. Read
[containment guidance](../containment/AGENTS.md#native-notification-forwarding) before changing the handoff.

## Root-owned output

A root launch can create root-owned files through its grants or policy-mediated interpreters.
A later unsandboxed program consuming those files uses its own authority. Preserve Box's checks on
its own operations; root ownership alone does not establish that a Box control failed. See
[root sandbox launches](../../docs/design/containment.md#linux-root-sandbox-launches).

## Open findings — divergences no decision covers

- `Reach` protects this box and reserved state roots, not arbitrary sibling `box_dir` paths.
  A policy can reach a sibling's stored state under an otherwise reachable parent. The maintainers
  accepted this residual with caller-selected box directories.
- Secret-source `reads` and `deny` paths are sandbox refusals, not interpreter floors. Shell and
  Monty leave them to policy. On Linux an absent protected path is disclosed and skipped, but it
  must still participate in grant-overlap checks. See [source limits](../../docs/design/limitations.md#a-secret-source-runs-outside-every-sandbox).
- Shell's floor discards its approved path. Descriptor-bound effects protect content operations,
  but metadata operations re-resolve paths and retain race windows. `glob` has no `Resolved`.
  Keep `ReachFloor::approve_one`'s refusal distinctions; matching error text is not equivalent logic.
- Ownership-remapping mounts can hide a configured command's writable alias. Path and inode checks
  alone do not prove this case safe.
- Linux alias images remain readable; execute-only mode prevents the ELF dependency scanner from
  launching them. The approved read-test skip is Linux-specific; keep the write checks everywhere.
- Linux mounts a fresh writable `/tmp`. Fixture homes stay under `/var/tmp`, outside fresh mount
  roots, so fixtures do not accidentally make box scaffolding writable.

## Telemetry integration

Carry `McpToolCallRecord` through each completion path; its drop records an unfinished call as
indeterminate. Drain telemetry from the outer run teardown, including failures before `HostedBox`
exists. See [telemetry guidance](../telemetry/AGENTS.md).

Named `cloudwatch_traces` log-group routing rests on a live endpoint measurement. Its test checks
only the request Box builds. A failed destination was observed to reach neither the named group
nor `aws/spans`; do not assume fallback delivery.
