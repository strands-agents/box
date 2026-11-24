# Containment guidance

The root freeze covers this facade and sandbox minimums. Before changing grants, read
[minimum process authority](README.md#the-minimum-process-authority-the-profile-grants) and the
[containment design](../../docs/design/containment.md).

## Cross-platform traps

- Every `Containment::apply` error means incomplete containment; never run the workload after one.
  Keep grant validation beneath every backend and recheck identities at the backend's last safe point.
- `os_paths::forbidden_paths()` supplies the single credential/system floor list. System roots use
  exact matching; credential stores use overlap matching. Swapping those semantics breaks runtime
  paths or leaves descendants grantable. Floor homes are additive to the passwd home, never replacements.
- A prepared path's traversal nodes and reachable endpoints serve different purposes. macOS needs
  metadata rules on symlink nodes; Linux binds the resolved object at endpoints. Store the judged
  traversal set once and validate it, rather than rewalking separately in the floor and renderer.
- File write/execute restrictions do not stop a permitted runtime interpreting data or generating
  code in memory. Linux permits JIT memory. Keep claims about file execution separate from claims
  about arbitrary code or policy mediation.
- A Linux read bind can also execute, and a write bind can also read. Loader dependencies add
  runnable paths beyond the explicit exec list. Do not describe macOS exec enumeration as portable.
- Keep the macOS renderer buildable on Linux so profile conformance runs on both platforms.

## macOS, measured

These are platform observations, not guarantees inferred from rendered text. Re-measure affected
behavior on a native Mac with an uncontained control when changing a rule.

- Seatbelt resolves operation specificity before rule order. A leaf allow can beat a later wildcard
  deny on a narrower path. `protect_write` and `refusals` must deny the write leaves as well as the
  wildcard; a profile-string test alone missed this bypass.
- `(version 1)` supplies default allows even beside `(deny default)`. A census of explicit allows
  misses them. Deny view-changing operations by exact leaf names: `fs-snapshot-mount`, `file-graft`,
  and `file-ungraft` were reachable without them. A wildcard deny did not close those routes.
- `file-graft` and `file-ungraft` are unbound on measured macOS 14/15 releases; an unguarded name
  prevents the entire profile loading. Keep `defined?` only on names that need it. Changing
  `(version ...)` does not change the compiler's symbol table. Kernel grafting reach on releases
  without those symbols remains unmeasured.
- Data rules match the object's canonical path. Metadata lookup also needs each symlink node in
  parent-canonical spelling, including linked directories. `realpath` does not collapse firmlinks;
  a `/System/Volumes/Data` grant can render dead data rules. Test both names, not just temp paths.
- Keep the runtime minimum's `/tmp` spelling: `/private/tmp` alone omits metadata on the `/tmp`
  link and breaks `lstat`, `realpath`, and accesses through it. `(path-ancestors "/")` does not compile.
- Agent exec rules stay enumerated and paired with metadata, never data reads. `process-fork`
  must stay unscoped: a generic filter compiles but authorizes nothing. The fork-bomb limit remains.
  Broad exec, home discovery, and loading newly built libraries are leaf-only exceptions.
  Preserve `the_agent_profile_never_carries_broad_exec` and `a_leaf_carries_broad_exec_and_the_main_box_does_not`.
- `file-test-existence` is not default-denied. The home deny gates reads and metadata too, so its
  re-allows need ancestors, traversal spellings, and position-sensitive scope. A grant on the home
  itself must not reopen all descendants. Existence outside the home remains observable.
- Keep write cells as leaf allowlists. `setattrlist` can bypass individual attribute denies when
  `file-write*` is allowed. The explicit `file-attributes` switch accepts those residuals; see
  [file attributes](../../docs/design/containment.md#file-attributes-in-a-macos-write-folder).
- `file-clone` remains default-allowed and can copy file flags; its check is on the source, so a deny
  scoped to the writable destination did not work. A blanket deny was withheld pending Bun copy
  compatibility measurements. Do not claim all flag-setting routes are closed.
- The agent's write-root `file-map-executable` deny must use canonical paths. A blanket deny also
  breaks loading read-only runtime libraries. Use `dlopen` to measure it: an ordinary uncontained
  process's executable `mmap` can already fail and produce a vacuous test.
- `ioctl-command` compiled but did not distinguish measured terminal requests on macOS 26.
  `TIOCSTI` failed in the uncontained control too; that is platform behavior, not profile enforcement.
  Inherited Mach rights also survive exec; denied service lookup is not absence of handles.
- Native egress needs the trust-service exceptions for platform TLS. The measured login-keychain
  refusal does not qualify data-protection or iCloud items; `secd` stays denied.

## Linux traps

- A read-only bind needs a remount; `MS_BIND` ignores `MS_RDONLY`. Recursive read-only remounting
  walks deepest first because `MS_REMOUNT` ignores `MS_REC`. Device binds need their `MS_NODEV`
  exception or `/dev/null` stops working.
- Mount `/proc` only after entering the PID namespace. `apply` returns in namespace PID 2, not the
  original PID. Preserve the supervisor/reaper lifetime chain and its memory hardening.
- Keep post-fork paths syscall-only and use `_exit`. Close inherited descriptors while they are
  enumerable; clear capabilities and set `no_new_privs` before installing seccomp last.
- A syscall denied with `EPERM` may not trigger a library's fallback. `umask` cannot report failure
  normally and can silently corrupt resulting modes; optimized copies can stop after partial
  output. Test effects with the actual wrapper, not just syscall return values.
- Legacy x86 syscalls and their `*at` counterparts use different mode/flags argument positions.
  Preserve special-bit checks, unused-mode handling, and upper-bit tests when editing the tables.
  Use `libc` numbers; the private terminal UAPI and `ARCH_SET_FS` constants are explicit exceptions
  whose production and independent test values must match the pinned Linux headers.
- Block the whole mount-creation API and `io_uring_setup`, not just `mount` and `socket`.
  `io_uring` can create sockets without `socket(2)`. Nested namespace operations do not themselves
  reopen the host view; preserve their allowed controls beside the mount refusals.
- Keep `/bin`, `/sbin`, and library links into `usr/` consistent with grant and refusal mount
  targets. A real `/bin` directory hiding the host link breaks `#!/bin/sh` wrappers even when the
  interpreter is granted under `/usr/bin`.
- Resolve ELF dependencies without inheriting loader variables. A writable loader tree needs
  explicit execution coverage or broad leaf exec; combining separate grants must not create it.
- Terminal syscall restrictions do not isolate the inherited terminal. Test virtual-console
  effects only on a disposable console with separate recovery access; a PTY proves request
  refusal, not keyboard or display effects.

### Native notification forwarding

One containment supervisor receives both filesystem-information and native-policy notifications.
A second seccomp listener fails with `EBUSY`, even for disjoint syscall sets. Box receives a copy
for validation and replies, never for notification receive. Finish startup acknowledgement before
Box reads the forwarding stream, and close the workload's stream copy before exec.
A full send buffer retains one request while supervision continues reaping; a partial write or
lost peer terminates supervision. Preserve that lifetime chain.

## Test traps

- Rebuild `strands-box-contain-trampoline` before integration tests; Cargo can otherwise test the
  old binary. Plant non-`CLOEXEC` descriptors when testing closure, and derive high descriptor
  numbers from the host limit rather than assuming Linux's limit on macOS.
- Attribute a refusal with a successful uncontained control. Root/group ownership, absent services,
  and invalid syscall arguments can all make a broken sandbox test pass. Check stored file bits,
  not only return codes: macOS `chmod` can return success while withholding a set-ID bit.
- A copied Apple platform executable can die from signature failure. It is not a valid control.
  Hard-linking compressed `/private/etc/passwd` hung even outside containment on macOS 26.6.2;
  use `/private/etc/hosts` and bound the probe externally.
- Run privileged probes only on disposable fixtures, never `/dev/null` or a live mount. The
  `tests/support/measure-*.sh` and `run-i*-matrix.sh` scripts are measurements, not CI gates.
  Their historical results do not establish behavior on a new OS release.
- Root-owned output is supported; it does not imply extra filesystem reach. Read the
  [root-output contract](../box/AGENTS.md#root-owned-output) before interpreting a root experiment.
