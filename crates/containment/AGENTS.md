Follow [repository guidance](../../AGENTS.md).

**Interface-frozen.** The `pub use` façade and the SBPL minimums need the user's approval before they
change, and a *narrowing* counts. A defect fix behind the current shape needs none.

The code and its tests own behaviour, and [the design decisions](../../docs/design/decisions.md)
own why.

**This file holds what the code cannot say: measurements, escapes that were reproduced, and the
footguns that cost a day.** Where it and a document disagree, the code is the fact. Anything derivable
by reading `src/` belongs in `src/` — the README describes the shape.

## The shape, in one pass

`model.rs` the vocabulary · `config.rs` the request · `floors.rs` the deny-only floors ·
`facade.rs` the pipeline · `backend/*` the mechanisms. One decision per module.

- **One verb**, `Containment::apply(&config, egress_handoff)`. Add no tier report, status flag,
  post-apply report, lifecycle handle, configure phase, or second entry point. Treat every error as
  incomplete containment: terminate, and never run the workload.
- **A grant states what it authorizes, never who asked.** No provenance tag, no role name, no
  `allow_system_*`. This is why the proxy trust bundle's contents check lives in `box`: only the box
  knows which path is its CA.
- **The floors run beneath every backend**, in `floors.rs`, and the two pure ones run before the two
  that touch the filesystem — a grant naming `/` is refused without a `canonicalize`, which matters
  because a grant's path may be workload-influenced. Each backend re-runs the identity check at its
  own last safe point.
- **An execute grant on a set-user-ID or set-group-ID file is refused**, by
  `require_no_identity_changing_executables`. It reads the mode of `resolved`, which is the inode the
  macOS renderer names in its one `process-exec` literal; `original` gets `file-read-metadata` alone,
  so no other inode is reachable through an exec grant. Reading `original` instead would return the
  same mode anyway, because `fs::metadata` follows the link and the identity check has just confirmed
  the two agree — so do not write that this floor "checks the resolved spelling", as though a second
  spelling were a route.
  - **This is the one floor with no backend re-run, and that is deliberate.** The other two are
    re-run at each backend's last safe point because each bounds something the backend *renders* — a
    path set, and a literal's identity. A mode is rendered into no rule, so a second read would
    narrow a window rather than correct an artifact. And the window is not usable: `chmod` needs
    ownership, so only the file's owner sets the bit, and set-user-ID to an identity the caller
    already holds confers nothing. The workload is not running yet and cannot write an exec-granted
    path, because `require_no_conflicting_grants` refuses that pair.
  - **The two bits are octal literals rather than `libc` constants.** `mode_t` is `u16` on macOS and
    `u32` on Linux while `metadata.mode()` is `u32` on both, so `as u32` raises
    `clippy::unnecessary_cast` on Linux and `u32::from` raises `clippy::useless_conversion` there.
    Octal is the only spelling with zero owned warnings on both, and both values are POSIX-fixed.
  - **The refusal is a `ConfigValidation`, not a `GrantTooBroad`.** That variant reads "grant is too
    broad to be authorized", which names the wrong defect on a path that is one file.
  - **On Linux this refuses a configuration that used to run.** `MS_NOSUID` on every bind neutered
    the bit, so a set-user-ID workload program started and ran unprivileged; it is now a launch
    refusal. On macOS the same configuration was already dead, in the kernel, at exec.
  - Guard: `an_execute_grant_that_changes_identity_is_refused`, which sets each bit in turn and
    **asserts the bit survived the `chmod`** — a host that drops it would otherwise leave the test
    passing while it proved nothing. It fails rather than skips, because a floor's own pin must not
    go quiet. What it does **not** pin is the call order inside `require_all`: swapping the two
    filesystem floors leaves every one of the 13 test binaries green.
- **`FORBIDDEN_PATHS` is one list, in `floors.rs`, and `rule` is the security decision on every row.**
  A row is `anchor`, `rule`, `permits`, `reason`. The anchor is a plain string, home-relative when it
  starts with `~/`, and `Forbidden::exact` or `Forbidden::overlap` builds the row. The comparison is
  set intersection, so `AnyOverlap` catches a grant *above* a row with no second relation: one
  `~/.ssh` row is what refuses a read root on the operator's whole home. Three classification rules,
  each measured:
  - **Every system tree is `ExactPath`.** `AnyOverlap` on `/usr` refuses `/usr/share/icu` and kills
    every Bun workload; on `/System` it kills Node's `/System/Library/OpenSSL` read; on `/Users`
    it refuses every operator home. Do not promote one.
  - **Every credential store is `AnyOverlap`.** `ExactPath` there leaves every secret inside the store
    grantable, which is what the earlier list did.
  - **`rule` takes no default**, because the two fail in opposite directions: `ExactPath` under-refuses
    in silence, `AnyOverlap` over-refuses on the next run.

  **The base is the passwd database, looked up once per process, and never `$HOME`.** The trampoline
  applies the config, and the workload's `HOME` is the operator's own home, unless `[agent] env.HOME`
  names another directory. A caller states its home with `anchored_at`, which adds an anchor beside the
  passwd one; a base that replaced it would be a floor the caller moves, and
  `a_declared_home_never_replaces_the_passwd_anchor` refuses that. An entry joins lexically and is
  never stat'd, so a path is refused whether or not the operator has that directory yet.

  **`permits` states the cells a row lets through, and the authority behind it is one sentence: a
  workload may stat what it cannot read.** Seven rows opt in with `.permitting(…)`: `/` at `Read` +
  `Dir` and at `Metadata` + `Dir`; `/etc` and `/private/etc` at `Metadata` + `Dir`; `/tmp` and
  `/private/tmp` at `Read` + `Dir` and at `Metadata` + `Root`; and `/var` and `/private/var` at
  `Metadata` + `Dir`, which the time zone chain crosses. **A permit names a cell, not a path.** The
  `/etc` row permits `Metadata` + `Dir`, which the runtime minimum needs, and it permits no root
  grant. A `metadata = ["/etc"]` entry stays refused as **too broad by this row**, which is the
  system-tree floor and not the credential one — the credential rows name `~/.aws`, `~/.ssh` and the
  keychains, and none of them sits under `/etc`. The password databases and the sudo configuration
  below `/etc` are what the row protects; what refuses the grant is the row's own shape. On macOS the
  operator's own spelling is refused earlier still, by the symbolic-link check on an
  `[agent.filesystem]` entry, and `/private/etc` is the spelling that reaches this row.
  `a_metadata_grant_on_etc_clears_one_row_at_a_time` pins both halves. Empty is the default, and it means the path's own existence
  is protected. **Never subtract by anything broader than a cell.** The earlier floor subtracted by
  shape — it skipped every non-directory grant — and that is why a grant on a credential *file* was
  never judged. A case that needs more than a cell is a third `Match` variant.

  **`box` holds no list of its own.** Every grant it renders, from its floor or from
  `[agent.filesystem]`, reaches `require_bounded_grant`. Two entry points serve it:
  `home_relative_path_refusal` judges an authored `~/`-relative spelling before a home is known, and
  `validate_grant(path, operator_home, operation, scope)` judges one composed grant and reports a
  named-exactly credential store in its `bool`. Two lists in two crates was the divergence this merge removed,
  and `the_floor_covers_every_credential_path_the_pack_loader_held` is the guard. One case table,
  `the_list_refuses_what_it_claims_and_renders_what_it_must`, pins every classification; a per-entry
  witness cannot see that `/Users` renders a home only because no credential entry sits under it.
- **Render `resolved`, and render every other node a lookup traverses.** Three cells emit a
  `file-read-metadata` rule per node: `Exec`/`File` (because `claude` is a symlink and 873 of
  874 Homebrew `bin` entries are) and both `Metadata` cells (because the box's floor authors `/etc`, the box
  canonicalizes to `/private/etc`, and Codex read `EPERM` on `/etc/codex/requirements.toml` when the
  link node had no rule). **`require_bounded_grant` judges the same set**, so the rendered set is
  never wider than the approved set. **Two rules reach a node other than `resolved`, and no third**:
  that `file-read-metadata`, and the `file-test-existence` allow the home deny needs paired back.
  Both at `literal` scope only — no `subpath`, no `path-ancestors`, and no data rule.
  - **`traversal_paths` is that set, and `reachable_paths` is NOT it.** The first is the caller's
    spelling, every link node, and the identity. The second is the two endpoints, and it is what the
    Linux view binds — the view binds `resolved` at each entry, so `A→B→C` becomes a bind of `C` at
    `A` and no link is traversed inside it. **Do not collapse the two.** Widening `reachable_paths`
    would put pointless bind mounts in the view.
  - **The floor judges the wider set on both platforms, so Linux is stricter than what it renders.**
    That is the safe direction and it keeps one list beneath every backend. The observable cost is a
    new startup refusal: an execute grant whose chain passes through a `FORBIDDEN_PATHS` row is now
    refused by name, where before the middle node was invisible and its metadata rule rendered
    anyway. Nothing box grants has such a chain.
  - **The two endpoints are the whole chain only at depth 0 or 1**, so a one-link test passes on them
    alone. That is why this was missed:
    `an_execute_grant_reached_through_a_link_renders_metadata_on_both_spellings` builds one link.
    Measured 2026-08-31, a chain to `/bin/bash` under a real box: depth 0 and 1 print, depth 2 gives
    `exec … Operation not permitted`, and one metadata rule on the middle node fixes it. A Homebrew
    CPython is three links and an Apple Command Line Tools CPython is two, so **neither could start a
    box at all**.
  - **Each node is spelled parent-canonical**, because Seatbelt matches a node with its ancestor
    components already resolved. Measured: `deny file-read-metadata /var/db/timezone/zoneinfo`
    matched nothing, and `/private/var/db/timezone/zoneinfo` refused. A node spelled as authored
    renders a rule that matches nothing, which is the same canonical-path result.
  - **`original` itself needs that treatment, and the set carries both spellings of it.** The raw
    `original` rule the exec cell has always rendered is *dead* whenever an ancestor of the caller's
    spelling is a link. Measured on a grant spelled `<link to a dir>/<a link>`: a deny on the
    authored spelling did not fire, and a deny on the same leaf under the resolved directory
    refused. So the walk records `parent_canonical(original)` as well, and
    `a_grant_through_a_linked_ancestor_renders_the_node_the_kernel_checks` is the pin. Box does not
    hit it, because `executable.rs`'s `canonical_route` normalizes the head first — but
    `ContainmentConfig::allow` is public and nothing in this crate required that.
  - **The set is a stored field, resolved once when the grant is built.** That is what makes the
    floor and the renderer read one answer. `traversal_paths` was briefly a live walk, and it then
    ran three times per grant inside one `render_profile` — once for `require_bounded_grant` and
    twice for the cells — so a filesystem change between them could render a rule the floor never
    judged. `validate_live_identity` re-asserts the set at the backend's last safe point, on the
    same terms as `original` and `resolved`. **Do not turn it back into a method that walks.**
  - **Spell every link target canonically when you measure this.** A target reached through `/tmp`
    adds an unrendered `/private` hop, and the run then fails at every depth — which reads as "chain
    depth is not the cause". It cost an hour.
  - **It adds no rule to any profile a box renders today.** Box canonicalizes every path it owns
    before granting it, `/etc` is one link whose head already rendered, and no other floor path is a
    link. The growth is bounded by the links a caller's own program carries.
  - **A firmlink spelling still renders a dead rule, and that residual is not closed.**
    `parent_canonical` is `realpath`, which does not collapse a firmlink, so a link target spelled
    through `/System/Volumes/Data` renders a node rule the kernel never matches and the exec is
    refused. Availability only — a dead rule grants nothing — but the crate has a pattern for exactly
    this two-name problem, and `operator_home_spellings` renders **both** names per anchor where this
    renders one. Closing it means collapsing a firmlink inside `PreparedFilesystemPath`, which narrows
    what a grant may name and needs the user's approval.
  - **`parent_canonical` duplicates `box`'s `canonical_route`** (`run/contain/executable.rs`) line for
    line. The renderer is the right owner, because it is what emits the spelling. Box's copy runs
    earlier, on the route it will exec, and it is why box never hits the dead-`original` case above.
    Two copies of one normalization rule is the shape the `FORBIDDEN_PATHS` merge removed; this one is
    recorded rather than merged.
  - **Six cells render no node rule at all**, so a symlinked grant in one is unreachable through the
    caller's spelling. Measured: `deny file-read-metadata /usr/share/zoneinfo` — a real two-link
    directory chain — refused a read through it, and `Read`/`Root` renders nothing on that head. No
    floor entry authors a symlinked read root today, so it is latent. Closing it is a separate decision,
    because it would put a node rule on cells that deliberately carry none.
- **The READ cells render the chain too, and that is what made the time zone database reachable.**
  All three read cells emit `file-read-metadata` on every node a lookup traverses, not only the two
  ends. Measured 2026-09-02 by rule-level bisect against the real chain,
  `/usr/share/zoneinfo` -> `/var/db/timezone/zoneinfo` -> `/var/db/timezone/tz/<version>/zoneinfo`:
  with the box's own rule set the read was refused; the canonical spelling read 2158 bytes; and one
  added `(allow file-read-metadata (literal "/var"))` made the chain spelling read too. **Data still
  names `resolved` alone.** A `subpath` on a link spelling would make every entry beneath the link
  readable through that name, and both
  `an_authored_symlink_is_rendered_as_the_directory_it_names` and
  `a_read_grant_reached_through_a_link_chain_renders_metadata_on_every_node` bound each spelling at
  two rules and refuse three data spellings on each. Six things not to re-derive:
  - **`/var` is a floor entry, not a derived node.** An earlier shape walked each hop target for its
    linked ancestors and recorded `/var` that way. That derivation **escaped the floor**:
    `require_bounded_grant` never refused it, because the row anchors resolve canonically and the node
    was the symlink spelling. The box's floor now names `/var` in the `metadata`/`dir` cell and the floor opts
    that one cell in, so the authority is stated and judged.
    [The runtime-minimum rule](../../docs/design/decisions.md#the-runtime-minimum-is-two-sets-and-the-agent-takes-the-smaller-one)
    holds.
  - **A system root needs BOTH spellings opted in.** `/var` alone was not enough: the grant
    canonicalizes to `/private/var`, whose own row refused it with
    `grant is too broad to be authorized: /private/var`. `/etc` and `/private/etc` carry the same pair.
  - **`forbidden_path_refusal` on the bare literal `/var` answers nothing**, because the row's anchor
    resolves to `/private/var`. A **grant** is still judged, because `require_bounded_grant` sees the
    resolved spelling — which is why
    `a_grant_on_the_var_system_root_is_refused_beyond_the_cell_it_permits` asserts at the grant level
    and not through the predicate.
  - **The rendered subpath is version-pinned, and a tzdata update reverts the defect until restart.**
    `/usr/share/zoneinfo` resolves to `/private/var/db/timezone/tz/<version>/zoneinfo`, so the profile
    names one version. macOS replaces that component without a reboot, and a box renders its profile
    once per run, so a long-running box silently reads UTC again until it restarts.
  - **The Linux view still binds `reachable_paths`, so there are now two answers.** The shared floor
    and the macOS renderer judge and render `traversal_paths()`. The divergence errs toward
    over-refusal on Linux, which is safe, and no test asserts that the narrower set is deliberate.
  - **The operation census gives the chain no coverage.** Every census fixture path is a canonicalized
    temporary directory, so the node set holds one element and no extra rule renders. The census passes
    and proves nothing about a chain.
- **The write cells render `resolved` alone, and `require_no_conflicting_grants` relies on it.** Its
  `Write`/`File` × `Exec`/`File` arm compares `resolved` only. That is sufficient because
  `PathGrant::new` canonicalizes, so a write grant naming the exec grant's symlinked spelling resolves
  to the same target. **If a write cell ever gains an `original` rule, that arm under-refuses in
  silence** — extend it in the same change.
- Linux selects `NamespaceBackend` on ARM64 and refuses every other architecture by name. Landlock
  was considered and rejected, because it does not enforce `Network::Blocked`.
- `cfg`-gate `backend/linux/` on its module declaration, and leave `backend/macos/` ungated so its
  conformance suite runs everywhere.

## macOS, measured

- **The profile carries no `/`, `/etc`, `/private/tmp`, or `/dev/null` rule of its own.** Each arrives
  as a grant instead, because static text gave every box every harness's needs — a Python box carried
  Bun's `/private/tmp` entry. The measurement that first put that entry in the profile still holds,
  and it now says which cell the box's floor must state: a Bun-compiled workload stats and opens
  `/private/tmp` in C++ static initialization, before any of its own code runs, so no flag redirects
  it. The floor still bounds what a caller may ask for on those paths: `/` at `Read` + `Dir` or
  `Metadata` + `Dir`, `/etc` at `Metadata` + `Dir`, `/tmp` at `Read` + `Dir` or `Metadata` + `Root`,
  and `/dev/null` as an ordinary file grant inside a forbidden tree. **A path carries one scope**, so
  the two `/tmp` cells serve different harnesses and no box may ask for both: a Bun-compiled agent
  takes the entry read, and V8 takes the descendant stat it needs to reserve its code range.
- **`(path-ancestors "/")` is an SBPL parse error**, and `sandbox-exec` reports
  `argument expected but none provided`. `ancestor_rule` renders nothing for `/`, which has no
  ancestor to name, so a grant on `/` renders its own rule and no ancestor rule.
- **Both denies on a write root's own literal are needed.** `(subpath X)` covers `X` itself, so
  without `file-write-unlink` *and* `file-write-create` a `symlink` at that path succeeds. Guards:
  `the_home_directory_itself_cannot_be_replaced`,
  `contains_exec_target.rs::the_agent_cannot_replace_its_own_home_directory`.
- **A rule must name the path a load asks for.** Seatbelt matches the literal, pre-resolution path.
  A Homebrew dylib's `install_name` requests the symlink spelling, so a grant built
  from the resolved one matches nothing and the workload dies in dyld. Probe a footprint with
  `DYLD_PRINT_SEARCHING`, never `DYLD_PRINT_LIBRARIES` — only the first reports the requested path,
  and `found: dylib-from-disk:` is the one kind naming a real file. Measured on macOS 15, Homebrew
  Python 3.12. **That measurement bounds one cell**: it is the `file-read-metadata` read on the link
  node, which is why `reachable_paths` renders the caller's spelling for three cells and no others.
  The bullet below says what the data rules match, and the two are not in conflict.
- **The data rules match the kernel's own canonical path for the object, so one object has one
  decision.** Measured 2026-08-29 on macOS 26.6.2 arm64, 50 cases through one real profile, by
  `tests/support/run-i3-matrix.sh`. Five spellings of one
  granted directory reached one decision: the resolved identity, the `/System/Volumes/Data` firmlink
  twin, an upper-case spelling on a case-insensitive volume, a return through `..`, and a trailing
  separator. **The allows and the three subtractive denies followed the same object**, which is the
  half that matters — a name-based matcher would let one spelling reach `(allow file-write* (subpath
  X))` and miss `(deny file-write-unlink (literal X))`. Guard:
  `contains_exec_target.rs::a_second_name_for_the_home_reaches_the_same_refusal`, which skips the
  firmlink and the case spelling rather than failing when the host has neither.
  - **The consequence runs the other way too: a grant authored in a non-canonical spelling renders a
    rule that matches nothing.** A write root granted as `/System/Volumes/Data/<path>` is refused for
    every access, including one that uses that same firmlink spelling. So such a grant is a dead
    grant, not a wide one, and the box starts and then fails with `EPERM`.
  - **`realpath` collapses a symbolic link and does not collapse a firmlink.** That is why the
    firmlink spelling survives `PathGrant::new` at all, and it is the whole of the gap recorded
    below.
- **`(version 1)` plus `(deny default)` is NOT a default-deny, and the census cannot see the
  difference.** `libsandbox` carries a version-keyed block of unconditional allows, and
  `seatbelt-agent.sb` declares `(version 1)`. About 35 operations are permitted whatever the profile
  says, `fs-snapshot-mount`, `file-clone`, `file-link`, `file-graft`, `file-ungraft`,
  `file-map-executable`, `file-test-existence`, `syscall-unix`, `process-info*`, `fs-quota*` and
  `nvram*` among them. Confirmed behaviourally: one identical rule set runs `/usr/bin/true` under v1 and
  is refused under v2 and v3. The census counts rendered `allow` lines, so none of this appears in it.
  - **That v2/v3 refusal needs re-measuring, because it does not reproduce and the rule set was never
    written down.** A five-rule set — `(deny default)`, `process-info*` at `(target self)`, one
    `process-exec` literal with its paired metadata read, `process-fork`, `(deny network*)` — **ran
    `/usr/bin/true` under all three versions** on 26.6.2 build 25G83 arm64, 2026-09-22. The original
    result is probably right for a rule set that leaned on a v1 default-allow the narrower one never
    touches. State the rules beside the outcome when you re-take it; without them neither reading can be
    checked. Nothing depends on the answer today, because the version stays at 1.
  - **This explains every one-off deny in this crate.** `(deny process-info*)`, `(deny network*)`, the
    write cell's `file-map-executable` deny and the credential floor's `file-test-existence` deny are
    all on that list — each was found by measurement, one at a time, without the list being known.
  - **A wildcard deny cannot reclaim a default-allowed operation. Only the exact leaf name can.**
    Measured: `(deny fs-snapshot*)` leaves `fs-snapshot-mount` **allowed** while
    `(deny fs-snapshot-mount)` denies it; `(deny file*)` reaches `file-mknod`, `file-mount` and
    `file-chroot` but silently skips `file-clone`, `file-link`, `file-map-executable`,
    `file-test-existence` and `file-graft`. So a wildcard written against that list compiles, reads as
    complete, and enforces nothing. **Never write one.**
  - **Eleven operations are therefore denied by exact name at the end of the profile**, after every cell
    so nothing above and no future overlay re-grants one: `file-mknod`, `file-mount`,
    `file-mount-update`, `file-unmount`, `file-chroot`, the four `fs-snapshot-*` leaves, `file-graft`
    and `file-ungraft`. Guard:
    `every_view_changing_operation_is_denied_by_its_exact_name`.
    **`file-clone` belongs on the list and is deliberately NOT on it**, because it waits on a Bun
    measurement nobody has taken — so the shipped count is eleven and twelve is the target. Earlier text
    here said twelve, which read as though the deny had landed.
    **Three were load-bearing** — `fs-snapshot-mount`, `file-graft`, `file-ungraft` were reachable in a
    shipped box. The rest were already refused by the default deny and are named so each closure can be
    falsified by deleting one line. `file-mknod` is the real name: `file-write-mknod`,
    `file-write-device` and `file-make-device` are unbound, and the operation sits in `file*` but
    **not** in `file-write*`.
  - **The operation table is per release, and two of the eleven are not in it before macOS 26. An
    absent name refuses the WHOLE profile.** `file-graft` and `file-ungraft` are unbound on macOS 14 and
    15, so `sandbox_init` reported `unbound variable: file-graft at <input string>, line 353, column 7`
    and **no box started at all** on either release.
    - **The name table per release is measured, not inferred, and only those two are missing.** Swept
      2026-09-22 on four EC2 Mac hosts — macOS 15.7.9 build 24G830 and macOS 14.8.9 build 23J631, each
      on `mac2.metal` arm64 (T8103) and `mac1.metal` x86_64. **All four agree exactly.** The other nine
      deny-tail names are bound, and so is every operation the renderer emits — `process-info*`,
      `process-exec`, `process-fork`, `file-read*`, `file-read-data`, `file-read-metadata`,
      `file-write*` and its six leaves, `file-map-executable`, `file-test-existence`, `file-link`,
      `file-ioctl`, `sysctl-read`, `network*`, `network-bind`, `network-inbound`, `network-outbound`,
      `system-socket`. `file-clone` is bound on all four. So the two grafting names are the whole of
      the release gap, and it is not architecture-dependent. **Re-run that sweep on any release the box
      has not seen**; `sandbox_init` reports one unbound name at a time, so iterating on box launches
      costs one host cycle per name.
    - **The defect and the fix are measured end to end on all four hosts.** With the guard reverted,
      `strands-box run` exits 1 with
      `unbound variable: file-graft at <input string>, line 289, column 7` and
      `containment setup failed during containment apply`. With the guard restored, the same box starts
      and exits 0. `profile_conformance` is 66 of 66 on every host, both new pins included.
      `scripts/macos-floor-host.yaml` builds such a host.
      - **Four suite failures on those hosts are the host, not the box, and each is a probe refusing to
        measure rather than a refusal that did not fire.** `a_write_grant_on_one_file_cannot_change_or_replace_it`
        and `the_agent_cannot_change_ownership_inside_its_own_home` report *this process holds no group
        other than 0, so a chown would be a no-op* — Systems Manager runs as root in group 0 alone, so
        the `require_owned` rule declines to produce a vacuous pass.
        `the_inherited_mach_bootstrap_right_reaches_no_service` fails its own **uncontained control**:
        `com.apple.pasteboard.1` answers 1102 on a headless host, which is exactly why that control
        exists, and why the template arranges an automatic login. `floors::tests::the_list_refuses_what_it_claims_and_renders_what_it_must`
        fails on macOS 26 too. Nothing in any of the four logs mentions `graft` or `unbound`.
    - **The two now state a test of their own name**, which is Apple's own idiom — `/System/Library/
      Sandbox/Profiles` uses it for `system-fsctl`, `system-package-check`, `process-codesigning*`,
      `xattr-regex`, `system-socket` and `system-fcntl`. **`defined?` is itself bound on macOS 15**,
      measured on that host, which is the prerequisite the fix rests on: were it not, the failure would
      be the same error naming `defined?`.
    - **The guard changes neither the decision nor its position, measured on the class that matters.**
      `file-clone` is preamble-granted, like the two graft names and unlike an ordinary read leaf, so
      `cp -c` is the probe. Guarded and bare denies **both** refused it, with an `(allow default)`
      control cloning, on 26.6.2 build 25G83 arm64 and again on 15.7.9. A later `(allow file*)`
      wildcard loses to both forms alike.
      - **Do not write that a later allow never wins.** For a **pathless** deny — which is the shape
        this tail renders — a later pathless allow of the same name **does** win, identically in both
        forms. It is harmless here because nothing renders after the tail and a second `sandbox_init`
        is refused, but the guard is what is position-neutral, not the deny.
      Guards: `a_test_of_an_operation_name_loads_where_the_operation_is_absent` drives `sandbox-exec`,
      asserts the refusal message rather than the exit status — an uncompilable profile also exits
      non-zero, and that vacuity was caught in review — and reads the guarded lines back out of a
      rendered profile so an edit to their form cannot leave it testing the old one.
      `every_view_changing_operation_is_denied_by_its_exact_name` matches whole lines, so a name cannot
      move between the guarded and unguarded classes unnoticed.
    - **Guard a name only when it has to be guarded.** A guard on a name the host does not bind drops
      that deny in silence, so the nine stay bare: if Apple ever renames one, the box refuses to start
      and somebody reads the name, rather than running on with one fewer closure.
    - **The cost is stated rather than closed: on macOS 14 and 15 a box starts with nine of the eleven,
      and nothing tells the operator.** Every test is green on exactly that host — the text pins and the
      goldens read the rendered guard, and the kernel legs pass because the profile finally loads. The
      crate has two patterns that would say it, `ContainmentWarning` and the startup stderr disclosure,
      and both are public surface this change deliberately did not add. **Whether grafting is reachable
      at all before macOS 26 is unmeasured**: the absence of a compiler symbol is not the absence of a
      kernel path, and no probe verb drives the syscall. Treat "a release without the name has nothing
      to refuse" as the assumption it is.
    - **A version bump is not the fix, and this is the measurement that settles it.** `(version N)`
      selects the default-allow preamble and **does not change the compiler's symbol table**: on 26.6.2,
      `file-graft`, `file-ungraft`, `file-mknod`, `file-mount-update`, `fs-snapshot-revert` and
      `file-map-executable` are bound identically under v1, v2 and v3. So `file-graft` stays unbound on
      macOS 15 whatever version the profile declares, and the bullet below already records that the two
      graft names stay default-allowed in all three regardless. A profile with no `(version …)` at all
      is refused with `no version specified`.
  - **`file-write-mount` and `file-write-unmount` are ALIASES for `file-mount` and `file-unmount`**, and
    both resolve **outside** `file-write*`. So a write cell never granted mount authority, and any text
    listing `mount`/`unmount` as members of the write family is misleading.
  - **About 25 of the v1 default-allows remain untriaged**, including `nvram*`,
    `dynamic-code-generation`, `syscall-mach`, `syscall-mig`, `fs-quota*`, `system-fcntl`,
    `sandbox-check`, `file-link` and `file-lock`. `(version 3)` would close `fs-snapshot-mount` and
    `syscall-unix` for free but is **not a drop-in**: the same profile that runs under v1 fails to exec
    under v3, and `file-graft`/`file-ungraft` stay default-allowed in all three versions regardless.
    The "fails to exec under v3" half is the claim flagged above as needing re-measurement with its rule
    set written down; the default-allowed half holds.
  - **The compiler is the instrument.** `(error (string-append …))` with `operation-expand`,
    `sbpl-operation-name` and `sbpl-operation-can-return?` answers all of this read-only, with no root
    and no syscall. The 203-name operation table lives in the dyld shared cache, not in Sandbox.kext.
- **The operation census still bounds what the profile GRANTS, and that half holds.** The profile
  carries no `file-mount`, `file-unmount`, `fs-snapshot*`, `sandbox-extension` or
  `system-fsctl` allow, and `the_rendered_profile_grants_exactly_these_operations_and_no_others`
  holds that set exactly. The macOS agent now permits one named `mach-lookup` service:
  `com.apple.system.opendirectoryd.libinfo`, authorized for issue 219. Two measured consequences:
  - **A second `sandbox_init` carrying `(allow default)` returns `Operation not permitted`.** The
    verb reads an ungranted path afterwards regardless, so a kernel that accepted a permissive
    profile and widened nothing is still told apart from one that widened. Guard:
    `a_second_profile_cannot_widen_the_first`.
  - **The tested privileged Mach services remain denied.** `bootstrap_look_up` returns 1100
    (`BOOTSTRAP_NOT_PRIVILEGED`) inside a box for `diskarbitrationd`, and 0 with a live port outside
    one. **Run the uncontained control every time**, because 1102 (`BOOTSTRAP_UNKNOWN_SERVICE`) and a
    refusal are both non-zero and a retired service would make the assertion vacuous. Guard:
    `privileged_mach_services_remain_denied`, and `containment-test-probe --uncontained` is the
    control mode.
- **`link(2)` on `/private/etc/passwd` never returns on macOS 26.6.2**, inside a box and outside one.
  The file carries `UF_COMPRESSED`. This is a host quirk rather than a containment result, and it
  cost an hour: use `/private/etc/hosts` as the ungranted hard-link source instead.
- **Keep the census `the_rendered_profile_grants_exactly_these_operations_and_no_others` exact**,
  counts included. On failure, justify the new authority or treat it as the bug. The last change moved
  it downward only: five operations left the expected list and none joined it, three `file-read-data`
  and two `file-read-metadata`, all of them the static rules named above.
- **No write cell grants `file-write-flags`, and it was the first authority the wildcard handed over by
  accident.** `file-write*` covers the write family, which includes the operation behind `chflags(2)`,
  so both write cells granted flag authority: one `UF_IMMUTABLE` in the home made `remove_dir_all` fail
  and left the box undeletable. It was a deny beside the wildcard until the cells became leaf
  allowlists; now the leaf is simply never named. Everything below still holds, with "the deny" read as
  "the withheld leaf".
  The kernel checks a flag above the ownership check, so it refuses the owner too. Guards:
  `every_writable_path_refuses_a_file_flag`,
  `contains_exec_target.rs::the_agent_cannot_set_a_file_flag_in_its_own_home`, and the per-root leg of
  `every_read_write_root_renders_with_its_own_identity_denies`. Four things not to re-derive:
  - **One rule covers both flag classes.** `chflags` is one Seatbelt operation whose flag argument no
    rule can read, so the owner `UF_` class, the super-user `SF_` class, every bit defined today, and
    any bit Apple adds later go through the same line. **This is what closes `SF_` for a root-mode
    box** — the `SF_` privilege check is not the box's closure, and nothing in the tree refuses,
    detects, or reads root. `SF_NOUNLINK` is a second way to wedge the same cleanup.
  - **Only the write cells could ever reach it.** The profile denies by default, so a path with no
    write leaf cannot reach `chflags`. Two tests, and they are not interchangeable:
    `every_writable_path_refuses_a_file_flag` asserts no cell *grants* the flags leaf and that neither
    cell reaches it through the family wildcard, with the data leaf as a live control so the test cannot
    pass by refusing everything; `a_traverse_root_renders_no_descendant_read_and_no_write` asserts no
    write rule of any kind lands on a non-writable path. Both are absence assertions now, which is
    weaker as string checks — the kernel-level pins in `contains_exec_target.rs` are what measure the
    refusal, and they are the ones that caught the `protect_write` near-miss.
  - **`file-write-mode` and `file-write-xattr` stay granted, and the reason is no longer `git`.** `git`
    runs in a leaf now, so the executable-bit argument moved there with it. What keeps the mode on the
    agent's own write root is measured: Claude Code creates `.claude.json` at 644, `chmod`s it to 600,
    and **swallows the failure**, so withholding the leaf leaves a config holding `mcpServers` group-
    and world-readable. Nothing ordinary sets a file flag. The two cases are not symmetric.
  - **The `SF_` leg is a recorded measurement, not a test.** Non-root it would pass on the privilege
    check alone, and a root-gated test never runs. `chflags-sf` ships in `containment-test-probe`, and
    `tests/support/measure-sf-flags-as-root.sh` drives it; no suite calls either. Measured 2026-08-25
    on macOS 26.6 arm64 at `euid` 0 and `kern.securelevel: 0`: **both classes refused, and both
    permitted again under `--control` with the deny removed**, so a Seatbelt `deny` binds root and the
    rule is what refuses. Run the control whenever this is re-measured — refused-as-root alone does
    not say *what* refused.
  - **`chflags_probe` reports an `Err` for every inconclusive outcome, and each case was a false
    pass first.** A `false` reads as "denied", so `expect-deny` would pass for a reason that is not
    the profile — the mistake `rmdir_probe` avoids by re-checking the filesystem. Four produce an
    `Err`: the target is absent (`ENOENT` whatever any rule says), the target already carries the
    flag (a refusal cannot be told from a success), `chflags` fails with anything but `EPERM`, and
    **`chflags` returns 0 while storing nothing** — `UF_COMPRESSED` behaves that way, so a return
    code alone would count permitted-but-not-kept as a refusal. The restore puts back the flag set
    the target arrived with rather than zero, because a target may carry an unrelated flag the probe
    did not set.
  - **`cp -p` inside a box now exits 1 where it used to exit 0.** `copyfile(COPYFILE_ALL)` copies
    data and mode and then calls `chflags`, which is refused. The data and the mode still land. This
    is the one ordinary tool the deny changes.
  - **`clonefile` is STILL OPEN, and the earlier reachability argument was wrong.** The blanket
    `(deny file-clone)` was written, measured, and then reverted before commit, because it needs a
    measurement on Node **and** Bun and only Node is measurable here. Both shipped harness packs are
    Bun-compiled, so landing it blind would break every file copy in a real box. Six syscalls reach
    the attribute; the withheld leaf covers five. `clonefile` copies the source's flags to the
    destination, and its Seatbelt operation `file-clone` filters on the **source**, so
    `(deny file-clone (subpath <write root>))` was measured to enforce nothing and only the blanket
    line refuses it. **`file-clone` is not default-denied.** It is one of the operations
    `(version 1)` grants unconditionally, measured two ways: the compiler's own
    `sbpl-operation-can-return?` reports `ALLOWED` under `(deny default)` alone, and `cp -c`
    succeeded inside a profile that rendered no `file-clone` allow at all. So the residual was never
    gated on a read grant, and anything saying otherwise is the claim to delete.
    - Half the prerequisite measurement is taken. With the blanket deny rendered, Node 18's
      `fs.copyFileSync` **falls back to a byte copy** and produces a full-size file, stable over
      repeats, while `/bin/cp -c` fails with `clonefile failed: Operation not permitted`. **Bun is not
      installable on this host, and both shipped harness packs are Bun-compiled, so the other half is
      still missing and the line stays out.** Take the Bun measurement on a host that has it, then land
      the deny; the cost will be one tool, a caller that demands a clone, beside the recorded `cp -p`.
    - Do not write "no writable path carries flag authority" anywhere; the flags residual the blanket
      line closes is only the clone route.
- **`(deny default)` does not deny an existence test, and one rule over the operator home closes it.**
  **This section describes the AGENT box.** A leaf inverts it: `allow_discovery` renders the home
  existence-and-metadata *open* (`file-test-existence` and `file-read-metadata` over the home), with
  the box-state and credential denies rendered last so they still win
  ([the leaf discovery decision](../../docs/design/decisions.md#a-leaf-discovers-existence-and-metadata-content-stays-gated)).
  `discovery_roots` empty is the agent posture below; `render_profile` suppresses the home
  existence-deny only where a discovery root is at or above the home spelling. The leaf tests pin it
  (`a_discovery_root_opens_home_existence_and_metadata_but_a_credential_store_stays_refused` and
  siblings), and `without_a_discovery_root_the_home_existence_deny_survives` pins the agent's. Two
  operations answer "does this path exist", and the default deny leaves both usable:
  `access(path, F_OK)` succeeds where the path is there, and `stat` reports `EPERM` where it is
  there against `ENOENT` where it is not. `(deny file-test-existence (subpath X))` moves
  authorization ahead of the lookup, so an absent path inside `X` reports `EPERM` too and the two
  stop differing. Measured 2026-08-29 on macOS 26.6 arm64. Nine things not to re-derive:
  - **The existence deny alone is enough.** It gates `stat` as well as `access`, measured with
    `file-read*` still granted on the tree, so a paired read deny would be dead text.
  - **A blanket deny is not available.** `(deny file-test-existence)` with no path refuses the
    workload's own exec, and pairing allows on `/usr`, `/System`, `/dev`, `/private`, and `/Library`
    did not recover the loader. Do not try it again.
  - **The deny is not one narrow operation: it authorizes the lookup, so it overrides every allow on
    its subtree, a metadata read and an open included.** That is why the scope is the operator's home
    and not the filesystem, why every grant needs the operation allowed back, and why no
    `AnyOverlap` row may opt a cell back in — a row that did would render a grant enforcing nothing.
    `no_credential_row_lets_a_cell_through` is the guard; without it nothing went red.
  - **The home answers to more than one name.** `/usr/share/firmlinks` maps `/Users` onto the data
    volume, so `/Users/x` and `/System/Volumes/Data/Users/x` are one directory with one inode. The
    operation matches the pre-resolution path, so a deny on the canonical spelling alone left the
    firmlink spelling answering — measured against the real profile, `access` succeeded on `~/.ssh`
    through that prefix. `operator_home_spellings` renders one deny per name, and `resolved_anchors`
    carries the same second name for **every** row, so the floor refuses `/System/Volumes/Data/private`
    as well as `/private`. That second half was a pre-existing gap the same review found: only the
    home-relative rows had been made spelling-aware, and four measured system paths were grantable
    through the prefix. Lexical variants (`//`, `/./`, `/../`) are kernel-normalized and need nothing,
    and a symlinked *prefix* like `/Volumes/Macintosh HD` is resolved before Seatbelt matches.
    **One prefix covers any path on the data volume**, not only `/Users`: `/private/var/root` and
    `/Users` both report the same inode through it, measured. It is not recursive — a doubled
    `/System/Volumes/Data/System/Volumes/Data/…` is `ENOENT`. Two guards, and both were written after
    the review found the first pins tautological: `every_spelling_of_the_operator_home_answers_nothing`
    names the prefix literally rather than reading it back from the code under test, and
    `a_forbidden_path_named_through_the_data_volume_is_refused` covers one credential row and one
    system row.
  - **Three parts in one block, and the order is the mechanism.** The home deny, then one allow per
    distinct granted path plus its ancestor chain, then the credential denies last.
    `the_operator_home_refuses_an_existence_test_before_any_allow` and
    `every_grant_renders_an_existence_allow_at_its_own_scope` pin the two halves. The credential
    denies are redundant for a spelling the home deny already covers — dropping them leaves the
    kernel test green — and they are kept because they are what a reader looks for.
  - **The allow's scope is POSITION, not the grant's own scope, and reading it the other way is the
    defect this fixed.** `subpath` at `Root` scope **or** for any path **strictly** inside the home,
    `literal` elsewhere. Position only ever widens: a `Root` grant reaches its entries wherever it
    sits, and `/usr/share/icu` is one outside the home. What position adds is a non-`Root` grant
    inside the home reaching its entries. Two exclusions carry the safety, and each is load-bearing:
    a path **outside** the home stays `literal`, because this block renders after the home deny and
    `/` is granted `Read` at `Dir` by the box's floor — a `subpath` allow on that ancestor would undo
    the deny; and **the home itself** is excluded, because a `Read` + `Dir` grant naming `~` passes
    every floor (`AnyOverlap` refuses a grant *inside* a credential row, and a Dir-scope grant on
    their common ancestor is not one), so `subpath` there would re-open every name in the home except
    the credential rows. `a_grant_naming_the_operator_home_itself_reaches_no_entry` is that pin, and
    it exists because **deleting the `!=` clause left all 155 tests green.**

    Keying on the grant's own scope alone shipped a **fatal** defect, not the non-fatal one recorded
    below. The workspace is granted `Read` at `Dir` — listable, nothing readable — so it answered for
    itself and for no entry beneath it. `Path.exists()` in Python converts `ENOENT`, `ENOTDIR`,
    `EBADF` and `ELOOP` to `False` and lets `EPERM` propagate, so
    a Strands agent handler died in
    `(Path.cwd() / "tools").exists()` while the Strands SDK built its `Agent`, before any model call,
    reporting `Operation not permitted` on a path that was never there. **The deny withheld less than
    the line above it disclosed**: `Read` at `Dir` renders `file-read-data` on the literal, so the
    workload already enumerated every name in that directory and was then refused `stat` on those very
    names.

    Cost: a granted tree inside the home answers existence for its descendants, so a workload maps
    that tree by guessing names where before it enumerated only the top level. `access(F_OK)` on a
    present descendant succeeds; contents, metadata values and `readdir` stay refused.
    **`<workspace>/.strands-box/box.toml` and its policy are in that set** — the two
    `policy::SELF_DEFENDED_FILES` — so their presence is disclosed and their bytes are not. Guards:
    `a_dir_grant_inside_the_operator_home_reaches_its_own_entries` and
    `an_entry_of_a_granted_directory_answers_and_an_ungranted_sibling_does_not`. Removing the position
    clause fails both; an unconditional `subpath` fails six, including three pre-existing kernel pins.
  - **`$TMPDIR` placement is load-bearing for every fixture now, because the filter reads position.**
    A `$TMPDIR` under the operator home makes `fixed_config`'s `File`-scope executable render
    `subpath`, and `every_grant_renders_an_existence_allow_at_its_own_scope` then fails naming the
    grant's scope as the cause. `fixed_config` asserts its root is outside the home for that reason.
    A test that means to sit inside the home sites its own fixture there and says so.
  - **A green containment suite did not cover this, and still may not cover the next one.** Before the
    fix, the only `Scope::Dir` grant in any macOS existence fixture was `/` — outside the home —
    because `profile_conformance.rs` builds from a tempdir and `contains_operator_home.rs` granted only
    `/` at that scope. So the one configuration **every real box uses** for its workspace was untested
    at both levels, and a change to the rule left all 155 tests green. Do not read this suite as
    covering the existence-allow scope rule without checking which scopes the fixture actually grants.
  - **The ancestor chain must carry the operation.** A tool searching upward for config from its
    `HOME` stats each parent, and `EPERM` there reads as "refused" where `ENOENT` reads as "keep
    looking". Removing the ancestor rule fails
    `contains_operator_home.rs::a_granted_path_and_its_ancestors_survive_the_home_deny` and nothing
    else.
  - **The caller's spelling gets `literal` and nothing wider.** The operation matches the
    pre-resolution path, measured: with only the resolved spelling allowed, a caller naming a link
    read `EPERM`, and adding the literal fixed it while a sibling through the link stayed refused.
    This is the second rule ever duplicated onto a caller's spelling, beside `file-read-metadata`,
    and it is strictly weaker than that one.
  - **The refusal on an empty set is load-bearing.** A caller renders one rule per path, so an empty
    list would render no rule and report success. `credential_store_paths` refuses instead.
  - **`~` itself stays disclosed on purpose.** The ancestor rule a granted path needs already grants
    metadata on the whole chain, and the workload's `HOME` is that same operator home.
    Hiding it buys nothing and would break the upward walk.
- **Enumeration is not one of the two operations the deny closes.** A `Read` + `Dir` grant on the
  operator home lists every name: `AnyOverlap` refuses a grant *inside* a row, and a Dir-scope grant
  on an ancestor is not one. Measured before this change — `readdir` returned 85 names including
  `.ssh` and `.aws` while `stat` and `access` on both reported `EPERM`. No floor entry asks for it and
  `workspace.rs` refuses the operator home as a workspace, so it is unreachable rather than closed,
  and nothing pins it. Never write that a credential store is unobservable.
- **One harness changed behaviour, and the operator accepted it.** An upward search for a config file
  no grant covers now reports "refused" rather than "absent", so `codex-cli-mcp-workload` logs
  `agents_md: error trying to find AGENTS.md docs: Operation not permitted` where it logged nothing.
  Non-fatal, and invisible in the exit code — it was found by diffing the log against a baseline run,
  which is how to check the next harness. Carving the harness configuration directories out of the
  deny was rejected: it would reopen the oracle beside a credential.
- **The AGENT box lifts this deny for nothing; a LEAF with `broad_exec` lifts it in its writable
  workspace
  ([the leaf toolchain decision](../../docs/design/decisions.md#a-leaf-runs-its-whole-toolchain-and-loads-what-it-builds)).**
  For the agent, `ContainmentConfig` carries `broad_exec` false, the renderer adds no
  `(allow file-map-executable …)`, and every agent profile keeps the deny. A leaf that calls
  `allow_broad_exec` renders one `(allow process-exec*)` and, over each writable grant, one
  `(allow file-map-executable …)` after the write-cell deny (last-match wins), so a build loads and
  runs what it compiles there; the relaxation is scoped to the leaf's writable grants and the agent
  keeps full W^X. A path that is both writable and executable is a startup warning rather than a
  refusal: `ContainmentWarning::WritableAndExecutable` names the two grants, and
  `lifecycle.rs::an_exec_grant_inside_a_write_root_warns_and_applies_beneath_every_backend` pins
  that the warning fires and the grants still apply. That the agent never renders broad exec is
  pinned by `seatbelt.rs::the_agent_profile_never_carries_broad_exec` (one `process-exec` rule per
  grant, never `process-exec*`), and the leaf carve-out by
  `a_leaf_carries_broad_exec_and_the_main_box_does_not` and
  `broad_exec_adds_a_map_exec_allow_overriding_the_write_cell_deny`.
- **Every write cell denies `file-map-executable`, and that is the fourth deny. It closes a measured
  write-xor-exec violation.** Before it, a contained workload wrote a valid dynamic library into its
  own home and `dlopen`ed it — measured 2026-08-30 on macOS 26.6.2 arm64, 100,512 bytes loaded
  inside a real box — so write-xor-exec held for `process-exec` and not for a library load. Neither
  the exec allowlist nor the other three denies reach that operation. Guards:
  `contains_exec_target.rs::a_library_written_in_the_home_cannot_be_loaded`,
  `every_writable_path_refuses_an_executable_mapping`, and the per-root leg of
  `every_read_write_root_renders_with_its_own_identity_denies`. Five things not to re-derive:
  - **The anchor must be canonical, or the rule enforces nothing.** `(deny file-map-executable
    (subpath "/tmp/x"))` was measured to permit the load, and the same rule spelled `/private/tmp/x`
    refused it. This is the canonical-path result applied to a deny: the kernel produces one path
    for the object, and a rule naming the other matches nothing. The write cells render `resolved`, so
    this holds today and would break silently if they ever rendered `original`.
  - **Blanket is not the fix, and it was measured.** `(deny file-map-executable)` refuses every
    file-backed executable mapping, a read-only root's included, which is where CPython's stdlib and
    every other runtime library comes from. So the deny is per write cell and never global.
    `a_traverse_root_renders_no_descendant_read_and_no_write` holds the "and nowhere else" half, and
    the in-box `dlopen` of a read-only root's library is the bound the kernel test asserts.
  - **The operation IS filterable in the allow direction**, canonically spelled, so a future box that
    needs one loadable path inside a writable tree has a shape available. Nothing needs it today.
  - **`mmap(PROT_READ|PROT_EXEC)` on a file is not the route, and a test that used it would be
    vacuous.** An unentitled process cannot map any file executable on this host — measured against a
    copy of `/bin/echo`, against `/bin/echo` itself, and against `/usr/lib/dyld`, all `EPERM` with **no
    containment applied**. dyld holds the privilege an ordinary caller lacks, which is why `dlopen` is
    the verb that measures the profile. `map-exec` ships and its test skips on the control, on the
    `chflags-sf` precedent.
  - **The functional cost is real and is the point.** A native module the workload builds inside a
    writable grant no longer loads. An `npm install` producing a `.node` addon under the workspace is
    the case to expect, and the answer is that such a tree belongs in a read-only
    `[agent.filesystem] read` entry.
- **A sandboxed process cannot exec a set-user-ID or set-group-ID file, and the kernel is what refuses
  it.** Measured 2026-08-26 on macOS 26.6 build 25G72, arm64, under `(version 1)(allow default)` — so
  no profile rule is involved. One binary compiled twice over: with the bit cleared it ran and
  reported `egid=20`; with `chgrp admin; chmod g+s` the same bytes gave
  `execvp() failed: Operation not permitted`. The five setuid-root platform binaries `/usr/bin/quota`,
  `/usr/sbin/traceroute`, `/usr/bin/su`, `/bin/ps`, and `/usr/bin/top` were each refused the same way.
  Two adjacent measurements from the same session: a nested `sandbox_init` returns
  `sandbox_apply: Operation not permitted`, so the workload cannot re-apply a profile at all, and a
  deny is inherited across fork and exec, so a `bash -c cat` grandchild met the same refusal.
  **Do not read this as the box's own closure.** The refusal is undocumented platform behaviour that
  no suite can see, `floors.rs` is what the box enforces, and Linux carries the property by wholly
  different means (`MS_NOSUID` on every mount, plus `setuid` and `setgid` in the seccomp table). What
  the floor buys on macOS is a startup refusal that names the bit, in place of an opaque `EPERM` the
  trampoline reports as its generic exec stage.
- **A copied Apple platform binary is not a control for anything.** `cp /usr/sbin/traceroute` then
  running the copy exits **137**, because the kernel kills it for a failed signature. The first attempt
  at the measurement above read that as a privilege refusal.
- **Every write cell also denies `file-write-acl`, and that deny reaches the flags deny's own harm
  without root.** `file-write*` carries the operation behind `acl_set_file(3)`, so a workload could
  store `everyone deny write,delete` on a file in its own writable grant; the operator, outside any sandbox
  and as that file's owner, then read `rm: Permission denied` and `rm -rf: Directory not empty`.
  Deleting a box directory is one `remove_dir_all`, so it fails exactly as one `UF_IMMUTABLE` made
  the withdrawn `rm` and `reset` verbs fail. Recovery is an out-of-band `chmod -R -N`, the counterpart of
  `chflags -R`. Guards: `every_writable_path_refuses_an_access_control_list`,
  `contains_exec_target.rs::the_agent_cannot_set_an_access_control_list_in_its_own_home`, whose last
  assertion is the operator's own `remove_dir_all`. Four things not to re-derive:
  - **The deny costs nothing ordinary.** `echo hi > f && chmod +x f && rm f` still works with it
    rendered. Nothing ordinary sets an ACL, so this is the flags case and not the mode case.
  - **`clonefile` is NOT a residual here**, unlike the flags. Measured with the deny rendered: `cp -c`
    and `cp -p` from a source carrying a deny ACL both produced a destination with no list, and the
    tree removed cleanly afterwards. Do not copy the flags residual across by analogy.
  - **`file-write-xattr` is not a second route.** An ACL'd file lists no user-visible attribute name,
    so leaving that operation granted opens nothing. Measured with `xattr -l`.
  - **`acl_delete_file_np` answers `ENOTSUP`**, so `acl_probe` restores by setting an empty list from
    `acl_init(0)`. The `libc` crate declares none of the five ACL calls; `test_probe.rs` declares them.
- **`chmod-mode`, `chown-self`, and `acl` refuse a target this process does not own.** All three
  operations are owner-or-root, so DAC answers before the profile does, and `/dev/null`, the grant
  the write-cell attribute denies exist for, is exactly that shape. Without `require_owned`, an
  `expect-deny` probe pointed at it passed with every deny removed. This is `chflags_probe`'s rule
  applied to three more verbs: every inconclusive outcome is an `Err`, never a `false`.
- **`write-open-modes` is a canary, not a pin.** It measures what the kernel does with `O_CREAT` on an
  existing file, not what the renderer emits, so removing the file cell's create deny leaves it green.
  Keep it — it catches a change that made the deny bite, which would break `> /dev/null` everywhere —
  but do not count it as the create deny's guard. `a_granted_file_itself_cannot_be_replaced` is that.
- **The write cells name the leaves they need and never `file-write*`. That is the whole shape, and it
  replaced five subtractive denies.** `WRITE_ROOT_LEAVES` in `seatbelt.rs` is the list — `data`,
  `create`, `unlink`, `xattr`, `mode`, `times` — and the `Write`+`File` cell names `data` alone. The
  flags, the access-control list, the owner, and the set-user-ID bit are **absent rather than denied**,
  so `(deny default)` refuses each. The bound operations were enumerated by compiling one profile per
  candidate name: the six above beside `owner`, `setugid`, `flags`, `acl`, `mount`, `unmount`, and
  `finderinfo`, and `file-clone`, `file-link`, `file-revoke`. `file-write`, `file-write-mknod`,
  `file-write-device`, and `file-write-truncate` are unbound variables and do not compile.
  - **A leaf deny cannot reach what `setattrlist(2)` dispatches to, and that is why the shape changed.**
    Seatbelt dispatches that call per requested attribute. Measured 2026-09-11, macOS 26.6.2 arm64 at
    `euid` 503, under the five-deny shape: `ATTR_CMN_ACCESSMASK` stored 0777, `ATTR_CMN_GRPID` moved gid
    20 to 12, and `ATTR_CMN_EXTENDED_SECURITY` stored a list — each while its own leaf deny was
    rendered, and each refused by an uncontained control's absence rather than by the profile. Only
    `ATTR_CMN_FLAGS` was caught. Bisection over all eleven leaves found **no leaf deny reaches the
    other three**: they ride the wildcard, and the only rule that refuses them is `(deny file-write*)`,
    which removes writing. An allowlist never has to name the operation, which is what closes it.
    Proof the two differ: with `file-write-mode` **allowed**, `ATTR_CMN_ACCESSMASK` is still refused.
  - **Apple uses this idiom itself.** `/System/Library/Sandbox/Profiles/` grants `/dev/null` as
    `(allow file-read* file-write-data (literal "/dev/null"))` and holds 46 bare `file-write-data`
    allows. There is no Apple SBPL reference — `strings` over `libsandbox.1.dylib` and the Sandbox kext
    yields no operation table — so those profiles plus compile-and-measure are the authority.
  - **`file-write-times` IS closable, by omission.** The earlier reading was that no leaf deny takes it
    back, which is true and is not the same claim: `touch -t` succeeds under `(allow file-write* …)`
    with `(deny file-write-times …)` rendered. Withholding the leaf refuses it outright. The leaf stays
    granted on the write root anyway, because `utimes` is ordinary work, so the backdating residual is
    a decision now rather than a limit.
  - `finderinfo`, `mount`, and `unmount` are no longer granted at all, because no cell names them.
    `xattr` is named because ordinary work sets one, and `mode` because a workload tightens a file it
    created — Claude Code creates `.claude.json` at 644 and `chmod`s it to 600, and **swallows the
    failure**, so withholding the mode leaves a config holding `mcpServers` world-readable.
- **Seatbelt resolves a rule by operation-name specificity BEFORE rule order, and this nearly shipped a
  hole.** A leaf allow beats a wildcard deny on a more specific path, whichever comes first. Measured
  both directions: `(allow file-write-data (subpath D))` with `(deny file-write* (literal D/f))` after
  it **wrote**; the same pair with the deny first also wrote; and a leaf deny in either position
  refused. So converting the write cells to leaves silently defeated `protect_write`, whose
  `(deny file-write* (literal …))` stopped overriding the cell — the authority object became writable
  while every string-assertion test stayed green, and `contains_exec_target.rs` is what caught it.
  **Every deny that must override a write cell now renders the wildcard AND one deny per leaf**, from
  the same `WRITE_ROOT_LEAVES` list, in `write_leaf_denies`. Two callers need it: `protect_write` and
  `refusals()`, the second being the operator's own `deny = [...]` over a path inside a write root.
  - **The read side has the same shape and is unexamined.** `refusals()` renders
    `(deny file-read* (subpath …))` while the `Read`+`Dir` cell renders `file-read-data` and
    `file-read-metadata` leaf allows, so a read grant nested inside a refused tree would win. Whether
    the floor refuses that pair is not established. Pre-existing, and not introduced here.
- **A `Write`+`File` grant may not sit inside a `Write`+`Root` grant, and `floors.rs` refuses the
  pair.** The file cell denies a literal, and a specific deny beats an enclosing `subpath` allow, so
  the nested path lost the mode, the owner, and its identity while every sibling kept them. Measured
  in render order: `chmod g+w` and `rm` on the nested literal both gave `EPERM`, and the sibling
  permitted both. This became reachable only when the file cell gained those denies — before that its
  one deny was the flags, which the root cell denied too, so nesting cost nothing. Guard:
  `a_write_file_inside_a_write_root_is_refused`, whose control asserts the same grant outside every
  write root still renders — without it the floor would refuse `/dev/null`.
- Describe a rule in an `.sb` comment in prose, never by quoting rule syntax — absence assertions run
  on a comment-stripped view, and a comment would answer them.
- **The no-inherited-handle rule holds for descriptors and cannot hold literally for a Mach right.**
  The trampoline's `close_inherited_descriptors` is `cfg(unix)` and reads `/dev/fd` here, so the
  descriptor half was always enforced on macOS and only untested. Five things measured 2026-08-30,
  macOS 26.6 arm64, through the trampoline so the target is `exec`'d.
  `tests/inherited_handles_macos.rs` holds the detail.
  - **A contained workload holds 11 Mach port rights after the target `exec`.** `exec` preserves the
    task's port namespace and no close-on-exec flag applies to a right, so zero is unreachable. Do not
    write that macOS inherits no handle.
  - **`(deny default)` is what refuses a service lookup, and the profile needs no `mach-lookup` rule.**
    Adding one `(allow mach-lookup)` line let the inherited bootstrap right reach
    `com.apple.pasteboard.1`, `com.apple.system.notification_center`, and `com.apple.SecurityServer`
    with a live port. The uncontained control reaches all three, which is what attributes the refusal.
  - **`TIOCSTI` on the inherited PTY slave is refused by the *platform*, not by the profile.** The
    uncontained control measured the same `EPERM`, so the `file-ioctl` grant is not what closes it.
    Re-measure with the control if a macOS release changes this; a restored `TIOCSTI` would be a write
    into the operator's own terminal input.
  - **A census with no planted descriptor asserts nothing.** Rust marks every descriptor it creates
    close-on-exec, so deleting the trampoline's closure entirely left both descriptor tests green
    until each planted a non-`CLOEXEC` descriptor at 10 and at 900. Each census also asserts it found
    stderr, because an unavailable census reported an empty table and read as a pass.
  - **An in-box probe must not read `/dev/fd`.** The box's floor does not grant it. Use
    `proc_pidinfo(PROC_PIDLISTFDS)` on self, which `(allow process-info* (target self))` permits, and
    fall back to an `fcntl` sweep — never a directory read. Treat a **full** reply buffer as a
    truncated list and sweep instead, because an under-reporting census is the one failure the whole
    test rests on not having.
  - **`cargo test --test box_inherited_handles` does not rebuild the trampoline.** It runs against
    whatever `target/debug/strands-box-contain-trampoline` holds, so a defect injected into the
    trampoline reports a **pass** until `cargo build -p strands-box-containment` runs. Rebuild before
    trusting any result from that suite. Pre-existing, and the macOS production test now depends on it
    too.
  - **The high planted descriptor number cannot be a constant.** `F_DUPFD` fails with `EINVAL` when
    the minimum is at or above the soft `RLIMIT_NOFILE`, and **macOS ships that limit at 256** while
    Linux ships 1024. The Linux suite's `900` therefore aborted both macOS tests at setup on a stock
    host, and passed only because this shell had a raised limit. Raise the soft limit toward the hard
    one, then derive the number from `getdtablesize()`.
- **`(ioctl-command N)` is a real SBPL filter and it did not discriminate. Do not reach for it to
  narrow the tty grant.** `file-ioctl` cannot tell `TIOCSTI` from `TIOCGWINSZ` today. Measured
  2026-08-30 on macOS 26.6 arm64, with `openpty` plus `TIOCGWINSZ` as the subject and the correct
  constants read from `<sys/ioctl.h>` (`TIOCGWINSZ` 1074295912, `TIOCSTI` 2147578994):
  - The filter **exists and is type-checked**. A string argument is refused with
    `invalid data type of ioctl-command filter; expected integer, got string`, and an invented filter
    name is refused as `unbound variable`. So it is not being silently ignored as unknown syntax.
  - It **matched nothing** in five forms: decimal, `#x` hex, the low request byte, inside a
    `require-all` with a path, and as an `allow` narrowing a blanket deny. As a deny it never fired;
    as an allow it never rescued.
  - **The positive control fires in the same profile.** A bare `(deny file-ioctl)` refuses `openpty`
    with `Operation not permitted`, so the operation does reach the sandbox and the subject is
    mediated. That is what makes the negative result mean something.
  - **`#x` hex aborts in one position.** `(deny file-ioctl (ioctl-command #x80017472))` alone in a
    minimal profile exits **134** with no message at all, while the decimal form compiles. Read an
    unexplained `sandbox-exec` abort as a literal-form problem before doubting the filter name.
  - Not proven: that the filter is inert for every operation and every macOS version. Proven: it is
    not usable to narrow this grant today. A pty interposition is the mechanism
    that would close it.

## Linux, measured

### The seccomp filters permit, then restrict

- The permit filter returns `EPERM` for every syscall outside `WORKLOAD_PERMITTED`. A new syscall
  stays denied until measured evidence and a compatibility rationale justify its addition.
- The restriction filter then applies complete or argument-scoped denials from `MEDIATED`. Stacked
  seccomp filters select the most restrictive result, and a workload cannot remove either filter.
- Permit these nested-namespace operations: `clone`, `clone3`, `unshare`, `setns`, `umount2`,
  `pivot_root`, and `chroot`. They change only copied views. If a workload removes a copied bind,
  it reveals fresh content in the scaffold or content from an authorized ancestor.
- **Deny the whole mount-creation API by number**, not `mount(2)` alone: `open_tree`, `move_mount`,
  `fsopen`, `fsconfig`, `fsmount`, `fspick`, and `mount_setattr`. Delete none as redundant.
- **Restrict `socket()` by negative match**, family != AF_UNIX and != AF_INET. A denylist let `AF_ALG`
  and `AF_RDS` through.
- **Deny `io_uring_setup` beside `socket(AF_INET)`**, because `IORING_OP_SOCKET` needs no `socket(2)`
  since 5.19 and seccomp cannot read a ring's SQEs.
- **Take every number from `libc`**, never a hand-written `#ifdef` table. Fix a missing name upstream;
  never `#[cfg]` it away.

### W^X

W^X closes three routes. Every writable mount, including `/tmp`, uses `MS_NOEXEC`. The permit filter
denies `memfd_create`, all `execveat`, and all `pkey_mprotect` calls. The restriction filter denies
`mmap` with `PROT_WRITE|PROT_EXEC` and `mprotect` with `PROT_EXEC`. Scope `mmap` to both bits or the
loader breaks (`a_read_execute_mapping_is_still_permitted`,
`route_three_write_then_execute_is_refused`).

**W^X protects the `fs:*` enforcement point, not the kernel boundary.** It does not stop the workload
running code of its own choosing. An exec view is safe only when no reachable program is
universal over authored data: no interpreter, no FFI runtime, and no `find -exec`, `xargs`,
`tar --to-command`, or `git -c core.pager`.

### A refused call whose wrapper cannot fail

**Adding a call to the permit table is not only about compatibility; leaving one out can corrupt a
result instead of failing it.** `umask` has no failing return, so the filter's `EPERM` reaches the
caller as a mask of every bit. A linker read that mask, added the execute bits it left, and wrote
output nothing could run — with every call it made reporting success. When you leave a call out,
check what its wrapper returns on failure, and pin the *effect* rather than the answer.

### The namespace launcher

- Read uid and gid **before** the user-namespace unshare, and write `deny` to `setgroups` before the
  GID map.
- **Create the PID namespace before mounting `/proc`**: the kernel refuses a procfs for a namespace
  the caller is not in, and `mount("proc", …)` returns `EPERM`.
- `pivot_root`, never `chroot`. Create the old-root mountpoint before sealing the root, and assert it
  is empty.
- **A read-only bind is two mount calls**, because `MS_BIND` ignores `MS_RDONLY`.
- `MS_NOSUID | MS_NODEV | MS_NOEXEC` on every fresh filesystem and on the root's final remount. Omit
  `MS_NODEV` on a device bind, or `/dev/null` stops working.
- Create the staging root with `mkdir`, never `create_dir_all`, on a name suffixed from
  `/dev/urandom` and never from the pid.
- **`remount_read_only` walks `/proc/self/mounts` and remounts deepest first**, because `MS_REMOUNT`
  ignores `MS_REC`. Unescape octal space, tab, newline, and backslash.
- Resolve `DT_NEEDED` through the image's `DT_RUNPATH` (or `DT_RPATH`) with `$ORIGIN` expanded,
  then the executable's, then a fixed per-architecture list, never `LD_LIBRARY_PATH`, never
  `/etc/ld.so.conf`, and never a hardware-capability subdirectory; refuse an unresolved name. The
  list is `/lib64` and `/usr/lib64`, plus the arch's Debian multiarch triplet under `/lib` and
  `/usr/lib`, plus plain `/lib` and `/usr/lib` — the multiarch entries are what hold `libc.so.6`
  on Ubuntu, and dropping them refused `/usr/bin/dash` at plan time. The walk is transitive
  through every library found outside those directories, and each such library is judged by the
  floor as a read grant, so a `DT_RUNPATH` cannot reach a credential store. `image_needs` reads
  the headers and two segments, never the whole file — `codex` is 297 MB.
- A read root on a loader directory is bound executable, because a mount cannot separate
  `mmap(PROT_EXEC)` from `execve`; a dependency beneath a planned exec-capable tree is not bound
  again. `a_read_root_on_a_loader_directory_is_bound_executable_and_read_only` and
  `a_dependency_a_loader_directory_covers_is_not_planned_twice` pin both.
- **`apply` returns in the workload process, namespace PID 2**, so depend on no stable `getpid()`.
  Namespace PID 1 forwards `SIGTERM` and `SIGINT`, stores the workload pid *before* installing the
  handlers, and reaps in a loop.
- **`netns`:** a socket's namespace is fixed at creation, so bind inside and pass the descriptor out
  over `SCM_RIGHTS` with at least one data byte. Bring `lo` up, and precede `SIOCSIFFLAGS` with
  `SIOCGIFFLAGS`. `CAP_NET_ADMIN` is unavailable in the host namespace, and an AF_UNIX proxy cannot
  serve `HTTPS_PROXY`.

### Privilege drop

Close inherited descriptors while `/proc/self/fd` is enumerable, clear every capability set including
bounding and ambient, set `no_new_privs`, then install seccomp **last**.

- Post-fork code is syscall-only: no allocation, no `format!`, no panic, and `_exit` never `exit`.
- `verify_closed` takes the attempted list, never a re-enumeration.
- After seccomp the workload may only `read`/`write` its sync socket: it may not `sendmsg`, and the
  observed program refuses `seccomp`, so nothing is stacked after it. PID 1 copies the listener out
  with `pidfd_getfd` and sends it on the relay socket; the workload closes its relay copy right
  after the fork and its listener before `exec`. PID 1's copy check runs only after the workload
  drops its capabilities, or the capability-subset check refuses it.

## The trampoline

`strands-box-contain-trampoline --config <file> --config-sha256 <digest> --target-env-json <json> --
<command> [args...]`. Read and unlink the config, verify the digest, apply once while
single-threaded, then decode the target environment and exec with a cleared environment. Reject an
empty name, `=` or NUL in a name, and NUL in a value. `--relay-control-fd` is Linux-only.

| Code | Meaning |
|---|---|
| 2 | usage or setup error before containment |
| 3 | `apply` failed; containment incomplete |
| 4 | contained, but target-env decode or `exec` failed |

`containment-test-probe` stays under `tests/support/` behind `test-support`.

## Open gaps and residuals

- **A read grant confers exec on Linux and not on macOS.** A read-only bind preserves exec, so
  `python3` in a read-granted tree runs. `Read` + `File` is refusable cheaply; `Read` + `Root` is
  not.
- **The view leaves 14 paths `execve`-able where the box grants 5.** The extras are `ld.so`, seven
  mode-`0755` libraries, and the workload's second spelling. None runs authored bytes, and `MS_NOEXEC`
  cannot remove a library without mode-`0444` copies.
- **The identity floor judges the exec grant set, not every runnable file, and its name is wider than
  its check.** Three routes stay outside it, and `MS_NOSUID` on every bind is what closes all three on
  Linux, while macOS renders no `process-exec` for a read grant at all — so none is a hole, and each
  is a place the floor stops rather than a mechanism that is missing.
  - **`Read` + `Root`**, because a read grant confers exec on Linux (the residual above). Closing it
    in the floor means walking every granted tree.
  - **`Read` + `File`**, the same class, which is refusable cheaply. It is the cheap half and it is
    still open.
  - **A Linux file capability** — the `security.capability` xattr — which is a privilege
    route that two mode bits cannot see. `no_new_privs` closes it beside `MS_NOSUID`. There is no
    macOS counterpart.
- **Write-xor-exec is enforced over the grant *set*, not transitively.** `floors.rs` is pairwise over
  (exec grant, write root), which is complete for the grant set — "writable" is exactly "inside some
  write root". What it does not cover is a reachable interpreter universal over authored data, which is
  the residual above rather than a hole in the check.
- **On macOS, existence still answers outside the operator's home.** A workload can learn that
  `/bin/bash` is there and that a name beside it is not, over both `access(F_OK)` and `stat`'s errno.
  A machine-wide deny refuses the workload's own exec, so this is scoped rather than closeable.
  Existence only: no contents, no metadata value, no enumeration, and weaker than the `/private/tmp`
  metadata grant already accepted.
  `an_ungranted_path_outside_the_operator_home_still_answers_existence` is what stops it being
  described as closed.
- **`cargo test --workspace` stops at the first failing binary, and `scripts/test-all.sh` passes no
  `--no-fail-fast`.** So a pre-existing failure in `strands-box` hides every later crate, containment
  included. Always add the flag. Three failures are pre-existing, each confirmed by reverting this
  crate to its base commit: `box_shell.rs::the_shims_shell_has_no_network_path` (also flaky),
  `mcp_schema_generation.rs::non_utf8_home_and_workspace_paths_keep_their_approved_identity`, and
  `python_handler_e2e.rs::a_typescript_handler_is_not_refused_for_its_extension`, which needs Node 22.
- **Write-xor-exec's third clause is not met on macOS, and the reason is the workload's own
  program.** The rule counts three things as executing: running a file, loading it as a library, and
  *running it through a permitted interpreter*. The first two are closed and measured — the exec
  allowlist and the write cells' `file-map-executable` deny. The third is open by design, because
  the one program the profile grants `process-exec` on is frequently a language runtime: a
  Bun-compiled or Node harness reads a file the box wrote in its own home and evaluates it in
  process. No kernel operation happens that any rule could refuse, so this is not a hole in the
  profile and cannot be closed by one.
  - **No approval covers it today, and claiming one does is the mistake to avoid.** An approval must
    name the executable *and the writable locations it may interpret*. `ContainmentConfig` has no such
    field, and an `Exec` grant is not that approval, so the leg is open rather than approved. The honest
    statement is: a box cannot run code it wrote *as a process or as a library*, and its own agent can
    still evaluate that code in memory. Do not write "write-xor-exec holds on macOS" without that
    qualifier.
  - **It is a mediation and audit gap rather than an authority gap**, on the same terms as the
    writable-memory residual: the evaluated code inherits exactly the grants the profile already made,
    and what it escapes is the `fs:*` and `shell:*` decision layer. The box's answer for a program that
    should be governed is the broker socket, and containment cannot make a runtime use it.
  - **Linux does not close it either.** `MS_NOEXEC` and the mapping denies stop a file becoming a
    process; neither stops a runtime reading a file and interpreting it. The AGENTS.md W^X section says
    the same thing in its own words: an exec view is safe only when no reachable program is
    universal over authored data, and the harness always is.
- **`ioctl` is permitted wholesale on Linux, and nothing filters `TIOCSTI`. Unmeasured, and Linux is
  the more exposed platform.** `ioctl` sits in `WORKLOAD_PERMITTED` with no `MEDIATED` entry, so no
  request number is scoped. The workload's descriptor 0 is the operator's real controlling terminal on
  both platforms: `terminal.rs` hands the terminal to the child's process group and the box calls no
  `setsid`. On macOS Apple's kernel refuses `TIOCSTI` — measured, and by the platform rather than by
  the profile. Linux's historic check permits it with **no capability** when the descriptor is the
  caller's own controlling terminal, and the `dev.tty.legacy_tiocsti` sysctl that closes it arrived in
  6.2. So the target kernel decides, and nobody has run the probe.
  - **Measure before designing.** Drive `ioctl(0, TIOCSTI, &byte)` from a contained workload on a real
    terminal, with an uncontained control, exactly as `tests/inherited_handles_macos.rs` does.
  - **Unlike Seatbelt, seccomp can express the narrow denial.** The request number is `arg1`, a
    scalar, so an `ArgumentScoped` entry is the same shape `mmap`, `mprotect`, and `execveat` already
    use. That is a cheap floor whichever way the measurement goes.
- **The reach modes have one legal value each.** Both backends refuse every non-default `SignalMode`,
  `ProcessInfoMode`, and `IpcMode`, so those four exported enums describe a widening the product does
  not offer. Kept deliberately for a future backend that honours them.
- **The Shell's `resolve_host` still trusts a re-resolved path string**, in its exact-match arm and
  under an ancestor swap. Only the box can replace a bind root today, so give nothing else write
  access beside one.
- **`FORBIDDEN_PATHS` and the kernel recognize different spellings of one directory, and the box is
  safe only because they disagree in the refusing direction.** Measured by
  `tests/support/check-firmlink-floor.sh`. A grant on
  `~/.ssh` is refused with "this path holds a credential". The same directory granted as
  `/System/Volumes/Data/Users/<user>/.ssh` **passes every floor** and reaches `sandbox_init`, because
  `realpath` does not collapse a firmlink and the row's anchor matches only one of that directory's
  two canonical names.
  - **No secret is exposed, and the reason is narrower than "the rule matches nothing".** The *data*
    rule matches nothing: `(allow file-read* (subpath "/System/Volumes/Data/…"))` names a path the
    kernel never produces for that object, and `check-firmlink-floor.sh` measures exactly that. **The
    ancestor rule is a different matter.** `Read` + `Root` renders `ancestor_rule` beside the subpath
    allow, so the grant also emits
    `(allow file-read-metadata (path-ancestors "/System/Volumes/Data/Users/<user>/.ssh"))`, and that
    chain includes `/`, `/System`, `/System/Volumes` and `/System/Volumes/Data` — every one a real
    canonical path. So the grant confers surplus authority rather than none. It is stat-only on four
    directories whose existence is public, and a workload may stat what it cannot read, so the
    conclusion holds. `Metadata` + `Root` renders the same chain. **The census cannot catch this**,
    because `file-read-metadata` is already in its expected set.
  - What is wrong is that two independent mechanisms disagree and nothing checks. `box` treats this
    floor as the only credential check for an `[agent.filesystem] read` entry, so the shape outlives
    this one outcome. **Do not fix it by adding a `/System/Volumes/Data` row** — that is one more
    anchor for one more spelling. Collapsing a firmlink inside `PreparedFilesystemPath`, or refusing a
    path under `/System/Volumes/`, are the two shapes to consider, and each narrows what a grant may
    name, so each needs the user's approval under the freeze.
- **`fs_snapshot(2)` is CLOSED by an exact-name deny, and the census was never closing it.**
  `fs-snapshot-mount` is one of the operations `(version 1)` grants unconditionally, so the census
  argument — which counts rendered allows — reported a closure that was not there. The profile now
  denies all four `fs-snapshot-*` leaves by name. A `fs-snapshot*` wildcard would have left the mount
  reachable, which is the trap recorded above. Still unmeasured behaviourally: no probe verb reaches
  the syscall, and the root leg needs a snapshot to exist, so the evidence is the compiler oracle
  flipping when the line is deleted.
  `sandbox_extension_consume` is closed by transitivity: `require_expressible` refuses every
  non-`None` `BackendOverride`, so no box turns extensions on, and a token needs an issuer the empty
  bootstrap namespace does not reach.
- **The root leg of `mount`, `unmount` and `chroot` is unmeasured, and only `chroot` has a probe that
  could measure it.** All three reach the privilege check before the profile, so an ordinary user reads
  `EPERM` whether or not a rule refuses — the same vacuity `chflags-sf` has.
  `tests/support/measure-i3-as-root.sh` drives the `chroot` leg with its uncontained control, and
  nobody has run it. Record the result here when somebody does.
  - **`mount` and `unmount` have no root probe that is both safe and conclusive**, so do not add one to
    that script. `mount_probe` passes a NULL `data` pointer: as root the privilege check passes and the
    apfs VFS then rejects the arguments, which `privileged_outcome` reports as an error because an
    argument rejection is not a refusal. Building a valid argument would mount a real filesystem over a
    live path on the operator's machine. `unmount` of a live volume answers EBUSY, which is again not
    the profile, and forcing it would tear down the running system. The census closes both for root.
- **Six probe verbs are script-only, on the `chflags-sf` precedent.** `link`, `symlink-escape` and
  `openat-escape` need no root and are still reached only from `tests/support/run-i3-matrix.sh`;
  `mount`, `unmount` and `chroot` need root and are reached only from there and from
  `measure-i3-as-root.sh`. No gate runs either script, so the matrix's own numbers are a recorded
  measurement rather than a test. Promoting the first three is cheap and worth doing.
  - **`link_probe` has no time bound**, and the `/private/etc/passwd` hang above is why that matters. A
    test that called `link` on such a target would hang rather than fail. `run-i3-matrix.sh` bounds it
    from outside with a 30-second poll. Bound the verb itself before any test calls it.
- **`run-i1-matrix.sh` is a recorded measurement, not a gate.** Eleven routes, and it prints each raw
  outcome beside its uncontained control rather than a pass. Last run 2026-08-30 on macOS 26.6.2 arm64
  at `euid` 503: every control PERMITTED except the `mmap` one, every boxed write-then-execute and
  write-then-load REFUSED, and the read-only root's own load PERMITTED. Re-run it after any change to a
  write cell, because the census counts allows and cannot see one of these denies.
- **V8 does not degrade under W^X; it aborts. Measured 2026-09-20** on Node 20.20.2, ARM64, kernel
  6.18: it asks for `mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)` and has no protection-key path on this
  architecture. JavaScriptCore absorbs the refusal and falls back to its interpreter in silence, so
  throughput there is still unmeasured. `PR_SET_MDWE` is unavailable on 5.10.
- `egress-gateway` asserts it writes no key material only in a `#[cfg(test)]` test.
- **Two tests go vacuous if misconfigured:** the capability-drop test needs a user namespace, and
  `blocked_mode_leaves_no_route_at_all` must assert loopback is unreachable.
- **Nothing here refuses or detects root.** `facade.rs` and `floors.rs` judge paths and never the
  caller, and the one `geteuid` in the tree is a permitted-syscall table entry in
  `backend/linux/namespace/syscall.rs` rather than a check. **A Seatbelt `deny` binds root**,
  measured 2026-08-31 with a control for each row, so the setuid bits, device nodes, both flag
  classes, the write root's own identity, and every ungranted path are all refused at `euid` 0.
  - **`file-write*` carried `file-write-owner`, and the leaf allowlist is what took it back. CLOSED
    2026-09-18, measured at `euid` 0 with a control.** The old record read: `chown` to a foreign uid
    **succeeds** at `euid` 0 inside a write cell, invisible non-root because DAC refuses first.
    `/dev/null` is a `Write`+`File` grant in `base.toml`, so a root-mode box reached a system device
    node's mode and owner. Under the narrow cell — `(allow file-write-data (literal …))` alone — all
    five routes are refused at `euid` 0 on a root-owned fixture: `chmod`, `setattrlist ACCESSMASK`,
    `chown`, `setattrlist OWNERID`, `setattrlist EXTENDED_SECURITY`. The control renders today's old
    shape on the same fixture and reaches three of them, which is what attributes the refusal to the
    cell. Never `/dev/null` in the measurement: `tests/support/` holds the script and it builds a
    root-owned file in its own `mktemp` directory, because `chmod 000 /dev/null` breaks the host until
    reboot.
    - **The old matrix row saying `chown` succeeds is stale twice over.** An owner deny added on
      2026-08-30 closed the `chown(2)` route, leaving only `setattrlist`; the leaf allowlist then
      closed that too. A reader who takes the row at face value re-derives a threat that is now shut.
  - **`file-write-setugid` is a separate operation outside the `file-write*` wildcard**, so
    `(deny default)` refuses it and no write cell renders a rule for it. Proven both ways:
    `(allow file-write-setugid …)` parses and makes the bit stick, and
    `contains_exec_target.rs::the_agent_cannot_set_a_setuid_bit_in_its_own_home` fails when it is
    added. That test needs no root, because the owner may set the bit on their own file. No write
    cell renders a rule for it.
  - **The set-user-ID refusal has two shapes, and a return-code probe reads one as success.**
    `fchmodat(2)` — what `/bin/chmod` calls — gives `EPERM`. `chmod(2)` — what Rust and Python call —
    **returns 0 and stores nothing**. So `chmod_bit_probe` judges the *stored bit*, which is the
    opposite of `chflags_probe`'s rule, where `UF_COMPRESSED` made permitted-but-not-kept
    inconclusive. Read both probes before changing either.
  - **`setgid-bit` is attributable only when the fixture owns the file's group**, like `chflags-sf`:
    POSIX lets the kernel clear that bit silently for a caller outside the group.
  - **Device-node creation is refused by `file-mknod`, and the rule CAN be named after all.** `mkfifo`
    inside a write cell succeeds, so `file-write-create` covers a FIFO — yet `mknod` of a block device
    is `EPERM` at `euid` 0, with the control creating it fine outside. The three names tried earlier,
    `file-write-mknod`, `file-write-device` and `file-make-device`, are all unbound; the real one is
    `file-mknod`, one word and no `write`. Apple's own prelude states the mapping, and the operation
    sits in `file*` but not in `file-write*`, so no write cell ever granted it. The profile now denies
    it by name, which makes the closure falsifiable — delete the line and the compiler oracle flips.
    One XNU hook, `mac_vnode_check_create`, serves both calls and Sandbox splits it on the vnode type,
    which is why one succeeded and the other did not.
  - **The anchor divergence is CLOSED**, by
    [the floor anchor decision](../../docs/design/decisions.md#a-caller-adds-a-floor-anchor-and-never-moves-one).
    `anchor_homes` resolves every `~/` row at the passwd home **and** at the home the config states,
    so the two no longer have to agree. Measured under `sudo -E` before the fix: `$HOME`
    `/Users/<operator>` against a passwd home of `/var/root`, so all 15 credential rows matched
    nothing and a read root on the operator's `~/.aws` applied. Three things not to re-derive. The
    union is **additive**, which is the whole safety argument — replacing the anchor is the floor the
    caller moves and is what `a_declared_home_never_replaces_the_passwd_anchor` refuses; measured
    under the override, the profile rendered `(allow file-read* (subpath "<passwd home>/.ssh"))`. The
    floor cannot read `$HOME` for itself, because the trampoline is spawned with `env_clear()`. And
    the residual is caller honesty: a config stating no home gets the passwd anchor alone. Two guards
    cover that. One is behavioural and is the one that remains:
    `box_filesystem.rs::a_credential_store_is_refused_beneath_a_grant_and_disclosed_when_named_exactly`.
    It works precisely because **every fixture home in the suite diverges from the passwd home**
    (`FIXTURE_HOME_PARENT_TEXT` is `/var/tmp`). The source-reading guard beside it is deleted, and it
    was the weaker one: it read the config rather than the profile, and it still failed on a host
    where the two homes agree. So no test states the anchor itself.
  - **The Linux launcher writes `uid_map` as `0 <uid> 1`**, which under real root is `0 0 1`, so the
    workload's in-namespace uid 0 is host uid 0. Capabilities are still all dropped, so no flag or
    mount authority survives — but nothing detects the collapse. Still open.
  - **Linux: `fchmod` and `fchmodat` are permitted with no argument scoping**, and a bind shares its
    inode with the host, whose mount has no `nosuid`. So `MS_NOSUID` holds inside the view and the
    bit still lands outside it. Unmeasured — read from `syscall.rs` and `view.rs`, and no Linux
    target was exercised. Seccomp **can** scope this, unlike the macOS flag argument, because the
    mode is a scalar.
