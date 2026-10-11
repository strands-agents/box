//! strands_det_harness — the shared library every deterministic case `use`s.
//!
//! # Adding a test case
//!
//! Create ONE file under `tests/<category>/` named after the case id, e.g.
//! `tests/policy/po_9.rs`:
//!
//! ```ignore
//! use strands_det_harness::det_case;
//!
//! det_case! {
//!     name: po_9,                       // a valid Rust fn name (snake_case)
//!     id:   "PO-9",                      // the case id (also the verdict.json id)
//!     desc: "Shell gate: 'git status' is refused with no shell:spawn permit",
//!     run: |b| {
//!         b.reset_policy();
//!         let r = b.run_mediated("git status");
//!         r.assert_spawn_denied("git");
//!         r.assert_absent("fatal:");     // git never ran: no output of its own
//!     }
//! }
//! ```
//!
//! That's it. Cargo auto-discovers the file (no registry to edit), the case runs
//! in its own fresh box, and it records its own row in `verdict.json`. Category is
//! derived from the id prefix (`CN-*` → containment, everything else → policy).
//!
//! A case that only applies to one platform declares it — `platforms: [Linux]` or
//! `platforms: [Macos]` after `id:` — and records a `SKIP` row elsewhere. Do not
//! `return` early from the body instead: a body that launches no workload or makes
//! no assertion is recorded as `ERROR`, not `PASS`.
//!
//! # Two routes into the box, and denial evidence at its enforcement point
//!
//! `[agent] command = ["bash"]` resolves on the declared search path to the HOST
//! bash, which the box runs natively contained (namespaces/seccomp, Seatbelt).
//! Its builtins (`read`, `printf`, redirections) are the agent's own syscalls, and
//! a program it execs is a native exec — nothing passes the broker. The box puts
//! its alias directory first on that workload's PATH, so only an explicit alias
//! invocation (`zsh -lc …`, `python3 -c …`) enters the broker: the hosted Strands
//! Shell, or Monty. The Core suite drives the Shell the same way
//! (`box_shell.rs`: native bash running `zsh -lc "…"`).
//!
//! | helper | route | proves entry by |
//! |---|---|---|
//! | `run_sh(cmd)` | native bash | `DET_ENTERED` (bash builtin `printf`) |
//! | `run_mediated(cmd)` | native bash → `zsh -lc` alias → hosted Shell | `DET_ENTERED`, then `DET_MEDIATED` echoed by the Shell AND a journaled `shell:exec` decision for that echo |
//! | `run_py(script)` | native bash → `python3` alias → Monty | `DET_ENTERED`, `python3 --version` = Monty, `DET_MONTY_ENTERED` |
//! | `probe_py(script)` | host CPython selected as the contained agent | `DET_NATIVE_CPYTHON`, after checking `sys.implementation.name` |
//!
//! A refusal is asserted at the point that is meant to refuse. Each assertion
//! first proves the run entered by its route, so a launch failure, a usage error,
//! a host zsh, or a host interpreter can never read as a deny:
//!
//! | call | route | proves |
//! |---|---|---|
//! | `assert_spawn_denied(program)` | mediated | the Shell admitted the spawn to the broker, the journal holds a `shell:spawn` deny for `program`, the Shell printed `effect denied` |
//! | `assert_mediated_denied(action, resource)` → rule | mediated / Monty | the journal holds a broker deny for that `action` on `resource` (policy gate or reach floor) |
//! | `assert_forbidden_by(action, resource, @id)` | mediated / Monty | that deny was caused by the `forbid` with that `@id` (reason `a forbid rule matched`, annotation among `determining.ids`); default-deny never satisfies it |
//! | `assert_spawn_permitted_exactly(path)` | mediated | a `shell:spawn` permit whose resource is exactly the resolved binary the box executed |
//! | `assert_kernel_marker()` | native | a kernel refusal spelling is in the output; meaningful only beside an absent effect |
//! | `assert_monty()` | Monty | interpreter identity and the script's start |
//! | `assert_allow()` | any | exit 0 and no denial marker |
//!
//! A native probe (a binary the case compiles and runs under an `exec` grant)
//! prints its own entered/refused/reached sentinels; the case asserts those and,
//! where it can, a host-side effect (a planted file, a socket, a process).
//!
//! Assertions panic on failure, so a case is ordinary `#[test]` code: run it with
//! `cargo test` in your editor, or the whole suite with `./run.sh`.

pub mod egress;
pub mod mcp_fixture;
pub mod mcp_origin;
pub mod quarantine;
pub mod telemetry;
pub mod verdict;

use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

pub use verdict::CaseSpec;

/// A denied filesystem / exec / egress operation surfaces one of these markers.
/// Linux: a denied read of an absent operator path is ENOENT; a seccomp/namespace
/// refusal is EPERM. macOS (Seatbelt) refusals surface as EPERM. The policy engine
/// and egress gateway also print their own markers. Used by `assert_allow` (which
/// requires their absence) and `assert_kernel_marker`; on its own a marker is not a
/// deny — `No such file or directory` is also what a wrong interpreter prints.
///
/// The gateway's status code is matched as `\b403\b` (plus the `HTTP_403` spelling the
/// probes print), NEVER as bare `403`. Bare digits also match inside a hex box id: the
/// box prints `box box-01403bafc4d78ad5` on every run, and `01403` made `assert_allow`
/// read a successful run as denied. That is a per-run lottery on a random id — roughly
/// fourteen positions at 1/4096 each, across every box the suite creates — so it
/// surfaced as an unreproducible RED on a happy-path case (`SH-HP-BUILTINS` and
/// `SH-HP-FS` on 2026-09-28) while two earlier runs of the same commit were green.
/// A word boundary cannot match a run of hex, and costs nothing: a real refusal reads
/// `403 forbidden`, which `Forbidden` already covers independently.
pub const DENIED_PATTERN: &str = "policy denied|effect denied|NoMatch|Forbidden|blocked by effect interceptor|blocked by egress control|Operation not permitted|Permission denied|EPERM|ENOENT|No such file or directory|PermissionError|not permitted|refused|\\b403\\b|HTTP_403|no `\\[tool\\.<name>\\] command` matches";

/// The sentinel the native bash driver prints before its command (every `run_*`).
pub const ENTERED: &str = "DET_ENTERED";
/// The sentinel the hosted Shell echoes before a mediated command (`run_mediated`).
pub const MEDIATED: &str = "DET_MEDIATED";
/// The sentinel `run_py` scripts print before their first operation.
pub const MONTY_ENTERED: &str = "DET_MONTY_ENTERED";
/// What `python3 --version` prints in the hosted Shell. Never a CPython string. The direct
/// `python3` alias accepts only `-c SOURCE` or a script, so the version is asked of the Shell.
pub const MONTY_VERSION: &str = "Monty (Strands-Box Python subset)";
/// The footer Monty appends to an exception it raises: proof the script ran under Monty even
/// when it failed before its first statement (a compile-time import rejection prints nothing else).
pub const MONTY_FOOTER: &str = "this box's Python is Monty";
/// The Shell's label on a spawn (or any effect) the policy engine refused.
pub const EFFECT_DENIED: &str = "effect denied";
/// A comment line the fixture writes into `box.toml` and nowhere else, so a case can assert the
/// file's content did not leak without matching the disclosure's section names.
pub const PROTECTED_CONFIG_MARKER: &str = "DET_PROTECTED_CONFIG_MARKER_7f3a9c";
/// What the Shell prints when a path resolves to a loaded authority source (box.toml, policy.dw).
pub const AUTHORITY_REFUSAL: &str =
    "resolves to an authority source that this run loaded, which no policy may open or change";
/// What the Shell prints when a path resolves outside everything this box acts on.
pub const UNRESOLVABLE_REFUSAL: &str = "cannot be resolved to a path this box acts on";
/// What the Shell prints when a spelling is not its own canonical identity — every symlink,
/// whatever it points at (reach.rs): the path policy judged is not the path the effect
/// would touch, so the resolver refuses it before any read.
pub const NOT_IDENTITY_REFUSAL: &str =
    "resolves to a different path, so it is not the identity policy judged";

fn denied_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!("(?i)({DENIED_PATTERN})")).expect("valid denial regex"))
}

/// Lines that mean the box never ran the workload (CLI usage error, box load-time
/// refusal, a spawn/wait failure of the box process itself, a containment setup
/// failure) — treated as ERROR, never a deny. Anchored per-line. The trampoline's
/// `warning:` lines (a writable tree that is also executable) are disclosures a
/// successful launch prints, so only its failure lines (`exec … failed`, the
/// status channel, an unsupported platform) count — measured on the native Linux
/// run of 2026-09-22, which misread five successful cases as never-ran.
fn box_never_ran_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)^(error: the following required arguments|Usage: strands-box|strands-box: (error|refusing to run):|strands-box (spawn|wait) error:|workload exited before the ready marker|strands-box-contain-trampoline: (exec |cannot arm|unsupported platform)|containment setup failed)",
        )
        .expect("valid box-never-ran regex")
    })
}

/// Which OS the suite is running on — from `$PLATFORM` (the pipeline sets it) else
/// the compile target.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        match std::env::var("PLATFORM").as_deref() {
            Ok("macos") => Platform::Macos,
            Ok("linux") => Platform::Linux,
            _ if cfg!(target_os = "macos") => Platform::Macos,
            _ => Platform::Linux,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
        }
    }
}

/// The operator's home: `$HOME` if usable, else the per-platform default. The box
/// anchors its "operator home" on the same `$HOME`, so per-test boxes live here.
pub fn user_home() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    match Platform::current() {
        Platform::Macos => PathBuf::from("/Users/ec2-user"),
        Platform::Linux => PathBuf::from("/home/ec2-user"),
    }
}

/// Canonical operator-home spelling used by the rendered macOS profile.
pub fn operator_home() -> PathBuf {
    user_home().canonicalize().unwrap_or_else(|_| user_home())
}

/// Derive the verdict.json category from the id prefix. `CN-*` are containment;
/// `SH-*` are shell; `MO-*` are monty; `TL-*` are telemetry; `PO-*` (and anything
/// else) are policy.
pub fn category_for(id: &str) -> &'static str {
    match id.split('-').next() {
        Some("CN") => "containment",
        Some("SH") => "shell",
        Some("MO") => "monty",
        Some("TL") => "telemetry",
        _ => "policy",
    }
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Locate `strands-box`: PATH first, then the release/debug build under
/// `~/box/target/`.
pub fn find_box() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join("strands-box");
            if is_executable(&cand) {
                return Some(cand);
            }
        }
    }
    let home = user_home();
    for rel in [
        "box/target/release/strands-box",
        "box/target/debug/strands-box",
    ] {
        let cand = home.join(rel);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

/// Recover the box commit from the COMMIT stamp in the source tree, else "unknown".
pub fn resolve_box_commit() -> String {
    if let Ok(s) = std::fs::read_to_string(user_home().join("box/COMMIT")) {
        let trimmed: String = s.split_whitespace().collect();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    "unknown".to_string()
}

thread_local! {
    /// Assertions the running case made on a `RunResult`; a case that makes none is ERROR.
    static ASSERTIONS: Cell<usize> = const { Cell::new(0) };
    /// Workloads the running case launched (after the fixture preflight); none is ERROR.
    static LAUNCHES: Cell<usize> = const { Cell::new(0) };
}

fn count_assertion() {
    ASSERTIONS.with(|c| c.set(c.get() + 1));
}

fn count_launch() {
    LAUNCHES.with(|c| c.set(c.get() + 1));
}

/// The box's decision journal reader, shared with every other suite.
///
/// Re-exported rather than defined here: both this suite and the agent-driven one must
/// agree on what a decision is, and when they each carried their own reader they
/// drifted — the workload suite's `journal_find.py` queried a key the box had renamed,
/// so its journal assertions silently matched nothing. One parser, in `test-common/`,
/// is the fix. Re-exporting keeps `strands_det_harness::Decision` working for the
/// ~200 case files that already spell it that way.
pub use test_common::{Decision, FORBID_REASON, parse_decisions};
/// The combined output (stdout+stderr) and exit code of one `strands-box run`,
/// with the decisions the box journaled during it.
/// The assertion methods PANIC on failure — that's what makes a case a normal
/// `#[test]` and is captured by [`run_case`] as the row's note.
pub struct RunResult {
    pub out: String,
    pub rc: i32,
    /// Decisions journaled by this run: the journal after it, minus the journal before it.
    pub decisions: Vec<Decision>,
    /// How the run entered the box, which fixes what every assertion first requires.
    pub route: Route,
}

/// The route a run took into the box.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// The box binary itself was probed (fixture preflight); nothing is required of the output.
    Bare,
    /// Native contained bash: the output must carry [`ENTERED`].
    Native,
    /// A host CPython selected as the agent command, with its own identity/start sentinel.
    NativePython,
    /// Native bash invoking the `zsh -lc` alias: the output must carry [`ENTERED`] and
    /// [`MEDIATED`], and the journal a `shell:exec` decision — the hosted Shell was reached.
    Mediated,
}

impl RunResult {
    /// A result with no journal, for a probe of the box binary itself.
    pub fn bare(out: String, rc: i32) -> Self {
        RunResult {
            out,
            rc,
            decisions: Vec::new(),
            route: Route::Bare,
        }
    }

    pub fn matches_denied(&self) -> bool {
        denied_re().is_match(&self.out)
    }

    /// The last 8000 characters of the output, where the box's refusal or the workload's own
    /// last words are, for an assertion message. The box prints its startup disclosures first.
    pub fn snippet(&self) -> String {
        let characters: Vec<char> = self.out.chars().collect();
        let start = characters.len().saturating_sub(8000);
        characters[start..].iter().collect()
    }

    fn decisions_summary(&self) -> String {
        if self.decisions.is_empty() {
            return "(no decisions journaled)".to_string();
        }
        self.decisions
            .iter()
            .map(|d| {
                let ids = if d.determining_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ids={:?}", d.determining_ids)
                };
                let reason = if d.reason.is_empty() {
                    String::new()
                } else {
                    format!(" reason={:?}", d.reason)
                };
                format!(
                    "{} {} {} [{}]{ids}{reason}",
                    d.verdict, d.action, d.resource, d.rule
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The box never ran the workload: a clap usage failure (`error:` / `Usage:`),
    /// the box's own load-time refusal (`strands-box: error:` /
    /// `strands-box: refusing to run:` — config and policy validation land there),
    /// a failure to spawn or wait for the box process, or a containment setup
    /// failure. Each case rewrites policy.dw, so a malformed rule would otherwise
    /// exit nonzero with no denial marker and count as a deny. This is
    /// infrastructure, never a verdict. `refusing` deliberately does not match
    /// DET_DENIED's `refused`, and no case emits usage text.
    fn box_never_ran(&self) -> bool {
        box_never_ran_re().is_match(&self.out)
    }

    /// Panic (as DET_ERROR) if the box never ran the workload, or — for a hosted-shell run —
    /// if the Shell never printed its entry sentinel. Called first by every assertion so a
    /// launch/CLI/load failure or a wrong interpreter can't masquerade as a deny.
    fn ensure_ran(&self) {
        count_assertion();
        assert!(
            !self.box_never_ran(),
            "DET_ERROR: box never ran the workload (CLI or load refusal). out=[{}]",
            self.snippet()
        );
        match self.route {
            Route::Bare => {}
            Route::Native => self.require_entered(),
            Route::NativePython => {
                assert!(
                    self.out.lines().any(|line| line == "DET_NATIVE_CPYTHON"),
                    "DET_ERROR: native CPython did not start; rc={} out=[{}]",
                    self.rc,
                    self.snippet()
                );
            }
            Route::Mediated => {
                self.require_entered();
                self.require_mediated();
            }
        }
    }

    fn require_entered(&self) {
        assert!(
            self.out.contains(ENTERED),
            "DET_ERROR: the native bash driver never printed {ENTERED}; the workload did not enter the box (wrong interpreter, refused launch, or bash did not start). rc={} out=[{}]",
            self.rc,
            self.snippet()
        );
    }

    fn require_mediated(&self) {
        assert!(
            self.out.contains(MEDIATED),
            "DET_ERROR: the hosted Shell never echoed {MEDIATED}; the zsh alias did not start the Shell. rc={} out=[{}]",
            self.rc,
            self.snippet()
        );
        assert!(
            self.decisions.iter().any(|d| d.is_action("shell:exec")),
            "DET_ERROR: no shell:exec decision was journaled: the command ran in a shell that did not reach the broker (a host zsh, not the box's alias). decisions:\n{}\nout=[{}]",
            self.decisions_summary(),
            self.snippet()
        );
    }

    /// Panic (as DET_ERROR) unless the run entered the box by its route: the native driver's
    /// [`ENTERED`] sentinel, and for a mediated run the Shell's [`MEDIATED`] echo with its
    /// journaled `shell:exec`. Without that nothing the command was meant to do was attempted,
    /// so no refusal that follows can be the one under test. Every other assertion makes this
    /// check too; call it directly when a case has nothing else to assert first.
    pub fn assert_entered(&self) {
        self.ensure_ran();
    }

    /// Return the exact errno token from `<label> ERR <errno> <text>`.
    pub fn errno_for(&self, label: &str) -> Option<i32> {
        self.out.lines().find_map(|line| {
            let rest = line.strip_prefix(label)?.strip_prefix(" ERR ")?;
            rest.split_whitespace().next()?.parse().ok()
        })
    }

    /// Compare the complete integer token, so errno 1 cannot match 10, 12 or 13.
    pub fn assert_errno(&self, label: &str, errno: i32) {
        self.ensure_ran();
        assert_eq!(
            self.errno_for(label),
            Some(errno),
            "expected {label} to return errno {errno}; rc={} out=[{}]",
            self.rc,
            self.snippet()
        );
    }

    pub fn assert_ok(&self, label: &str, value: &str) {
        self.ensure_ran();
        let expected = format!("{label} OK {value}");
        assert!(
            self.out.lines().any(|line| line == expected),
            "expected line {expected:?}; out=[{}]",
            self.snippet()
        );
    }

    /// An EPERM reported by the operation, after its route has proved entry.
    pub fn assert_eperm(&self) {
        self.ensure_ran();
        let labelled = self.out.lines().any(|line| {
            line.split_once(" ERR ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                == Some("1")
        });
        assert!(
            self.rc != 0
                && (labelled
                    || self.out.contains("Operation not permitted")
                    || self.out.contains("EPERM")),
            "expected EPERM refusal; rc={} out=[{}]",
            self.rc,
            self.snippet()
        );
    }

    /// Compatibility helper for the mainline macOS cases. A Shell refusal needs a broker deny.
    pub fn assert_shell_denied(&self) {
        assert_eq!(
            self.route,
            Route::Mediated,
            "DET_ERROR: Shell refusal requires run_shell/run_mediated"
        );
        self.ensure_ran();
        assert!(
            self.rc != 0
                && self.decisions.iter().any(Decision::denied)
                && (self.out.contains("policy denied") || self.out.contains(EFFECT_DENIED)),
            "expected journaled Strands Shell policy refusal; rc={} out=[{}]; decisions:\n{}",
            self.rc,
            self.snippet(),
            self.decisions_summary()
        );
    }

    /// Panic unless the script ran under Monty: it printed its first statement
    /// (`DET_MONTY_ENTERED`), or Monty raised and signed the exception with its footer — a
    /// compile-time import rejection releases no print, and the footer is the only line then.
    /// A host CPython prints neither; an unavailable interpreter is an error. Interpreter
    /// identity through a supported path is [`BoxFixture::assert_python_is_monty`], which a
    /// Monty case runs first as its positive control.
    pub fn assert_monty(&self) {
        self.ensure_ran();
        assert!(
            !self.out.contains("no interpreter is available"),
            "DET_ERROR: the Shell has no Python interpreter; out=[{}]",
            self.snippet()
        );
        assert!(
            self.out.contains(MONTY_ENTERED) || self.out.contains(MONTY_FOOTER),
            "the script did not run under Monty: neither {MONTY_ENTERED} nor Monty's footer ({MONTY_FOOTER:?}) appeared; out=[{}]",
            self.snippet()
        );
    }

    /// Assert the operation was permitted (exit 0, no denial marker).
    pub fn assert_allow(&self) {
        self.ensure_ran();
        assert!(
            self.rc == 0 && !self.matches_denied(),
            "expected ALLOW but rc={} out=[{}]",
            self.rc,
            self.snippet()
        );
    }

    /// Assert the Shell admitted a spawn of `program` to the broker and the broker refused it:
    /// the workload entered, the journal holds a `shell:spawn` deny whose resource names
    /// `program`, no `shell:spawn` permit names it, and the Shell printed `effect denied`. The
    /// run's own exit status is not judged here: a case echoes the operation's status
    /// (`echo RC=$?`, which is 126 for a denied effect) and asserts it, so the echo cannot mask
    /// the result and a script's last command cannot stand in for the operation. The case still
    /// asserts the target's own output absent, which is the proof the program did not execute.
    pub fn assert_spawn_denied(&self, program: &str) {
        assert!(
            self.route == Route::Mediated,
            "DET_ERROR: assert_spawn_denied needs a mediated run (run_mediated*): only the hosted Shell asks the broker for a shell:spawn; a native bash exec never does"
        );
        self.ensure_ran();
        let spawns: Vec<&Decision> = self
            .decisions
            .iter()
            .filter(|d| d.is_action("shell:spawn") && d.resource.contains(program))
            .collect();
        assert!(
            spawns.iter().any(|d| d.denied()),
            "expected a journaled shell:spawn deny naming {program:?}; decisions:\n{}\nout=[{}]",
            self.decisions_summary(),
            self.snippet()
        );
        assert!(
            !spawns.iter().any(|d| d.permitted()),
            "a shell:spawn permit names {program:?}: the gate admitted it; decisions:\n{}\nout=[{}]",
            self.decisions_summary(),
            self.snippet()
        );
        assert!(
            self.out.contains(EFFECT_DENIED),
            "the Shell did not print {EFFECT_DENIED:?} for {program:?}; out=[{}]",
            self.snippet()
        );
    }

    /// Assert a Shell- or Monty-mediated operation was refused at the broker: the workload
    /// entered and the journal holds a deny for `action` (e.g. `fs:read`, `http:request`)
    /// whose resource contains `resource`, from the policy gate or the reach floor. Returns the
    /// rule that refused, so a case can pin the enforcement point (`default-deny`, a policy id,
    /// or `enforcement:reach-floor`). The case asserts the operation's own success output
    /// absent, which is the proof it did not happen.
    pub fn assert_mediated_denied(&self, action: &str, resource: &str) -> String {
        self.ensure_ran();
        let about: Vec<&Decision> = self
            .decisions
            .iter()
            .filter(|d| d.is_action(action) && d.resource.contains(resource))
            .collect();
        let denied = about.iter().find(|d| d.denied());
        assert!(
            denied.is_some(),
            "expected a journaled {action} deny on a resource containing {resource:?}; decisions:\n{}\nout=[{}]",
            self.decisions_summary(),
            self.snippet()
        );
        denied.map(|d| d.rule.clone()).unwrap_or_default()
    }

    /// Assert the journal holds a deny for `action` on `resource` that a `forbid` with the `@id`
    /// `annotation_id` caused: reason `a forbid rule matched` and the annotation among the
    /// determining ids. A default-deny (`no permit matched`), a deny attributed only by engine rule
    /// number, or a reach-floor refusal does not satisfy this. The message carries every decision
    /// with its ids and reason, and the output.
    pub fn assert_forbidden_by(
        &self,
        action: &str,
        resource: &str,
        annotation_id: &str,
    ) -> Decision {
        self.ensure_ran();
        let about: Vec<&Decision> = self
            .decisions
            .iter()
            .filter(|d| d.is_action(action) && d.resource.contains(resource) && d.denied())
            .collect();
        let forbidden = about.iter().find(|d| d.forbidden_by(annotation_id));
        assert!(
            forbidden.is_some(),
            "expected a journaled {action} deny on a resource containing {resource:?} caused by the forbid @id({annotation_id:?}) \
             (reason {FORBID_REASON:?}, annotation among strands.policy.determining.ids); {} deny(ies) on it read otherwise; decisions:\n{}\nout=[{}]",
            about.len(),
            self.decisions_summary(),
            self.snippet()
        );
        forbidden
            .map(|d| (*d).clone())
            .unwrap_or_else(|| unreachable!())
    }

    /// Assert the journal holds a `shell:spawn` permit whose resource is EXACTLY `program_path` — the
    /// resolved identity the box decided on and executed (`request.rs`: the spawn resource is
    /// `program_path`). This is the control that the program the case spelled, the `[tool.<name>]`
    /// the box selected, and the policy's subject are one file; a substring match would let a
    /// same-named shim or helper pass.
    pub fn assert_spawn_permitted_exactly(&self, program_path: &Path) {
        self.ensure_ran();
        let wanted = program_path.to_string_lossy();
        let spawns: Vec<&Decision> = self
            .decisions
            .iter()
            .filter(|d| d.is_action("shell:spawn"))
            .collect();
        assert!(
            spawns.iter().any(|d| d.permitted() && d.resource == wanted),
            "expected a journaled shell:spawn permit with resource exactly {wanted:?}; spawn decisions: {}; all decisions:\n{}\nout=[{}]",
            if spawns.is_empty() {
                "(none)".to_string()
            } else {
                spawns
                    .iter()
                    .map(|d| format!("{} {:?}", d.verdict, d.resource))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            self.decisions_summary(),
            self.snippet()
        );
    }

    /// Assert a permit was journaled for `action` on `resource` — a positive control that the
    /// gate admitted an operation which a later enforcement point is expected to refuse.
    pub fn assert_mediated_permitted(&self, action: &str, resource: &str) {
        self.ensure_ran();
        assert!(
            self.decisions
                .iter()
                .any(|d| d.is_action(action) && d.resource.contains(resource) && d.permitted()),
            "expected a journaled {action} permit on a resource containing {resource:?}; decisions:\n{}\nout=[{}]",
            self.decisions_summary(),
            self.snippet()
        );
    }

    /// Assert a kernel refusal marker (EPERM/ENOENT/EACCES spellings, or the box's own
    /// exec-selection refusal) is in the output of a native run. Only meaningful after the run
    /// proved it entered and the case proved the target's effect absent; a marker alone is not a
    /// deny.
    pub fn assert_kernel_marker(&self) {
        assert!(
            self.route == Route::Native,
            "DET_ERROR: assert_kernel_marker reads a native run (run_sh*); a mediated refusal is asserted from the journal"
        );
        self.ensure_ran();
        assert!(
            self.matches_denied(),
            "expected a kernel or box refusal marker; out=[{}]",
            self.snippet()
        );
    }

    /// Assert the output contains the literal needle.
    pub fn assert_contains(&self, needle: &str) {
        self.ensure_ran();
        assert!(
            self.out.contains(needle),
            "expected to contain '{needle}'; out=[{}]",
            self.snippet()
        );
    }
    /// Assert the output contains at least one of the literal needles.
    pub fn assert_contains_any(&self, needles: &[&str]) {
        self.ensure_ran();
        assert!(
            needles.iter().any(|n| self.out.contains(n)),
            "expected one of {needles:?}; out=[{}]",
            self.snippet()
        );
    }
    /// Assert the output does NOT contain the literal needle.
    pub fn assert_absent(&self, needle: &str) {
        self.ensure_ran();
        assert!(
            !self.out.contains(needle),
            "unexpectedly contained '{needle}'; out=[{}]",
            self.snippet()
        );
    }

    /// Like [`Self::assert_absent`], but neither echoes the needle nor leaves it in the
    /// surrounding output on failure.
    ///
    /// For a planted marker whose entire purpose is to be unreachable: naming it in the
    /// panic message adds nothing (the case already knows what it planted) and puts a
    /// value the test calls a secret into the CI log and into `verdict.json`, which CodeQL
    /// flags as `rust/cleartext-logging`. The marker is synthetic — a pid plus a nanosecond
    /// timestamp — so the finding overstates the impact, but the dataflow is real.
    ///
    /// Note the needle must be scrubbed from the SNIPPET too, not just omitted from the
    /// message: this assertion only fails BECAUSE the marker is present in the output, so
    /// printing that output verbatim would leak it just as surely. The redacted form is
    /// strictly more informative than the plain one anyway — `label` says which marker
    /// leaked, the byte length distinguishes a truncated leak from a whole one, and the
    /// placeholder shows exactly where in the stream it surfaced.
    pub fn assert_absent_secret(&self, needle: &str, label: &str) {
        self.ensure_ran();
        assert!(
            !self.out.contains(needle),
            "unexpectedly contained the planted {label} (redacted, {} bytes); out=[{}]",
            needle.len(),
            self.snippet().replace(needle, "<REDACTED>")
        );
    }

    /// Assert the box refused the configuration at load, naming why, and never ran the
    /// workload: every `needle` is in the output and `workload_marker` (what the workload
    /// would have printed) is not. For a case whose expected outcome is the load refusal.
    pub fn assert_refused_at_load(&self, needles: &[&str], workload_marker: &str) {
        count_assertion();
        assert!(
            self.box_never_ran(),
            "expected the box to refuse the configuration at load, but it ran (or failed some other way); out=[{}]",
            self.snippet()
        );
        for needle in needles {
            assert!(
                self.out.contains(needle),
                "the load refusal did not name {needle:?}; out=[{}]",
                self.snippet()
            );
        }
        assert!(
            !self.out.contains(workload_marker),
            "the workload ran ({workload_marker:?} printed) although the configuration was to be refused; out=[{}]",
            self.snippet()
        );
    }
}

/// The SSRF floor that refused a Shell `curl` to a link-local destination.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SsrfFloor {
    /// The Shell kernel's own floor (`check_url_safe`), which runs before any transport: curl
    /// prints `curl: access denied: <ip>` and exits 1; no HTTP status exists.
    ShellKernel,
}

/// Judge the output of the PO-12 probe — `curl -sS -w "HTTP_%{http_code} BODY_%{size_download}\n"
/// <link-local url>; echo CURL_RC=$?` in the hosted Shell — and name the floor that refused it,
/// or say why the output is not evidence of the SSRF floor at all.
///
/// Accepted: the Shell kernel floor's own words with curl exit 1 and no status line. Rejected,
/// each by name: any status (200 is a leak; 401 is IMDSv2 itself answering — the request reached
/// the instance; a 403 reached the gateway), `policy denied this operation` (the broad permit did
/// not take, so the floor was never asked), `blocked by egress control` (the gateway's L7 policy
/// interceptor), `curl: (6)` (transport or proxy protocol), an option the Shell's curl rejects, and
/// any metadata content.
pub fn judge_ssrf_probe(out: &str) -> Result<SsrfFloor, String> {
    let has = |needle: &str| out.contains(needle);
    let status = out
        .lines()
        .find_map(|line| line.strip_prefix("HTTP_"))
        .map(str::to_string);
    let rc = out
        .lines()
        .find_map(|line| line.strip_prefix("CURL_RC="))
        .map(str::trim);
    if has("invalid option") {
        return Err("the Shell's curl rejected an option; no request was attempted".into());
    }
    for leak in ["ami-id", "instance-id", "iam/", "local-ipv4"] {
        if has(leak) {
            return Err(format!("metadata content {leak:?} reached the workload"));
        }
    }
    if has("policy denied this operation") {
        return Err("the policy engine refused the request: the broad permit did not apply, so the SSRF floor was never asked".into());
    }
    if has("blocked by egress control") {
        return Err(
            "the gateway's L7 policy interceptor refused the request; that is not the Shell kernel floor"
                .into(),
        );
    }
    if has("curl: (6)") || has("curl: (7)") {
        return Err("transport failure (proxy protocol or connection), not a refusal".into());
    }
    match (status.as_deref(), rc) {
        (None, Some("1")) if has("access denied: 169.254.") => Ok(SsrfFloor::ShellKernel),
        (Some(line), _) if line.starts_with("403") => Err(format!(
            "HTTP_{line}: the request passed the Shell kernel floor and reached the gateway"
        )),
        (Some(line), _) if line.starts_with("401") => Err(format!(
            "HTTP_{line}: IMDSv2 itself answered — the request reached the instance metadata service"
        )),
        (Some(line), _) if line.starts_with("200") => {
            Err(format!("HTTP_{line}: the request succeeded"))
        }
        (Some(line), rc) => Err(format!(
            "unexpected status HTTP_{line} with CURL_RC={}",
            rc.unwrap_or("?")
        )),
        (None, rc) => Err(format!(
            "no status line and no floor refusal; CURL_RC={}",
            rc.unwrap_or("?")
        )),
    }
}

/// Read a child's pipe to completion on its own thread, so the child never blocks on a full pipe.
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = std::io::Read::read_to_end(&mut pipe, &mut bytes);
        }
        bytes
    })
}

/// One isolated box workspace. Its directory outlives the fixture, and `run.sh` removes it after the
/// suite.
pub struct BoxFixture {
    box_bin: PathBuf,
    ws: PathBuf,
    config: PathBuf,
    policy_base: PathBuf,
    /// The configuration text with `{command}` where `[agent] command` belongs. A trailing
    /// `run` argv appends to the stored command, so each run writes the program it needs.
    template: String,
    /// The box directory, whose `private/telemetry/records.jsonl` is the decision journal.
    state: PathBuf,
    note: std::sync::Mutex<String>,
}

/// The native bash driver's command for `cmd`: the entry sentinel, then the command. `printf`
/// is a bash builtin, so the sentinel proves the contained bash is running before anything the
/// case asked for is attempted. Nothing here passes the broker.
fn native(cmd: &str) -> String {
    format!("printf '%s\\n' {ENTERED}; {cmd}")
}

/// The native driver's command that runs `cmd` in the hosted Shell: the box's `zsh` alias
/// (first on the workload PATH) with `-lc`, as the Core suite drives it, echoing the mediated
/// sentinel first. `echo` is a Shell command, so the echo itself is journaled as `shell:exec`,
/// which is the proof the alias reached the broker and not a host zsh.
fn mediated(cmd: &str) -> String {
    native(&format!(
        "zsh -lc {}",
        sh_quote(&format!("echo {MEDIATED}; {cmd}"))
    ))
}

/// `text` as one single-quoted POSIX shell word.
pub fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

// These are native OS probes, deliberately separate from the Monty alias helper.
const PY_PROBE_PRELUDE: &str = r#"
import os, sys
assert sys.implementation.name == "cpython", "native probe needs CPython"
print("DET_NATIVE_CPYTHON", flush=True)
def t(label, fn):
    try:
        print(label, "OK", fn(), flush=True)
    except OSError as e:
        print(label, "ERR", e.errno, e.strerror, flush=True)
    except Exception as e:
        print(label, "EXC", type(e).__name__, e, flush=True)
def libc():
    import ctypes, ctypes.util
    return ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
def raw(name, *args):
    import ctypes
    ctypes.set_errno(0)
    rc = getattr(libc(), name)(*args)
    return "rc", rc, "errno", ctypes.get_errno()
"#;

impl BoxFixture {
    /// Prepare a complete box configuration and verify that its workload starts.
    pub fn pristine() -> Self {
        let box_bin = find_box().unwrap_or_else(|| {
            panic!("DET_ERROR: strands-box not found on PATH or in ~/box/target")
        });

        let base = std::env::var_os("DET_BOX_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| user_home().join(".det-harness-boxes"));
        std::fs::create_dir_all(&base)
            .unwrap_or_else(|e| panic!("DET_ERROR: create {}: {e}", base.display()));
        // Kept until the suite ends; test-integ/README.md says why.
        let tmp = tempfile::Builder::new()
            .prefix("det-box-")
            .tempdir_in(&base)
            .unwrap_or_else(|e| panic!("DET_ERROR: tempdir: {e}"))
            .keep();
        // The kernel's spelling of the fixture root, so every path derived from it, the grants
        // `prepare_box` writes and the paths a case probes or matches in the disclosure, names what
        // the kernel checks. On the macOS instances HOME is /var/tmp/det-home, a link into /private.
        let root = tmp
            .canonicalize()
            .expect("DET_ERROR: resolve the fixture root");
        let ws = root.join("workspace");
        // The box directory sits at `b/state`, so the box-state discovery deny (the boxes namespace,
        // `box_dir.parent()`) is `root/b` and not `root/` — which is the workspace's parent. A real
        // box_dir is `~/.strands-box/b/<name>`, whose namespace never contains a workspace; siting the
        // box_dir under its own `b/` mirrors that, so a leaf's upward path walk (git repository
        // discovery) crosses discovery-allowed ancestors of the workspace rather than the box-state
        // deny (CN-L-03). The `bin/` alias directory stays `.../state/bin`, which cases match.
        let state = root.join("b").join("state");
        let name = tmp
            .file_name()
            .expect("DET_ERROR: the tempdir has a name")
            .to_string_lossy()
            .into_owned();
        let template = prepare_box(&ws, &state, &name);

        let config = ws.join(".strands-box/box.toml");
        let policy = ws.join(".strands-box/policy.dw");
        let policy_base = ws.join(".strands-box/policy.base");
        std::fs::copy(&policy, &policy_base)
            .unwrap_or_else(|e| panic!("DET_ERROR: snapshot policy.dw: {e}"));

        let fixture = BoxFixture {
            box_bin,
            ws,
            config,
            policy_base,
            template,
            state,
            note: std::sync::Mutex::new(String::new()),
        };

        // Preflight under the pristine policy: prove a permitted workload runs.
        let probe = fixture.run(&["/bin/echo", "DET_PREFLIGHT_OK"]);
        assert!(
            probe.out.contains("DET_PREFLIGHT_OK"),
            "DET_ERROR: box did not launch a trivially-permitted workload \
             (bad --config / CLI / trampoline); every deny case would pass \
             spuriously. out=[{}]",
            probe.snippet()
        );

        fixture
    }

    /// Set the observation saved in this case's PASS row; failures keep their original reason.
    pub fn record_note(&self, note: String) {
        *self
            .note
            .lock()
            .expect("DET_ERROR: case note lock poisoned") = note;
    }

    /// Restore the fixture policy.
    pub fn reset_policy(&self) {
        let _ = std::fs::copy(&self.policy_base, self.ws.join(".strands-box/policy.dw"));
    }

    /// Compose the given Dogwood/Cedar rules onto the pristine baseline. A running
    /// box does not hot-reload policy; the next `run_*` re-opens it and picks up
    /// the change.
    pub fn apply_policy(&self, rules: &str) {
        if let Ok(mut content) = std::fs::read_to_string(&self.policy_base) {
            content.push('\n');
            content.push_str(rules);
            content.push('\n');
            let _ = std::fs::write(self.ws.join(".strands-box/policy.dw"), content);
        }
    }

    /// The fixture's own policy.dw, for a case that checks it is unchanged afterwards.
    pub fn policy_path(&self) -> PathBuf {
        self.ws.join(".strands-box/policy.dw")
    }

    /// Run a command in the NATIVE contained bash (`[agent] command = ["bash"]`, host bash under
    /// kernel containment). Builtins and redirections are the agent's own syscalls; nothing
    /// passes the broker. The command is preceded by [`ENTERED`], which every assertion requires.
    pub fn run_sh(&self, cmd: &str) -> RunResult {
        let mut result = self.run(&["bash", "-c", &native(cmd)]);
        result.route = Route::Native;
        result
    }

    /// Run a command in the HOSTED Strands Shell: the native driver invokes the box's `zsh -lc`
    /// alias, which enters the broker. Shell-implemented commands (`cat`, `ls`, `curl`, `ln`,
    /// `echo`, `python3`, …) are mediated and journaled; a program the Shell does not implement
    /// is a `shell:spawn` the policy engine judges. Assertions require [`ENTERED`], [`MEDIATED`]
    /// and a journaled `shell:exec`.
    pub fn run_mediated(&self, cmd: &str) -> RunResult {
        let mut result = self.run(&["bash", "-c", &mediated(cmd)]);
        result.route = Route::Mediated;
        result
    }

    /// The macOS helper name for the mediated route.
    pub fn run_shell(&self, cmd: &str) -> RunResult {
        self.run_mediated(cmd)
    }

    pub fn run_native(&self, cmd: &str) -> RunResult {
        self.run_sh(cmd)
    }

    /// Run the host's CPython as the contained agent (the `NativePython` route), never the box's
    /// Monty alias and never Apple's `/usr/bin/python3` launcher shim, which needs the developer
    /// directory the agent's runtime minimum does not carry. The interpreter is selected and
    /// verified on the HOST once per process ([`select_native_python`]): its real executable image
    /// and the directories its runtime lives in are read back from the interpreter itself, and only
    /// those directories are granted, beside the workspace — no home, no global exec tree.
    /// HOME names the existing writable workspace; the real operator home stays outside it. The
    /// declared search path is [`NATIVE_PROBE_SEARCH_PATH`], so the composed PATH is exact.
    pub fn probe_py(&self, script: &str) -> RunResult {
        self.probe_py_with_config(|config| config, script)
    }

    /// [`BoxFixture::probe_py`] with `edit` applied to the probe's configuration first, for a case
    /// that declares its own telemetry target.
    pub fn probe_py_with_config<F: FnOnce(String) -> String>(
        &self,
        edit: F,
        script: &str,
    ) -> RunResult {
        let python = native_python();
        let config = edit(native_probe_config(&self.template, &self.ws, python));
        self.install_config(config);
        let before = self.decisions().len();
        let result = self.capture(
            Command::new(&self.box_bin)
                .arg("run")
                .arg("--config")
                .arg(&self.config)
                .arg("--")
                .arg("-c")
                .arg(format!("{PY_PROBE_PRELUDE}\n{script}"))
                .current_dir(&self.ws)
                .output(),
            before,
            Route::NativePython,
        );
        self.write_command("bash");
        result.assert_entered();
        result
    }

    /// The box's alias directory (`<box_dir>/bin`), which the composed workload PATH begins with.
    pub fn alias_dir(&self) -> PathBuf {
        self.state.join("bin")
    }

    /// The directory `box_dir` names, which is the box's whole state.
    pub fn box_dir(&self) -> &Path {
        &self.state
    }

    /// A configuration edit declaring `[tool.git]` as the developer directory's real `git`
    /// ([`macos_git_identity`]), with its developer directory and the workspace as its filesystem
    /// and nothing else. The tool's helpers (`libexec/git-core`) are deliberately NOT exec-granted:
    /// a permitted git may not fork them (CN-L-03). No search path is declared: the hosted Shell resolves a bare host-program
    /// name on the broker process's own `PATH` (`shell/src/exec.rs::host_program_path`), which the
    /// agent's `[agent.env]` does not reach, so a case invokes the tool by the identity this
    /// declares ([`macos_git_identity`]) and the policy names that same identity
    /// ([`git_only_spawn_policy`]).
    pub fn with_macos_git_tool(&self) -> impl Fn(String) -> String {
        let git = macos_git_identity();
        let ws = serde_json::to_string(&self.ws.to_string_lossy()).unwrap();
        move |text: String| git_tool_config(text, &git, &ws)
    }

    /// [`BoxFixture::run_mediated`] against a configuration `edit` derives from the fixture's
    /// template, restored afterwards.
    pub fn run_mediated_with_config<F: FnOnce(String) -> String>(
        &self,
        edit: F,
        cmd: &str,
    ) -> RunResult {
        let mut result = self.run_native_with_config(edit, &mediated(cmd));
        result.route = Route::Mediated;
        result
    }

    /// [`BoxFixture::run_mediated_with_config`] with extra variables in the HOST environment of
    /// `strands-box run`, such as a fixture `HOME` or a credential an `env://` locator reads.
    pub fn run_mediated_with_config_env<F: FnOnce(String) -> String>(
        &self,
        edit: F,
        cmd: &str,
        env: &[(&str, &str)],
    ) -> RunResult {
        let mut result = self.run_native_with_config_env(edit, &mediated(cmd), env);
        result.route = Route::Mediated;
        result
    }

    /// The box's telemetry journal, one OTLP line per record; empty when nothing was recorded.
    pub fn journal(&self) -> String {
        std::fs::read_to_string(self.telemetry_file()).unwrap_or_default()
    }

    /// The decisions the journal holds now.
    pub fn decisions(&self) -> Vec<Decision> {
        parse_decisions(&self.journal())
    }

    /// Where the box writes its records when no `[telemetry.<name>]` table names a destination.
    pub fn telemetry_file(&self) -> PathBuf {
        self.state.join("private/telemetry/records.jsonl")
    }

    /// The default destination, parsed. An absent file reads as an empty journal.
    pub fn telemetry(&self) -> telemetry::Journal {
        telemetry::Journal::read(&self.telemetry_file())
    }

    /// The journal at `path`, for a case that declares its own destination.
    pub fn telemetry_at(&self, path: &Path) -> telemetry::Journal {
        telemetry::Journal::read(path)
    }

    /// The `box_id` the stored record carries, which is what `strands.box.name` holds.
    ///
    /// The attribute is spelled `name` and holds the box ID the box minted, never the `name` key the
    /// operator authored. Read it from the record so an assertion names what the box recorded.
    pub fn box_id(&self) -> String {
        let record = self.state.join("private/box.toml");
        let text = std::fs::read_to_string(&record).unwrap_or_else(|error| {
            panic!(
                "DET_ERROR: read the stored record {}: {error}",
                record.display()
            )
        });
        text.lines()
            .find_map(|line| {
                let rest = line.trim().strip_prefix("box_id")?.trim_start();
                let value = rest.strip_prefix('=')?.trim();
                Some(value.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| {
                panic!(
                    "DET_ERROR: {} names no box_id; first 400 bytes [{}]",
                    record.display(),
                    text.chars().take(400).collect::<String>()
                )
            })
    }

    /// A configuration edit declaring one `file` target at `destination`, replacing the default.
    ///
    /// `include` names the signal words when it is not empty; an empty list writes no `include`, so
    /// the target takes every signal.
    pub fn with_telemetry_file(
        &self,
        destination: &Path,
        include: &[&str],
    ) -> impl Fn(String) -> String {
        let destination = serde_json::to_string(&destination.to_string_lossy())
            .expect("DET_ERROR: quote the telemetry destination");
        let include = if include.is_empty() {
            String::new()
        } else {
            let words = serde_json::to_string(include)
                .expect("DET_ERROR: quote the telemetry include words");
            format!("include = {words}\n")
        };
        move |text: String| {
            format!(
                "{text}\n[telemetry.records]\nkind = \"file\"\ndestination = {destination}\n{include}"
            )
        }
    }

    /// Run a command through the Shell with extra variables in the HOST environment of
    /// `strands-box run`, to measure what the box refuses to inherit.
    pub fn run_sh_with_host_env(&self, cmd: &str, env: &[(&str, &str)]) -> RunResult {
        self.write_command("bash");
        let before = self.decisions().len();
        let mut command = Command::new(&self.box_bin);
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            .arg("--")
            .arg("-c")
            .arg(native(cmd))
            .current_dir(&self.ws);
        for (key, value) in env {
            command.env(key, value);
        }
        self.capture(command.output(), before, Route::Native)
    }

    /// Run a command in the native bash against a configuration `edit` derives from the
    /// fixture's template, then restore the fixture's own configuration.
    pub fn run_sh_with_config<F: FnOnce(String) -> String>(&self, edit: F, cmd: &str) -> RunResult {
        self.run_native_with_config(edit, &native(cmd))
    }

    /// The driver behind the `*_with_config` helpers: `argument` is the full `-c` text.
    fn run_native_with_config<F: FnOnce(String) -> String>(
        &self,
        edit: F,
        argument: &str,
    ) -> RunResult {
        self.run_native_with_config_env(edit, argument, &[])
    }

    /// [`BoxFixture::run_native_with_config`] with extra variables in the box process's environment.
    fn run_native_with_config_env<F: FnOnce(String) -> String>(
        &self,
        edit: F,
        argument: &str,
        env: &[(&str, &str)],
    ) -> RunResult {
        self.install_config(edit(self.template.replace("{command}", "[\"bash\"]")));
        let before = self.decisions().len();
        let mut command = Command::new(&self.box_bin);
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            .arg("--")
            .arg("-c")
            .arg(argument)
            .current_dir(&self.ws);
        for (key, value) in env {
            command.env(key, value);
        }
        let result = self.capture(command.output(), before, Route::Native);
        self.write_command("bash");
        result
    }

    fn capture(
        &self,
        output: std::io::Result<std::process::Output>,
        decisions_before: usize,
        route: Route,
    ) -> RunResult {
        count_launch();
        let (out, rc) = match output {
            Ok(o) => {
                let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
                out.push_str(&String::from_utf8_lossy(&o.stderr));
                (out, o.status.code().unwrap_or(-1))
            }
            Err(e) => (format!("strands-box spawn error: {e}"), -1),
        };
        RunResult {
            out,
            rc,
            decisions: self
                .decisions()
                .into_iter()
                .skip(decisions_before)
                .collect(),
            route,
        }
    }

    /// Run a command in the native bash inside the box, and perform `meanwhile` on the HOST
    /// while the workload is live.
    ///
    /// The workload script must touch the `ready` marker (see [`BoxFixture::ready_marker`]) once
    /// the box is running, then wait for the `go` marker (see [`BoxFixture::go_marker`]) before
    /// the part of the script that depends on `meanwhile`. This is how a case measures what the
    /// box does about a path that changes AFTER startup, which no single in-box command can
    /// arrange: a write the box denies never creates the file, so a read of it afterwards proves
    /// only the write denial.
    pub fn run_sh_meanwhile<F: FnOnce()>(&self, cmd: &str, meanwhile: F) -> RunResult {
        self.write_command("bash");
        self.spawn_meanwhile(cmd, &[], meanwhile)
    }

    /// [`BoxFixture::run_sh_meanwhile`] against a configuration `edit` derives from the fixture's
    /// template, restored afterwards as [`BoxFixture::run_sh_with_config`] restores it.
    pub fn run_sh_with_config_meanwhile<E: FnOnce(String) -> String, F: FnOnce()>(
        &self,
        edit: E,
        cmd: &str,
        meanwhile: F,
    ) -> RunResult {
        self.install_config(edit(self.template.replace("{command}", "[\"bash\"]")));
        let result = self.spawn_meanwhile(cmd, &[], meanwhile);
        self.write_command("bash");
        result
    }

    /// [`BoxFixture::run_sh_with_config_meanwhile`] with extra environment on the box process — used
    /// when the box must resolve something on its own `PATH` (e.g. a declared MCP server's program).
    pub fn run_sh_with_config_meanwhile_env<E: FnOnce(String) -> String, F: FnOnce()>(
        &self,
        edit: E,
        cmd: &str,
        env: &[(&str, &str)],
        meanwhile: F,
    ) -> RunResult {
        self.install_config(edit(self.template.replace("{command}", "[\"bash\"]")));
        let result = self.spawn_meanwhile(cmd, env, meanwhile);
        self.write_command("bash");
        result
    }

    fn spawn_meanwhile<F: FnOnce()>(
        &self,
        cmd: &str,
        env: &[(&str, &str)],
        meanwhile: F,
    ) -> RunResult {
        let _ = std::fs::remove_file(self.ready_marker());
        let _ = std::fs::remove_file(self.go_marker());
        count_launch();
        let before = self.decisions().len();
        let mut command = Command::new(&self.box_bin);
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            .arg("--")
            .arg("-c")
            .arg(native(cmd))
            .current_dir(&self.ws)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                return RunResult::bare(format!("strands-box spawn error: {e}"), -1);
            }
        };
        // Drain both pipes on their own threads from the start. The box writes its startup
        // disclosures before the workload runs; left undrained past the pipe buffer, that write
        // would block the box before it ever touched the ready marker.
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut exited_early = None;
        while !self.ready_marker().exists() {
            if let Ok(Some(status)) = child.try_wait() {
                exited_early = Some(status);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "DET_ERROR: the workload never touched the ready marker {}",
                self.ready_marker().display()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if exited_early.is_none() {
            meanwhile();
            std::fs::write(self.go_marker(), "go\n").expect("DET_ERROR: write the go marker");
        }
        // Bound the wait: a box that will not exit (e.g. a contained-MCP teardown hang on Linux)
        // must fail observably with its captured output, not hang the whole suite forever. On the
        // deadline, kill the box — which closes its pipes so the drain threads below can join.
        let mut hung = false;
        let status = match exited_early {
            Some(status) => Ok(status),
            None => {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break Ok(status),
                        Ok(None) if std::time::Instant::now() >= deadline => {
                            hung = true;
                            let _ = child.kill();
                            break child.wait();
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                        Err(e) => break Err(e),
                    }
                }
            }
        };
        let mut out =
            String::from_utf8_lossy(&stdout.join().expect("DET_ERROR: join stdout")).into_owned();
        out.push_str(&String::from_utf8_lossy(
            &stderr.join().expect("DET_ERROR: join stderr"),
        ));
        let decisions = self.decisions().into_iter().skip(before).collect();
        match status {
            Ok(status) => RunResult {
                out: if exited_early.is_some() {
                    format!("workload exited before the ready marker: {out}")
                } else if hung {
                    format!("box did not exit within 45s (killed; likely a teardown hang): {out}")
                } else {
                    out
                },
                rc: status.code().unwrap_or(-1),
                decisions,
                route: Route::Native,
            },
            Err(e) => RunResult::bare(format!("strands-box wait error: {e}"), -1),
        }
    }

    /// The file a [`BoxFixture::run_sh_meanwhile`] workload touches once it is running. Under the
    /// workspace, which the agent holds read and write.
    pub fn ready_marker(&self) -> PathBuf {
        self.ws.join(".det-ready")
    }

    /// The file the host writes after `meanwhile` ran; the workload waits for it. Under the
    /// workspace, which the agent holds read, so the wait is an ordinary existence check.
    pub fn go_marker(&self) -> PathBuf {
        self.ws.join(".det-go")
    }

    /// Run a script through Monty, the box's own Python: the native driver invokes the box's
    /// `python3` alias (first on the workload PATH), which forwards to the broker's interpreter
    /// and accepts only `-c SOURCE` or a script. The script begins with
    /// `print("DET_MONTY_ENTERED")`, and Monty signs any exception with its footer, so
    /// [`RunResult::assert_monty`] can prove the script ran under Monty either way. A case first
    /// runs [`BoxFixture::assert_python_is_monty`] for the interpreter's identity, then asserts
    /// the broker's deny in the journal ([`RunResult::assert_mediated_denied`]) and the
    /// operation's own output absent.
    pub fn run_py(&self, script: &str) -> RunResult {
        let script = format!("print(\"{MONTY_ENTERED}\")\n{script}");
        self.run_sh(&format!("python3 -c {}", sh_quote(&script)))
    }

    /// The positive control for a Monty case: the hosted Shell's `python3 --version` (the
    /// supported path for the question; the direct alias accepts only `-c` or a script) must
    /// answer with Monty's version line. Panics with DET_ERROR otherwise.
    pub fn assert_python_is_monty(&self) {
        let r = self.run_mediated("python3 --version");
        r.assert_entered();
        assert!(
            r.out.contains(MONTY_VERSION),
            "DET_ERROR: this box's python3 is not Monty ({MONTY_VERSION:?} absent from the Shell's `python3 --version`); out=[{}]",
            r.snippet()
        );
    }

    /// The workspace the box runs in, for a case that plants a file the workload then reaches.
    pub fn workspace(&self) -> &Path {
        &self.ws
    }

    /// The `list`-only tree beside the workspace (macOS), holding `entry.txt`.
    pub fn listed_tree(&self) -> PathBuf {
        self.ws.with_file_name("listed")
    }

    /// The built tool under the workspace's `out/` exec tree: a binary `rustc` compiled there.
    pub fn built_tool(&self) -> PathBuf {
        self.ws.join("out/built-hello")
    }

    /// The built script under the same tree, with a `#!/usr/bin/env sh` shebang.
    pub fn built_script(&self) -> PathBuf {
        self.ws.join("out/built-tool.sh")
    }

    /// The canonical exec tree (`out/`) the fixture's tools live in, for a case that compiles a
    /// probe beside them and runs it under the agent's own `exec` entry.
    pub fn exec_tree(&self) -> PathBuf {
        self.built_tool()
            .parent()
            .expect("DET_ERROR: the built tool sits in the exec tree")
            .canonicalize()
            .expect("DET_ERROR: resolve the exec tree")
    }

    /// Compile `source` with `rustc` to `<exec tree>/<name>` and answer the binary's path. A
    /// native probe is built here, beside the declared tool, so the agent's `exec` entry on the
    /// tree (see [`BoxFixture::with_exec_tree`]) can carry it.
    pub fn compile_probe(&self, name: &str, source: &str) -> PathBuf {
        let out = self.exec_tree();
        let probe = out.join(name);
        let source_path = out.join(format!("{name}.rs"));
        std::fs::write(&source_path, source).expect("DET_ERROR: write the probe's source");
        let compiled = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-O", "-o"])
            .arg(&probe)
            .arg(&source_path)
            .output()
            .expect("DET_ERROR: rustc is on PATH");
        assert!(
            compiled.status.success(),
            "DET_ERROR: rustc failed on the probe {name}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        probe
    }

    /// A configuration edit that grants the agent `exec` on the fixture's exec tree, so a probe
    /// compiled there runs in the agent's own boundary with no `[tool.*]` table (follow-up F1).
    pub fn with_exec_tree(&self) -> impl Fn(String) -> String {
        let exec_entry = serde_json::to_string(&self.exec_tree().to_string_lossy()).unwrap();
        move |text: String| {
            text.replacen(
                "read_file = [",
                &format!("exec = [{exec_entry}]\nread_file = ["),
                1,
            )
        }
    }

    /// Write `program` as `[agent] command`, so the argv that follows `--` appends to it.
    fn write_command(&self, program: &str) {
        let command = serde_json::to_string(&[program]).expect("a JSON array is TOML too");
        self.install_config(self.template.replace("{command}", &command));
    }

    /// Install `text` as the box configuration through a staged file and a rename, so the box
    /// never reads a half-written file.
    fn install_config(&self, text: String) {
        let staged = self.config.with_extension("toml.staged");
        std::fs::write(&staged, text).expect("DET_ERROR: stage the box configuration");
        std::fs::rename(&staged, &self.config).expect("DET_ERROR: install the box configuration");
    }

    fn run(&self, argv: &[&str]) -> RunResult {
        let (program, arguments) = argv
            .split_first()
            .expect("DET_ERROR: a workload names a program");
        self.write_command(program);
        let before = self.decisions().len();
        self.capture(
            Command::new(&self.box_bin)
                .arg("run")
                .arg("--config")
                .arg(&self.config)
                .arg("--")
                .args(arguments)
                .current_dir(&self.ws)
                .output(),
            before,
            Route::Bare,
        )
    }
}

/// The search path the native probe declares for its agent, so the composed workload PATH is
/// exactly the alias directory followed by these entries (`boundary.rs::composed_path`).
pub const NATIVE_PROBE_SEARCH_PATH: &str = "/usr/bin:/bin";

/// A CPython selected and verified on the host for the `NativePython` route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePython {
    /// The canonical executable image the interpreter reported for itself while running — the
    /// file the kernel actually maps, not a launcher that would exec it.
    pub executable: PathBuf,
    /// Canonical, EXISTING directories the interpreter's runtime lives in — the required roots
    /// (base prefix, stdlib, the framework version root of a framework build) and those optional
    /// hints (prefix, `LIBDIR`) that name a real directory on this host — each a `read` grant for
    /// the probe's agent. Deduplicated to the outermost; nothing above them is granted, and a path
    /// that is not there is never granted (the box refuses a grant on a nonexistent path at load).
    pub runtime_reads: Vec<PathBuf>,
    /// Compile-time hints the interpreter reported that do not exist on this host, each with why
    /// it was dropped (e.g. `sysconfig`'s `LIBDIR` naming the build machine's Xcode). Reported, not
    /// granted, not fabricated.
    pub rejected_hints: Vec<String>,
}

/// What a candidate interpreter says about itself when the host runs it (see [`PY_IDENTITY_QUERY`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyIdentity {
    pub implementation: String,
    pub image: PathBuf,
    /// Runtime identities the interpreter is actually using: `sys.base_prefix` and the stdlib
    /// directory. Each MUST exist, or the candidate is not a usable runtime.
    pub roots: Vec<PathBuf>,
    /// Build-configuration hints: `sys.prefix` and `sysconfig`'s `LIBDIR`. These can name the
    /// machine the interpreter was built on rather than this host; each is used only if it exists.
    pub hints: Vec<PathBuf>,
}

/// The query run on the host against a candidate: prints one JSON object with the implementation
/// name, the executing image (`_NSGetExecutablePath` on macOS, `/proc/self/exe` on Linux,
/// `sys.executable` otherwise), the runtime roots it is using, and its build-configuration hints.
pub const PY_IDENTITY_QUERY: &str = r#"
import json, os, sys, sysconfig
def image():
    try:
        return os.readlink("/proc/self/exe")
    except OSError:
        pass
    try:
        import ctypes
        buf = ctypes.create_string_buffer(4096); size = ctypes.c_uint32(4096)
        if ctypes.CDLL(None)._NSGetExecutablePath(buf, ctypes.byref(size)) == 0:
            return buf.value.decode()
    except Exception:
        pass
    return sys.executable
roots = [sys.base_prefix, sysconfig.get_paths().get("stdlib", "")]
hints = [sys.prefix, sysconfig.get_config_var("LIBDIR") or ""]
print(json.dumps({"implementation": sys.implementation.name, "image": image(),
                  "roots": [d for d in roots if d], "hints": [d for d in hints if d]}))
"#;

/// Whether `path` is Apple's launcher shim (or any `/usr/bin` interpreter, which on macOS is one):
/// a shim asks `xcode-select` for the developer directory, which the agent boundary never reaches.
pub fn is_apple_shim(path: &Path) -> bool {
    path.starts_with("/usr/bin")
}

/// The canonical form of `dir` if it names an existing directory on this host, else why not. Never
/// falls back to the unresolved spelling: a grant on a path that is not there grants nothing and
/// makes the box refuse the whole configuration at load (measured, native run of 2026-09-22).
fn existing_directory(dir: &Path) -> Result<PathBuf, String> {
    match dir.canonicalize() {
        Ok(canonical) if canonical.is_dir() => Ok(canonical),
        Ok(canonical) => Err(format!("{} is not a directory", canonical.display())),
        Err(e) => Err(format!("{} is not there ({e})", dir.display())),
    }
}

/// Choose the first candidate that is not a shim, answers the identity query as CPython, and whose
/// image and runtime roots exist on this host. `query` runs a candidate on the host and returns what
/// it reports; it is a parameter so a test can stand in for real interpreters. The reads granted are
/// the existing canonical roots plus those hints that exist; a hint that does not is recorded in
/// [`NativePython::rejected_hints`], never granted and never replaced by a made-up directory. Errors
/// name every rejection.
pub fn select_native_python_from<I, Q>(candidates: I, query: Q) -> Result<NativePython, String>
where
    I: IntoIterator<Item = PathBuf>,
    Q: Fn(&Path) -> Result<PyIdentity, String>,
{
    let mut rejected = Vec::new();
    for candidate in candidates {
        let canonical = candidate.canonicalize().unwrap_or(candidate.clone());
        if is_apple_shim(&candidate) || is_apple_shim(&canonical) {
            rejected.push(format!(
                "{}: Apple launcher shim under /usr/bin",
                candidate.display()
            ));
            continue;
        }
        let identity = match query(&canonical) {
            Ok(identity) if identity.implementation == "cpython" => identity,
            Ok(identity) => {
                rejected.push(format!(
                    "{}: implementation {:?} is not cpython",
                    candidate.display(),
                    identity.implementation
                ));
                continue;
            }
            Err(e) => {
                rejected.push(format!("{}: {e}", candidate.display()));
                continue;
            }
        };
        // The image is what the kernel maps: it must be a real file, and not a /usr/bin launcher.
        let image = match identity.image.canonicalize() {
            Ok(image) if image.is_file() => image,
            Ok(image) => {
                rejected.push(format!(
                    "{}: reported image {} is not a file",
                    candidate.display(),
                    image.display()
                ));
                continue;
            }
            Err(e) => {
                rejected.push(format!(
                    "{}: reported image {} is not there ({e})",
                    candidate.display(),
                    identity.image.display()
                ));
                continue;
            }
        };
        if is_apple_shim(&image) {
            rejected.push(format!(
                "{}: executes as a /usr/bin image",
                candidate.display()
            ));
            continue;
        }
        // Required roots: what the running interpreter is using. Missing one means this is not a
        // usable runtime, so the candidate is rejected by name rather than granted a phantom path.
        let mut reads: Vec<PathBuf> = Vec::new();
        let mut missing_root = None;
        for root in identity.roots.iter().chain(framework_root(&image).iter()) {
            if root.as_os_str().is_empty() || root == Path::new("/") {
                continue;
            }
            match existing_directory(root) {
                Ok(dir) => {
                    if !reads.contains(&dir) {
                        reads.push(dir);
                    }
                }
                Err(why) => {
                    missing_root = Some(why);
                    break;
                }
            }
        }
        if let Some(why) = missing_root {
            rejected.push(format!("{}: runtime root {why}", candidate.display()));
            continue;
        }
        if reads.is_empty() {
            rejected.push(format!("{}: reported no runtime root", candidate.display()));
            continue;
        }
        // Optional hints: build-configuration values that may name the build machine. Used only
        // when they exist here; otherwise reported and dropped.
        let mut rejected_hints = Vec::new();
        for hint in &identity.hints {
            if hint.as_os_str().is_empty() || hint == Path::new("/") {
                continue;
            }
            match existing_directory(hint) {
                Ok(dir) => {
                    if !reads.contains(&dir) {
                        reads.push(dir);
                    }
                }
                Err(why) => rejected_hints.push(format!("build-time hint {why}")),
            }
        }
        // Keep only the outermost of nested directories: one grant per identity.
        let mut outer: Vec<PathBuf> = reads
            .iter()
            .filter(|dir| {
                !reads
                    .iter()
                    .any(|other| other != *dir && dir.starts_with(other))
            })
            .cloned()
            .collect();
        outer.sort();
        return Ok(NativePython {
            executable: image,
            runtime_reads: outer,
            rejected_hints,
        });
    }
    Err(format!(
        "no native CPython on this host; rejected: {}",
        if rejected.is_empty() {
            "no candidates".to_string()
        } else {
            rejected.join("; ")
        }
    ))
}

/// For a framework build (`…/Python3.framework/Versions/3.9/…`), the version root that holds the
/// dylib, the stdlib and the app bundle; otherwise nothing.
pub fn framework_root(image: &Path) -> Option<PathBuf> {
    let mut cur = image;
    while let Some(parent) = cur.parent() {
        if parent.file_name().is_some_and(|n| n == "Versions") {
            return Some(cur.to_path_buf());
        }
        cur = parent;
    }
    None
}

/// Run [`PY_IDENTITY_QUERY`] on the host with `candidate`, isolated from the operator's
/// environment (`-I`), and parse its answer.
pub fn query_python_identity(candidate: &Path) -> Result<PyIdentity, String> {
    let output = Command::new(candidate)
        .arg("-I")
        .arg("-c")
        .arg(PY_IDENTITY_QUERY)
        .output()
        .map_err(|e| format!("cannot run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("identity is not JSON: {e}"))?;
    let paths = |key: &str| -> Vec<PathBuf> {
        value[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .map(PathBuf::from)
            .collect()
    };
    Ok(PyIdentity {
        implementation: value["implementation"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        image: PathBuf::from(value["image"].as_str().unwrap_or_default()),
        roots: paths("roots"),
        hints: paths("hints"),
    })
}

/// The host's candidates, in order: the developer directory's `python3` (`xcrun --find`, macOS),
/// then every `python3` on the host PATH. Shims are rejected by [`select_native_python_from`].
pub fn native_python_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(found) = macos_developer_tool("python3") {
        candidates.push(found);
    }
    for dir in std::env::var_os("PATH")
        .iter()
        .flat_map(|p| std::env::split_paths(p).collect::<Vec<_>>())
    {
        let cand = dir.join("python3");
        if is_executable(&cand) && !candidates.contains(&cand) {
            candidates.push(cand);
        }
    }
    candidates
}

/// The verified native CPython for this process, selected once. Panics with DET_ERROR when none
/// qualifies, naming every rejected candidate.
pub fn native_python() -> &'static NativePython {
    static SELECTED: OnceLock<NativePython> = OnceLock::new();
    SELECTED.get_or_init(|| {
        let python = select_native_python_from(native_python_candidates(), query_python_identity)
            .unwrap_or_else(|e| panic!("DET_ERROR: {e}"));
        // Dropped hints are evidence, not a fault: say so once, in the case output.
        for hint in &python.rejected_hints {
            eprintln!(
                "DET_NOTE: native python {}: {hint} (not granted)",
                python.executable.display()
            );
        }
        python
    })
}

/// The developer directory's real program `name` on macOS, through `xcrun --find`, canonicalized
/// and verified not to be a `/usr/bin` launcher shim.
pub fn macos_developer_tool(name: &str) -> Result<PathBuf, String> {
    let output = Command::new("xcrun")
        .arg("--find")
        .arg(name)
        .output()
        .map_err(|e| format!("xcrun --find {name}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun --find {name}: exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let found = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let canonical = found
        .canonicalize()
        .map_err(|e| format!("{}: {e}", found.display()))?;
    if is_apple_shim(&canonical) {
        return Err(format!(
            "xcrun --find {name} answered a /usr/bin shim: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// The probe's agent configuration: the interpreter's image as the command (implicitly executable),
/// its runtime directories as `read` grants beside the workspace, HOME in the workspace, and the
/// declared search path. Nothing else is widened.
pub fn native_probe_config(template: &str, workspace: &Path, python: &NativePython) -> String {
    let quoted = |p: &Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
    let command = serde_json::to_string(&[python.executable.to_string_lossy()]).unwrap();
    let extra: Vec<String> = python.runtime_reads.iter().map(|p| quoted(p)).collect();
    let mut config = template.replacen("{command}", &command, 1);
    if !extra.is_empty() {
        config = config.replacen("read = [", &format!("read = [{}, ", extra.join(", ")), 1);
    }
    // The CLT interpreter needs an entropy source during hash initialization.
    // This is one read-only device in this probe's fixture, not a wider Core minimum.
    config = config.replacen("read_file = [", "read_file = [\"/dev/urandom\", ", 1);
    config.push_str(&format!(
        "\n[agent.env]\nHOME = {}\nPATH = {}\n",
        quoted(workspace),
        serde_json::to_string(NATIVE_PROBE_SEARCH_PATH).unwrap()
    ));
    config
}

/// The developer directory's real `git` on this macOS host: `xcrun --find git`, canonicalized,
/// refused if it is the `/usr/bin/git` launcher shim. This one path is the `[tool.git]` command,
/// the program a case spells on the Shell's command line, and the program the git-only policy
/// names — so the invocation, the declaration and the permit agree by construction, and the
/// journaled `shell:spawn` resource (the resolved `program_path`) must read exactly this.
/// Panics with DET_ERROR when the host has no such git.
pub fn macos_git_identity() -> PathBuf {
    macos_developer_tool("git").unwrap_or_else(|e| panic!("DET_ERROR: {e}"))
}

/// The `[tool.git]` declaration for a verified developer-directory git: declaring it puts it in the
/// agent's reach, and the tool reads the developer directory git lives in (`<dir>/usr/bin/git`) and
/// the workspace. Nothing else is declared — in particular no `[agent.env] PATH`, which would not
/// affect what the hosted Shell resolves (see [`BoxFixture::with_macos_git_tool`]).
pub fn git_tool_config(template: String, git: &Path, workspace_json: &str) -> String {
    let git_json = serde_json::to_string(&git.to_string_lossy()).unwrap();
    let developer = git
        .ancestors()
        .nth(3)
        .expect("git lives at <developer directory>/usr/bin/git");
    let developer_json = serde_json::to_string(&developer.to_string_lossy()).unwrap();
    template
        + &format!(
            "\n[tool.git]\ncommand = [{git_json}]\nworkspace = {ws}\n\n[tool.git.filesystem]\nread = [{developer_json}, {ws}]\nwrite = [{ws}]\n\n\
         [tool.git.env]\nHOME = {ws}\nGIT_CONFIG_NOSYSTEM = \"1\"\nGIT_CONFIG_GLOBAL = \"/dev/null\"\n",
            ws = workspace_json
        )
}

/// A `shell:spawn` permit for exactly one host program: the one whose spelled `program` AND resolved
/// `program_path` (`crates/policy/src/schema.rs`: `context.input.program`, `context.input.program_path`)
/// both equal `git`'s canonical path. As narrow as the former `program == "git"` — one program — but
/// pinned to the identity the box will execute rather than to a bare name the broker's `PATH`
/// resolves. A bare `git`, `/usr/bin/git`, or `ssh` never matches.
pub fn git_only_spawn_policy(git: &Path) -> String {
    let git_json = serde_json::to_string(&git.to_string_lossy()).unwrap();
    format!(
        "permit(principal, action == Box::Action::\"shell:spawn\", resource)\nwhen {{ context.input.program == {git_json} && context.input.program_path == {git_json} }};"
    )
}

/// Write the box's configuration and policy, and answer with the configuration template.
///
/// The agent holds the workspace read and write, because `write` no longer implies `read`. The
/// `out/` tree under it is a declared tool's exec tree holding a binary `rustc` compiles at fixture
/// time, which is build output, for the case that runs a binary from an exec tree. On macOS the
/// agent also lists `listed/`, a sibling of the workspace, without content, and denies `later.env`,
/// a path that does not exist yet; Linux refuses both cells by name at load, so the cases that need
/// them skip there.
fn prepare_box(workspace: &Path, state: &Path, name: &str) -> String {
    let config_directory = workspace.join(".strands-box");
    std::fs::create_dir_all(&config_directory).expect("DET_ERROR: create workspace");
    std::fs::create_dir_all(state).expect("DET_ERROR: create box directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700))
            .expect("DET_ERROR: private box directory");
    }
    let workspace = workspace
        .canonicalize()
        .expect("DET_ERROR: resolve workspace");
    let state = state
        .canonicalize()
        .expect("DET_ERROR: resolve box directory");
    let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
    let out = workspace.join("out");
    std::fs::create_dir(&out).expect("DET_ERROR: create the exec tree");
    // Real build output: a binary `rustc` compiles here, because macOS kills a copied platform
    // binary at exec whatever the sandbox says.
    let tool = out.join("built-hello");
    let source = out.join("hello.rs");
    std::fs::write(
        &source,
        "fn main() { println!(\"BUILD_OUTPUT_RAN {}\", std::env::args().nth(1).unwrap_or_default()); }\n",
    )
    .expect("DET_ERROR: write the tool's source");
    let compiled = std::process::Command::new("rustc")
        .arg("-o")
        .arg(&tool)
        .arg(&source)
        .output()
        .expect("DET_ERROR: rustc is on PATH");
    assert!(
        compiled.status.success(),
        "DET_ERROR: rustc failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let script = out.join("built-tool.sh");
    std::fs::write(
        &script,
        "#!/usr/bin/env sh\nprintf 'SCRIPT_OUTPUT_RAN\\n'\n",
    )
    .expect("DET_ERROR: write the built script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for built in [&tool, &script] {
            std::fs::set_permissions(built, std::fs::Permissions::from_mode(0o755))
                .expect("DET_ERROR: executable built tool");
        }
    }
    std::fs::write(workspace.join("readable.txt"), "LISTED_CONTENT\n")
        .expect("DET_ERROR: write a file the workspace grant covers");
    // Beside the workspace, so no `read` entry covers it and only the `list` cell decides.
    let listed = workspace.with_file_name("listed");
    std::fs::create_dir(&listed).expect("DET_ERROR: create the listed tree");
    std::fs::write(listed.join("entry.txt"), "LISTED_CONTENT\n")
        .expect("DET_ERROR: write the listed file");
    let macos_only = if Platform::current() == Platform::Macos {
        format!(
            "list = [{}]\ndeny = [{}]\n",
            quoted(&listed),
            quoted(&workspace.join("later.env"))
        )
    } else {
        String::new()
    };
    // A single file under the operator home the agent may read, beside the unlisted home. Named by
    // the kernel's spelling: the box refuses a grant whose path is not the one the kernel checks,
    // and on the macOS instances HOME is /var/tmp/det-home, a link into /private.
    let operator = user_home()
        .canonicalize()
        .expect("DET_ERROR: resolve operator home");
    let listed_file = operator.join(".det-listed-settings.json");
    std::fs::write(&listed_file, "{\"listed\": \"LISTED_SETTINGS\"}\n")
        .expect("DET_ERROR: write the listed file under the operator home");
    // A crate the cargo act builds inside a tool, with its own temporary directory.
    let crate_root = workspace.join("hello-crate");
    std::fs::create_dir_all(crate_root.join("src")).expect("DET_ERROR: create the crate");
    std::fs::create_dir_all(crate_root.join("target/tmp")).expect("DET_ERROR: create target/tmp");
    std::fs::write(
        crate_root.join("Cargo.toml"),
        "[package]\nname = \"hello\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    )
    .expect("DET_ERROR: write Cargo.toml");
    std::fs::write(
        crate_root.join("src/main.rs"),
        "fn main() { println!(\"HELLO_RAN\"); }\n",
    )
    .expect("DET_ERROR: write main.rs");
    // A unique line only this file holds, so a case can prove the configuration's content never
    // reached the workload without matching the box's own startup disclosure, which repeats the
    // section names ("[agent]") on every run.
    let config = format!(
        "# {PROTECTED_CONFIG_MARKER}\nname = {}\nbox_dir = {}\npolicy = \"policy.dw\"\n\n\
         [agent]\ncommand = {{command}}\nworkspace = {}\n\n\
         [agent.filesystem]\nread = [{}]\nwrite = [{}]\nread_file = [{}]\n{macos_only}\n\
         [tool.built]\ncommand = [{}]\nworkspace = {}\n\n\
         [tool.built.filesystem]\nread = [{}]\n\n\
         [tool.built-script]\ncommand = [{}]\nworkspace = {}\n\n\
         [tool.built-script.filesystem]\nread = [{}]\n",
        serde_json::to_string(name).unwrap(),
        quoted(&state),
        quoted(&workspace),
        quoted(&workspace),
        quoted(&workspace),
        quoted(&listed_file),
        quoted(&tool),
        quoted(&workspace),
        quoted(&workspace),
        quoted(&script),
        quoted(&workspace),
        quoted(&workspace),
    );
    std::fs::write(
        config_directory.join("box.toml"),
        config.replace("{command}", "[\"/bin/echo\"]"),
    )
    .expect("DET_ERROR: write box configuration");
    let policy_path = |path: &Path| {
        let relative = path
            .strip_prefix(&operator)
            .expect("DET_ERROR: fixture beneath operator home");
        format!("~/{}", relative.display())
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('*', "\\*")
    };
    let policy = include_str!("fixture.dw").replace("{{WORKSPACE}}", &policy_path(&workspace));
    std::fs::write(config_directory.join("policy.dw"), policy)
        .expect("DET_ERROR: write fixture policy");
    config
}

/// The engine behind `det_case!`. Builds a fresh box, runs the case body, records
/// exactly one verdict.json row (PASS / FAIL / ERROR), then re-raises any failure
/// so `cargo test` also reflects it. A body that launched no workload or made no
/// `RunResult` assertion is recorded as ERROR: it exercised nothing, so it proved
/// nothing. Contributors don't call this directly.
pub fn run_case<F: FnOnce(&BoxFixture)>(id: &str, desc: &str, body: F) {
    let category = category_for(id);
    let dir = verdict::results_dir();
    let _ = std::fs::create_dir_all(&dir);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let fixture = BoxFixture::pristine();
        ASSERTIONS.with(|c| c.set(0));
        LAUNCHES.with(|c| c.set(0));
        body(&fixture);
        let launches = LAUNCHES.with(Cell::get);
        let assertions = ASSERTIONS.with(Cell::get);
        assert!(
            launches > 0,
            "DET_ERROR: the case launched no workload; a body that returns without running anything exercised nothing"
        );
        assert!(
            assertions > 0,
            "DET_ERROR: the case made no RunResult assertion; a body that checks nothing proved nothing"
        );
        fixture
            .note
            .into_inner()
            .expect("DET_ERROR: case note lock poisoned")
    }));

    match result {
        Ok(note) => verdict::write_row(&dir, id, category, desc, "PASS", &note),
        Err(payload) => {
            let note = panic_message(&payload);
            // Infrastructure faults (box not found / preparation failed / preflight / box
            // never ran / nothing exercised) are raised with a "DET_ERROR: " prefix and
            // recorded as ERROR; anything else is a real assertion failure (FAIL). ERROR
            // turns the suite RED (see verdict::Summary::build).
            let (result, note) = match note.strip_prefix("DET_ERROR: ") {
                Some(rest) => ("ERROR", rest.to_string()),
                None => ("FAIL", note),
            };
            verdict::write_row(&dir, id, category, desc, result, &note);
            std::panic::resume_unwind(payload);
        }
    }
}

/// [`run_case`] for a case declared for `platforms` (empty = every platform). On a
/// platform the case does not declare it records a `SKIP` row with the standard
/// note and runs nothing; the reducer accepts that SKIP only because the compiled
/// manifest carries the same declaration.
pub fn run_case_on<F: FnOnce(&BoxFixture)>(id: &str, platforms: &[Platform], desc: &str, body: F) {
    let current = Platform::current();
    if !platforms.is_empty() && !platforms.contains(&current) {
        let dir = verdict::results_dir();
        let _ = std::fs::create_dir_all(&dir);
        let declared: Vec<&str> = platforms.iter().map(|p| p.as_str()).collect();
        let note = format!(
            "{}{}: declared for [{}]",
            verdict::SKIP_NOTE_PREFIX,
            current.as_str(),
            declared.join(", ")
        );
        eprintln!("{id}: {note}");
        verdict::write_row(&dir, id, category_for(id), desc, "SKIP", &note);
        return;
    }
    // TEMPORARY QUARANTINE (test-integ/QUARANTINE.md): an authorized (case, platform) cell records
    // an explicit SKIP with the one authorized note and runs nothing. The platform still applies to
    // the case; the reducer accepts this SKIP only because it reads the same compiled list.
    if let Some(q) = quarantine::lookup(id, current.as_str()) {
        let dir = verdict::results_dir();
        let _ = std::fs::create_dir_all(&dir);
        let note = quarantine::note(q);
        eprintln!("{id}: {note}");
        verdict::write_row(&dir, id, category_for(id), desc, "SKIP", &note);
        return;
    }
    run_case(id, desc, body);
}

fn panic_message(payload: &Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panicked".to_string()
    }
}

/// Define a deterministic case as a `#[test]`. See the crate docs for the shape.
/// `platforms: [Linux]` / `platforms: [Macos]` (after `id:`) declares a
/// platform-specific case; elsewhere it records `SKIP`.
#[macro_export]
macro_rules! det_case {
    (name: $name:ident, id: $id:literal, $(platforms: [$($p:ident),* $(,)?],)? desc: $desc:literal, run: $body:expr $(,)?) => {
        #[test]
        // A case declared for one platform still COMPILES on the others (it is
        // skipped at run time, not compiled out), so its `|b|` goes unused wherever
        // the body is behind a `#[cfg(target_os = ...)]`. Lint levels are lexically
        // scoped, so allowing it here covers the closure the case file supplies, and
        // a platform-gated case needs no `_b` rename — that rename would be a lie on
        // the platform where the binding IS used. The closure is still passed
        // straight through: binding it to a `let` first would fix its argument to one
        // lifetime and break the `for<'a> Fn(&'a BoxFixture)` the runner needs.
        #[allow(unused_variables)]
        fn $name() {
            $crate::run_case_on($id, &[$($($crate::Platform::$p),*)?], $desc, $body);
        }
    };
}

#[cfg(test)]
mod tests {
    //! Fault injection for the assertions: every output a failed launch, a wrong
    //! interpreter, or a plain nonzero exit can produce must not satisfy a deny.
    use super::*;

    fn result(out: &str, rc: i32, decisions: Vec<Decision>) -> RunResult {
        RunResult {
            out: out.to_string(),
            rc,
            decisions,
            route: Route::Native,
        }
    }

    /// A mediated run: the Shell echoed its sentinel and the journal has that echo's shell:exec.
    fn mediated_result(out: &str, rc: i32, mut decisions: Vec<Decision>) -> RunResult {
        decisions.insert(
            0,
            decision("shell:exec", "echo", "permit", "shell_commands"),
        );
        RunResult {
            out: format!("DET_ENTERED\nDET_MEDIATED\n{out}"),
            rc,
            decisions,
            route: Route::Mediated,
        }
    }

    fn decision(action: &str, resource: &str, verdict: &str, rule: &str) -> Decision {
        Decision {
            action: format!("Box::Action::\"{action}\""),
            resource: resource.to_string(),
            rule: rule.to_string(),
            verdict: verdict.to_string(),
            reason: String::new(),
            determining_ids: Vec::new(),
            at_unix_nano: 0,
        }
    }

    /// A deny as the box journals it: engine rule id, refusal class, and the determining ids
    /// (`@id` when authored, else the engine id).
    fn deny(action: &str, resource: &str, rule: &str, reason: &str, ids: &[&str]) -> Decision {
        Decision {
            reason: reason.to_string(),
            determining_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..decision(action, resource, "deny", rule)
        }
    }

    /// The panic message of `f`, or None if it did not panic.
    fn panics<F: FnOnce()>(f: F) -> Option<String> {
        catch_unwind(AssertUnwindSafe(f))
            .err()
            .map(|p| panic_message(&p))
    }

    #[test]
    fn a_generic_nonzero_exit_is_not_a_spawn_deny() {
        let r = mediated_result("something broke\n", 1, vec![]);
        let msg = panics(|| r.assert_spawn_denied("git")).expect("must not pass");
        assert!(
            msg.contains("expected a journaled shell:spawn deny"),
            "{msg}"
        );
        // On a native run the question cannot even be asked.
        let r = result("DET_ENTERED\nbash: git: command not found\n", 127, vec![]);
        let msg = panics(|| r.assert_spawn_denied("git")).expect("must not pass");
        assert!(
            msg.starts_with("DET_ERROR: assert_spawn_denied needs a mediated run"),
            "{msg}"
        );
    }

    #[test]
    fn a_mediated_run_needs_the_shell_echo_and_a_journaled_shell_exec() {
        // A host zsh: echoes the sentinel, but nothing reaches the broker.
        let host_zsh = RunResult {
            out: "DET_ENTERED\nDET_MEDIATED\nstrands-shell: effect denied: …\n".into(),
            rc: 126,
            decisions: vec![decision(
                "shell:spawn",
                "/usr/bin/git",
                "deny",
                "default-deny",
            )],
            route: Route::Mediated,
        };
        let msg = panics(|| host_zsh.assert_spawn_denied("git")).expect("must not pass");
        assert!(
            msg.contains("no shell:exec decision was journaled"),
            "{msg}"
        );
        // The alias never started the Shell: no echo.
        let no_echo = RunResult {
            out: "DET_ENTERED\nzsh: command not found\n".into(),
            rc: 127,
            decisions: vec![decision("shell:exec", "echo", "permit", "shell_commands")],
            route: Route::Mediated,
        };
        let msg = panics(|| no_echo.assert_contains("x")).expect("must not pass");
        assert!(msg.contains("never echoed DET_MEDIATED"), "{msg}");
        // Both present: the route is proven and ordinary assertions read the output.
        assert!(panics(|| mediated_result("ok\n", 0, vec![]).assert_contains("ok")).is_none());
        // A kernel marker is a native question.
        let msg =
            panics(|| mediated_result("Permission denied\n", 1, vec![]).assert_kernel_marker())
                .expect("must not pass");
        assert!(
            msg.starts_with("DET_ERROR: assert_kernel_marker reads a native run"),
            "{msg}"
        );
    }

    #[test]
    fn a_wrong_interpreter_failure_is_not_a_deny() {
        // Host python3 refused before the Shell ran: an ENOENT spelling, nonzero exit, no sentinel.
        let r = result(
            "python3: /etc/shadow: No such file or directory\n",
            1,
            vec![],
        );
        for msg in [
            panics(|| {
                r.assert_mediated_denied("fs:read", "/etc/shadow");
            }),
            panics(|| r.assert_monty()),
            panics(|| r.assert_kernel_marker()),
        ] {
            let msg = msg.expect("must not pass");
            assert!(
                msg.starts_with("DET_ERROR: the native bash driver never printed DET_ENTERED"),
                "{msg}"
            );
        }
    }

    #[test]
    fn a_hex_box_id_holding_403_is_not_a_denial() {
        // The exact output that made SH-HP-BUILTINS and SH-HP-FS read as denied on
        // 2026-09-28: a successful happy-path run whose randomly minted box id happens to
        // contain the digits 403. Bare `403` in DENIED_PATTERN matched the id, so
        // `assert_allow` failed on a run that had allowed everything.
        let allowed = mediated_result(
            "DET_ENTERED\nDET_MEDIATED\nPIPE=3\nJQ=V\n\
             strands-box: box box-01403bafc4d78ad5 updated\n",
            0,
            vec![],
        );
        assert!(!allowed.matches_denied(), "a hex box id is not a refusal");
        assert!(
            panics(|| allowed.assert_allow()).is_none(),
            "the allow assertion must hold"
        );
        // The second id from that run, where the digits sit mid-string: 8d84031962f0ad6e.
        let other = mediated_result(
            "DET_ENTERED\nDET_MEDIATED\nINSIDE\nFS_OK\n\
             strands-box: box box-8d84031962f0ad6e updated\n",
            0,
            vec![],
        );
        assert!(
            !other.matches_denied(),
            "a hex box id is not a refusal, wherever 403 lands"
        );

        // A real gateway refusal still reads as denied, in every spelling the suite sees.
        for refusal in [
            "DET_ENTERED\nDET_MEDIATED\nfatal: unable to access: returned error: 403\n",
            "DET_ENTERED\nDET_MEDIATED\nHTTP_403 BODY_0\n",
            "DET_ENTERED\nDET_MEDIATED\n403 forbidden\n",
        ] {
            let r = mediated_result(refusal, 1, vec![]);
            assert!(
                r.matches_denied(),
                "must still read as a refusal: {refusal:?}"
            );
        }
    }

    #[test]
    fn a_redacted_absence_failure_names_the_label_and_not_the_marker() {
        // The planted marker leaked into the output: the assertion must fail (that is the
        // whole point) while keeping the marker itself out of the panic message, since that
        // message lands verbatim in the CI log and in verdict.json's note.
        let marker = "DET_SECRET_CNR02_4242_beef";
        let r = mediated_result(&format!("DET_ENTERED\nLEAKED {marker}\n"), 0, vec![]);
        let msg = panics(|| r.assert_absent_secret(marker, "secret.env marker"))
            .expect("a leaked marker must fail the assertion");
        assert!(
            !msg.contains(marker),
            "the panic message must not echo the marker; got: {msg}"
        );
        assert!(
            msg.contains("secret.env marker"),
            "the label must identify which marker: {msg}"
        );
        assert!(
            msg.contains(&marker.len().to_string()),
            "the byte length distinguishes a partial leak from a whole one: {msg}"
        );
        assert!(
            msg.contains("<REDACTED>"),
            "the snippet must still show WHERE the marker surfaced, scrubbed: {msg}"
        );
        // And the honest case still passes: an absent marker is not a failure.
        let clean = mediated_result("DET_ENTERED\nno leak here\n", 0, vec![]);
        assert!(panics(|| clean.assert_absent_secret(marker, "secret.env marker")).is_none());
    }

    #[test]
    fn every_assertion_on_a_hosted_run_needs_the_entry_sentinel() {
        let r = result("WRITTEN\nESCAPED_MARKER absent\n", 1, vec![]);
        for msg in [
            panics(|| r.assert_contains("WRITTEN")),
            panics(|| r.assert_absent("ESCAPED_MARKER")),
            panics(|| r.assert_allow()),
            panics(|| r.assert_contains_any(&["WRITTEN"])),
        ] {
            let msg = msg.expect("must not pass");
            assert!(
                msg.starts_with("DET_ERROR: the native bash driver never printed DET_ENTERED"),
                "{msg}"
            );
        }
        // A bare run (the fixture preflight) is not held to the sentinel.
        assert!(
            panics(|| RunResult::bare("DET_PREFLIGHT_OK\n".into(), 0)
                .assert_contains("DET_PREFLIGHT_OK"))
            .is_none()
        );
    }

    #[test]
    fn a_box_spawn_error_is_an_error_not_a_deny() {
        let r = RunResult::bare(
            "strands-box spawn error: No such file or directory (os error 2)".into(),
            -1,
        );
        let msg = panics(|| r.assert_contains("x")).expect("must not pass");
        assert!(msg.starts_with("DET_ERROR: box never ran"), "{msg}");
        let msg = panics(|| r.assert_kernel_marker()).expect("must not pass");
        assert!(msg.starts_with("DET_ERROR"), "{msg}");
    }

    #[test]
    fn trampoline_warnings_and_disclosures_are_not_never_ran() {
        // Verbatim from a native Linux run (CN-F1-01, CN-W-06):
        // successful workloads whose box printed writable-and-executable warnings.
        let real = "DET_ENTERED\nBUILD_OUTPUT_RAN from-the-agent\nstrands-box: box box-35483aa29a8624ea updated · config /root/.det-harness-boxes/det-box-RwTFah/workspace/.strands-box/box.toml\nstrands-box: starting workload\nstrands-box: [agent] runs /usr/bin/bash with no policy decision over these paths:\n  exec        /usr/bin/bash  (command, implicit)\nstrands-box: warning: [tool.cargo] command /root/.cargo/bin/rustup lies inside the writable grant /root/.cargo, so the process can replace the program it runs\nstrands-box-contain-trampoline: warning: /root/.det-harness-boxes/det-box-RwTFah/workspace/out is both writable and executable: the write grant /root/.det-harness-boxes/det-box-RwTFah/workspace reaches it, so the workload can replace a program it is authorized to run\nstrands-box-contain-trampoline: warning: /root/.det-harness-boxes/det-box-RwTFah/workspace/out/free-hello is both writable and executable: the write grant /root/.det-harness-boxes/det-box-RwTFah/workspace reaches it, so the workload can replace a program it is authorized to run\n";
        let r = result(real, 0, vec![]);
        assert!(panics(|| r.assert_contains("BUILD_OUTPUT_RAN from-the-agent")).is_none());
        assert!(panics(|| r.assert_allow()).is_none());
        // The trampoline's failure lines still are.
        for line in [
            "strands-box-contain-trampoline: exec \"/usr/bin/bash\" failed: Operation not permitted (os error 1)\n",
            "strands-box-contain-trampoline: cannot arm setup status channel: broken pipe\n",
            "strands-box-contain-trampoline: unsupported platform — containment is macOS (Seatbelt) / Linux\n",
            "containment setup failed during Exec\n",
        ] {
            let r = result(&format!("DET_ENTERED\n{line}"), 4, vec![]);
            let msg = panics(|| r.assert_contains("DET_ENTERED"))
                .unwrap_or_else(|| panic!("must not pass: {line}"));
            assert!(
                msg.starts_with("DET_ERROR: box never ran"),
                "{line} -> {msg}"
            );
        }
    }

    #[test]
    fn macos_run_outputs_are_read_as_ran_too() {
        // Verbatim from the native macOS run (same execution, mac leg): trampoline warnings under
        // /private/var/tmp, a probe that may signal itself but not the host, a refused bind.
        let cn_i_07 = "DET_ENTERED\nDET_MEDIATED\nPROBE_ENTERED\nSELF_OK 2467\nSIGNAL_REFUSED 2128: Operation not permitted (os error 1)\nstrands-box-contain-trampoline: warning: /private/var/tmp/det-home/.det-harness-boxes/det-box-spUBuN/workspace/out is both writable and executable: the write grant /private/var/tmp/det-home/.det-harness-boxes/det-box-spUBuN/workspace reaches it, so the workload can replace a program it is authorized to run\n";
        let r = RunResult {
            out: cn_i_07.into(),
            rc: 0,
            decisions: vec![
                decision("shell:exec", "echo", "permit", "shell_commands"),
                decision("shell:spawn", "…/out/sigprobe", "permit", "workspace_spawn"),
            ],
            route: Route::Mediated,
        };
        assert!(panics(|| r.assert_mediated_permitted("shell:spawn", "sigprobe")).is_none());
        assert!(panics(|| r.assert_contains("SIGNAL_REFUSED 2128: ")).is_none());
        assert!(panics(|| r.assert_contains_any(&["SELF_OK", "SELF_REFUSED"])).is_none());
        assert!(panics(|| r.assert_absent("SIGNAL_REACHED")).is_none());
        let cn_n_03 = "DET_ENTERED\nTCP_REFUSED 127.0.0.1:8799: Operation not permitted (os error 1)\nTCP_REFUSED 0.0.0.0:8800: Operation not permitted (os error 1)\nstrands-box-contain-trampoline: warning: /private/var/tmp/det-home/.det-harness-boxes/det-box-ykl8Md/workspace/out/sockprobe is both writable and executable: the write grant /private/var/tmp/det-home/.det-harness-boxes/det-box-ykl8Md/workspace reaches it, so the workload can replace a program it is authorized to run\n";
        assert!(
            panics(|| result(cn_n_03, 0, vec![]).assert_contains("TCP_REFUSED 127.0.0.1:8799"))
                .is_none()
        );
        // Linux's counterpart from the same run: the probe's pid was 2 and self-signal was refused.
        let linux = "DET_ENTERED\nDET_MEDIATED\nPROBE_ENTERED\nSELF_FAILED 2: Operation not permitted (os error 1)\nSIGNAL_REFUSED 48489: Operation not permitted (os error 1)\n";
        assert!(
            panics(|| result(linux, 0, vec![]).assert_contains("SIGNAL_REFUSED 48489: ")).is_none()
        );
    }

    #[test]
    fn the_ssrf_probe_accepts_the_shell_floor_and_rejects_everything_else() {
        let head = "DET_ENTERED\nDET_MEDIATED\n";
        // The Shell kernel's floor: no status line, curl exit 1, its own words.
        let shell = format!("{head}curl: access denied: 169.254.169.254\nCURL_RC=1\n");
        assert_eq!(judge_ssrf_probe(&shell), Ok(SsrfFloor::ShellKernel));
        // Rejections, each for its own reason.
        let cases: &[(&str, &str)] = &[
            ("HTTP_200 BODY_512\nCURL_RC=0\n", "succeeded"),
            ("HTTP_401 BODY_0\nCURL_RC=0\n", "IMDSv2 itself answered"),
            ("HTTP_403 BODY_27\nCURL_RC=0\n", "reached the gateway"),
            ("HTTP_403 BODY_0\nCURL_RC=0\n", "reached the gateway"),
            (
                "curl: policy denied this operation [default-deny]: No permit policy matched this request.\nCURL_RC=1\n",
                "permit did not apply",
            ),
            (
                "curl: blocked by egress control\nCURL_RC=1\n",
                "L7 policy interceptor",
            ),
            (
                "curl: (6) error sending request\nCURL_RC=6\n",
                "transport failure",
            ),
            (
                "strands-shell: curl: invalid option '--connect-timeout'\nCURL_RC=1\n",
                "rejected an option",
            ),
            (
                "ami-id\ninstance-id\nHTTP_200 BODY_90\nCURL_RC=0\n",
                "metadata content",
            ),
            (
                "curl: access denied: 169.254.169.254\nCURL_RC=0\n",
                "no status line and no floor refusal",
            ),
            ("CURL_RC=1\n", "no status line and no floor refusal"),
        ];
        for (tail, reason) in cases {
            let verdict = judge_ssrf_probe(&format!("{head}{tail}"));
            let err = verdict.clone().expect_err(&format!("must reject: {tail}"));
            assert!(err.contains(reason), "{tail} -> {err}");
        }
    }

    #[test]
    fn the_resolver_refusal_words_match_the_second_native_run() {
        // Verbatim from the second native run, both platforms: every
        // symlink spelling is refused as not its identity, the in-workspace one included.
        let linux = "DET_ENTERED\nDET_MEDIATED\ndone\nstrands-shell: cat: /root/.det-harness-boxes/det-box-d4Y82v/workspace/inlink: resolves to a different path, so it is not the identity policy judged\nstrands-shell: cat: /root/.det-harness-boxes/det-box-d4Y82v/workspace/etclink/hostname: resolves to a different path, so it is not the identity policy judged\n";
        assert!(linux.contains(&format!(
            "/root/.det-harness-boxes/det-box-d4Y82v/workspace/inlink: {NOT_IDENTITY_REFUSAL}"
        )));
        assert_eq!(linux.matches(NOT_IDENTITY_REFUSAL).count(), 2);
    }

    #[test]
    fn a_usage_error_or_load_refusal_is_an_error() {
        for out in [
            "error: the following required arguments were not provided:\n  --config <FILE>\n",
            "Usage: strands-box run --config <FILE> [WORKLOAD]...\n",
            "strands-box: error: executable is not an executable regular file: /x\n",
            "strands-box: refusing to run: policy.dw: parse error\n",
            "strands-box-contain-trampoline: exec \"bash\" failed: EPERM\n",
            "containment setup failed during Exec\n",
        ] {
            let r = RunResult::bare(out.into(), 2);
            let msg =
                panics(|| r.assert_entered()).unwrap_or_else(|| panic!("must not pass: {out}"));
            assert!(
                msg.starts_with("DET_ERROR: box never ran"),
                "{out} -> {msg}"
            );
        }
    }

    #[test]
    fn a_spawn_deny_needs_the_journal_and_the_shell_label() {
        let journal = vec![decision(
            "shell:spawn",
            "/usr/bin/git",
            "deny",
            "default-deny",
        )];
        // Complete evidence passes.
        let r = mediated_result(
            "strands-shell: effect denied: policy denied this operation [default-deny]: No permit policy matched this request.\n",
            126,
            journal.clone(),
        );
        assert!(panics(|| r.assert_spawn_denied("git")).is_none());
        // The label without the journal does not.
        let r = mediated_result("strands-shell: effect denied: …\n", 126, vec![]);
        assert!(panics(|| r.assert_spawn_denied("git")).is_some());
        // The journal without the label does not.
        let r = mediated_result("", 126, journal.clone());
        let msg = panics(|| r.assert_spawn_denied("git")).expect("must not pass");
        assert!(msg.contains("did not print \"effect denied\""), "{msg}");
        // A deny for a different program does not.
        let r = mediated_result(
            "strands-shell: effect denied: …\n",
            126,
            vec![decision(
                "shell:spawn",
                "/usr/bin/curl",
                "deny",
                "default-deny",
            )],
        );
        assert!(panics(|| r.assert_spawn_denied("git")).is_some());
        // A permit alongside the deny does not (the gate admitted it).
        let mut both = journal.clone();
        both.push(decision(
            "shell:spawn",
            "/usr/bin/git",
            "permit",
            "spawn_any",
        ));
        let r = mediated_result("strands-shell: effect denied: …\n", 126, both);
        let msg = panics(|| r.assert_spawn_denied("git")).expect("must not pass");
        assert!(msg.contains("the gate admitted it"), "{msg}");
        // The run's own exit is not judged: the native Linux run showed `git status; echo GIT_RC=$?`
        // exits 0 with GIT_RC=126 printed, and the case asserts that status line itself.
        let r = mediated_result("strands-shell: effect denied: …\nGIT_RC=126\n", 0, journal);
        assert!(panics(|| r.assert_spawn_denied("git")).is_none());
    }

    #[test]
    fn a_mediated_deny_needs_a_journaled_deny_for_that_action_and_resource() {
        let r = result(
            "DET_ENTERED\n",
            1,
            vec![decision("fs:read", "~/.aws/x", "deny", "default-deny")],
        );
        assert_eq!(
            r.assert_mediated_denied("fs:read", ".aws/x"),
            "default-deny"
        );
        // A permit is not a deny, whatever the exit code or output says.
        let r = result(
            "DET_ENTERED\ncat: Permission denied\n",
            1,
            vec![decision("fs:read", "~/.aws/x", "permit", "broad_read")],
        );
        assert!(
            panics(|| {
                r.assert_mediated_denied("fs:read", ".aws/x");
            })
            .is_some()
        );
        // A deny for another action is not.
        let r = result(
            "DET_ENTERED\n",
            1,
            vec![decision("fs:write", "~/.aws/x", "deny", "default-deny")],
        );
        assert!(
            panics(|| {
                r.assert_mediated_denied("fs:read", ".aws/x");
            })
            .is_some()
        );
        // No journal at all is not, even with a marker and nonzero exit.
        let r = result(
            "DET_ENTERED\ncat: ~/.aws/x: No such file or directory\n",
            1,
            vec![],
        );
        assert!(
            panics(|| {
                r.assert_mediated_denied("fs:read", ".aws/x");
            })
            .is_some()
        );
    }

    #[test]
    fn monty_evidence_is_the_script_sentinel_or_montys_own_footer() {
        // Verbatim from the native Linux run (MO-4): the alias ran the script, printed the
        // sentinel, then raised.
        let mo4 = "DET_ENTERED\nDET_MONTY_ENTERED\nstrands-box-sock-alias: Python alias accepts only -c SOURCE or SCRIPT\nPermissionError: policy denied this operation [default-deny]: No permit policy matched this request. (Permission denied: '/etc/shadow')\n(this box's Python is Monty, a subset — see the box's docs)\nstrands-box broker: rejected client: Connection reset by peer (os error 104)\n";
        assert!(panics(|| result(mo4, 1, vec![]).assert_monty()).is_none());
        // Verbatim (MO-11): the import was rejected at compile time, so no print ran; the footer
        // is the only proof the script reached Monty, and it suffices.
        let mo11 = "DET_ENTERED\nModuleNotFoundError: No module named 'subprocess'\n(this box's Python is Monty, a subset — see the box's docs)\n";
        assert!(panics(|| result(mo11, 1, vec![]).assert_monty()).is_none());
        // A host CPython prints neither the sentinel-then-footer nor the footer.
        let cpython = "DET_ENTERED\nTraceback (most recent call last):\nModuleNotFoundError: No module named 'subprocess'\n";
        let msg = panics(|| result(cpython, 1, vec![]).assert_monty()).expect("must not pass");
        assert!(msg.contains("did not run under Monty"), "{msg}");
        // CPython that did print the sentinel is caught by the identity control, not here.
        let cpython_entered = "DET_ENTERED\nDET_MONTY_ENTERED\nPermissionError: [Errno 13] Permission denied: '/etc/shadow'\n";
        assert!(panics(|| result(cpython_entered, 1, vec![]).assert_monty()).is_none());
        // No interpreter is an error.
        let none = "DET_ENTERED\npython: no interpreter is available in this Shell\n";
        let msg = panics(|| result(none, 127, vec![]).assert_monty()).expect("must not pass");
        assert!(msg.contains("no Python interpreter"), "{msg}");
    }

    #[test]
    fn allow_needs_exit_zero_and_no_marker() {
        assert!(panics(|| result("DET_ENTERED\nok\n", 0, vec![]).assert_allow()).is_none());
        assert!(panics(|| result("DET_ENTERED\nok\n", 1, vec![]).assert_allow()).is_some());
        assert!(
            panics(|| result("DET_ENTERED\nPermission denied\n", 0, vec![]).assert_allow())
                .is_some()
        );
    }

    #[test]
    fn a_load_refusal_is_asserted_only_when_the_box_refused_and_the_workload_did_not_run() {
        let refused = "strands-box: error: `list` cannot be listed without its contents on Linux; has no lowering for `list`\n";
        assert!(
            panics(|| RunResult::bare(refused.into(), 1)
                .assert_refused_at_load(&["has no lowering for `list`"], "RAN"))
            .is_none()
        );
        // The workload ran: not a load refusal.
        let ran = "DET_ENTERED\nRAN\n";
        assert!(
            panics(|| RunResult::bare(ran.into(), 0)
                .assert_refused_at_load(&["has no lowering"], "RAN"))
            .is_some()
        );
        // Refused for another reason: the needle is required.
        assert!(
            panics(|| RunResult::bare(refused.into(), 1)
                .assert_refused_at_load(&["does not exist yet"], "RAN"))
            .is_some()
        );
    }

    #[test]
    fn a_body_that_asserts_nothing_is_an_error() {
        // Without a box, the fixture itself fails first; the counters are what run_case checks
        // after the body. Exercise the check directly.
        ASSERTIONS.with(|c| c.set(0));
        LAUNCHES.with(|c| c.set(1));
        let assertions = ASSERTIONS.with(Cell::get);
        assert_eq!(assertions, 0);
        RunResult::bare("DET_ENTERED\n".into(), 0).assert_contains("DET_ENTERED");
        assert_eq!(ASSERTIONS.with(Cell::get), 1);
    }

    #[test]
    fn the_drivers_start_with_their_sentinels_and_quote_scripts() {
        assert!(native("git status").starts_with("printf '%s\\n' DET_ENTERED; "));
        assert_eq!(
            mediated("git status"),
            "printf '%s\\n' DET_ENTERED; zsh -lc 'echo DET_MEDIATED; git status'"
        );
        assert_eq!(sh_quote("print('a')"), "'print('\\''a'\\'')'");
    }

    #[test]
    fn platform_skip_records_a_declared_note_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: tests in this module that read DET_RESULTS_DIR run under this one's lock.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("DET_RESULTS_DIR", dir.path()) };
        let other = match Platform::current() {
            Platform::Linux => Platform::Macos,
            Platform::Macos => Platform::Linux,
        };
        run_case_on("CN-T-01", &[other], "d", |_b| panic!("must not run"));
        let rows = verdict::read_rows(dir.path());
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.rows[0].result, "SKIP");
        assert!(rows.rows[0].note.starts_with(verdict::SKIP_NOTE_PREFIX));
        unsafe { std::env::remove_var("DET_RESULTS_DIR") };
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── TEMPORARY QUARANTINE: the runner side (test-integ/QUARANTINE.md) ──────────────────────
    /// Run `run_case_on` for `id` as if on `platform`, capturing the row it writes. The body panics
    /// with a DET_ERROR sentinel so a body that RAN is visible as an ERROR row carrying the sentinel.
    fn quarantine_probe(id: &str, platform: &str) -> verdict::Row {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = user_home().join(".det-harness-boxes");
        std::fs::create_dir_all(&base).expect("create the box base");
        let boxes = tempfile::Builder::new()
            .prefix("probe-")
            .tempdir_in(&base)
            .expect("tempdir");
        // SAFETY: tests that touch DET_RESULTS_DIR / PLATFORM run under this one lock.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DET_RESULTS_DIR", dir.path());
            std::env::set_var("DET_BOX_ROOT", boxes.path());
            std::env::set_var("PLATFORM", platform);
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            run_case_on(id, &[], "probe", |_fixture| {
                panic!("DET_ERROR: BODY_RAN {id}")
            });
        }));
        unsafe {
            std::env::remove_var("PLATFORM");
            std::env::remove_var("DET_RESULTS_DIR");
            std::env::remove_var("DET_BOX_ROOT");
        }
        let rows = verdict::read_rows(dir.path());
        assert!(rows.malformed.is_empty(), "{:?}", rows.malformed);
        assert_eq!(
            rows.rows.len(),
            1,
            "exactly one row for {id} on {platform}; body outcome {:?}",
            outcome.is_ok()
        );
        rows.rows.into_iter().next().unwrap()
    }

    #[test]
    fn a_quarantined_cell_records_the_authorized_skip_and_never_runs_its_body() {
        for id in ["CN-W-05", "CN-W-06"] {
            let row = quarantine_probe(id, "linux");
            assert_eq!(row.result, "SKIP", "{id}: {}", row.note);
            assert_eq!(
                row.note,
                quarantine::note(quarantine::lookup(id, "linux").unwrap())
            );
            assert!(
                !row.note.contains("BODY_RAN"),
                "the body must not run: {}",
                row.note
            );
        }
    }

    /// The row proves `run_case` was entered (a real launch was attempted) rather than a SKIP being
    /// written: either the body's sentinel (a box is available) or the fixture's own launch DET_ERROR
    /// (no usable box on this host). A SKIP of either kind, or any other note, fails.
    fn assert_run_was_attempted(id: &str, row: &verdict::Row) {
        assert_ne!(row.result, "SKIP", "{id}: {}", row.note);
        assert!(
            !row.note.starts_with(quarantine::QUARANTINE_NOTE_PREFIX),
            "{id}: {}",
            row.note
        );
        assert!(
            row.note.contains(&format!("BODY_RAN {id}")) || row.note.contains("box did not launch"),
            "{id}: neither the body's sentinel nor the fixture's launch attempt: {}",
            row.note
        );
    }

    #[test]
    fn the_same_cases_still_run_their_bodies_on_macos() {
        for id in ["CN-W-05", "CN-W-06"] {
            let row = quarantine_probe(id, "macos");
            assert_run_was_attempted(id, &row);
        }
    }

    #[test]
    fn an_unlisted_case_cannot_skip_on_macos() {
        for id in ["CN-E-01", "CN-E-02", "CN-C-01"] {
            let row = quarantine_probe(id, "macos");
            assert_run_was_attempted(id, &row);
        }
    }

    #[test]
    fn a_platform_declaration_still_wins_over_the_quarantine_and_keeps_its_own_note() {
        // A case declared for macos only records the declared-inapplicable SKIP on linux, never a
        // quarantine note, even when the id is quarantined there.
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("DET_RESULTS_DIR", dir.path());
            std::env::set_var("PLATFORM", "linux");
        }
        run_case_on("CN-W-05", &[Platform::Macos], "probe", |_fixture| {
            panic!("DET_ERROR: BODY_RAN")
        });
        unsafe {
            std::env::remove_var("PLATFORM");
            std::env::remove_var("DET_RESULTS_DIR");
        }
        let row = verdict::read_rows(dir.path()).rows.pop().unwrap();
        assert_eq!(row.result, "SKIP");
        assert!(
            row.note.starts_with(verdict::SKIP_NOTE_PREFIX),
            "{}",
            row.note
        );
    }

    // ── native CPython selection and the narrow probe fixture (macOS port review) ──────────────
    fn identity(
        implementation: &str,
        image: &Path,
        roots: &[PathBuf],
        hints: &[PathBuf],
    ) -> PyIdentity {
        PyIdentity {
            implementation: implementation.into(),
            image: image.to_path_buf(),
            roots: roots.to_vec(),
            hints: hints.to_vec(),
        }
    }

    /// A REAL framework-shaped runtime on disk (`…/Python3.framework/Versions/3.9/{bin/python3,
    /// lib/python3.9}`) inside a temporary directory, so existence checks are exercised against the
    /// filesystem rather than against spellings. Returns (tempdir, version root, image, stdlib).
    fn real_framework_runtime() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let version_root = tmp
            .path()
            .join("Library/Frameworks/Python3.framework/Versions/3.9");
        let stdlib = version_root.join("lib/python3.9");
        let image = version_root.join("bin/python3");
        std::fs::create_dir_all(&stdlib).unwrap();
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(&image, b"#!/bin/sh\n").unwrap();
        let canonical = |p: &Path| p.canonicalize().unwrap();
        (
            tmp,
            canonical(&version_root),
            canonical(&image),
            canonical(&stdlib),
        )
    }

    #[test]
    fn the_apple_launcher_shim_is_never_selected_even_when_first() {
        let (_tmp, version_root, image, stdlib) = real_framework_runtime();
        let candidates = vec![PathBuf::from("/usr/bin/python3"), image.clone()];
        let chosen = select_native_python_from(candidates, |path| {
            assert_ne!(
                path,
                Path::new("/usr/bin/python3"),
                "the shim must not even be queried"
            );
            Ok(identity(
                "cpython",
                &image,
                &[version_root.clone(), stdlib.clone()],
                &[],
            ))
        })
        .expect("a real interpreter follows the shim");
        assert_eq!(chosen.executable, image);
        // Nested runtime directories collapse to the framework version root: one grant, nothing above it.
        assert_eq!(chosen.runtime_reads, vec![version_root]);
        assert!(chosen.rejected_hints.is_empty());
    }

    #[test]
    fn a_nonexistent_build_time_hint_is_reported_and_never_granted_while_real_roots_are_kept() {
        // The native run of 2026-09-22: sysconfig's LIBDIR named the build machine's Xcode
        // (`/Applications/Xcode.app/…/Versions/3.9/lib`), which is not on the host. It must not be
        // granted (the box refuses a grant on a path that is not there) and nothing must be made up
        // in its place; the existing roots are still granted.
        let (tmp, version_root, image, stdlib) = real_framework_runtime();
        let phantom = tmp.path().join("Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/lib");
        assert!(!phantom.exists());
        let chosen = select_native_python_from(vec![image.clone()], |_| {
            Ok(identity(
                "cpython",
                &image,
                &[version_root.clone(), stdlib.clone()],
                &[version_root.clone(), phantom.clone()],
            ))
        })
        .expect("a runtime with a stale hint is still usable");
        assert_eq!(
            chosen.runtime_reads,
            vec![version_root.clone()],
            "only the existing roots are granted"
        );
        assert!(
            !phantom.exists(),
            "no dummy directory may be created for a hint"
        );
        assert_eq!(
            chosen.rejected_hints.len(),
            1,
            "{:?}",
            chosen.rejected_hints
        );
        assert!(
            chosen.rejected_hints[0].contains(&phantom.display().to_string())
                && chosen.rejected_hints[0].contains("is not there"),
            "{:?}",
            chosen.rejected_hints
        );
        // The rendered config grants only the existing root: the phantom never reaches the box.
        let config = native_probe_config(
            "[agent]\ncommand = {command}\n\n[agent.filesystem]\nread = [\"/b/ws\"]\n",
            Path::new("/b/ws"),
            &chosen,
        );
        assert!(!config.contains("Xcode.app"), "{config}");
        assert!(
            config.contains(&format!(
                "read = [{}, \"/b/ws\"]",
                serde_json::to_string(&version_root.to_string_lossy()).unwrap()
            )),
            "{config}"
        );
    }

    #[test]
    fn a_hint_that_exists_is_granted_and_a_hint_that_is_a_file_is_not() {
        let (tmp, version_root, image, stdlib) = real_framework_runtime();
        let extra = tmp.path().join("opt/extra-lib");
        std::fs::create_dir_all(&extra).unwrap();
        let file_hint = tmp.path().join("opt/not-a-dir");
        std::fs::write(&file_hint, b"x").unwrap();
        let chosen = select_native_python_from(vec![image.clone()], |_| {
            Ok(identity(
                "cpython",
                &image,
                &[version_root.clone(), stdlib.clone()],
                &[extra.clone(), file_hint.clone()],
            ))
        })
        .unwrap();
        let mut expected = vec![version_root.clone(), extra.canonicalize().unwrap()];
        expected.sort();
        assert_eq!(chosen.runtime_reads, expected);
        assert_eq!(
            chosen.rejected_hints.len(),
            1,
            "{:?}",
            chosen.rejected_hints
        );
        assert!(
            chosen.rejected_hints[0].contains("is not a directory"),
            "{:?}",
            chosen.rejected_hints
        );
    }

    #[test]
    fn a_missing_required_root_or_image_rejects_the_candidate_by_name() {
        let (tmp, version_root, image, _stdlib) = real_framework_runtime();
        let gone_stdlib = tmp.path().join("gone/lib/python3.9");
        let gone_image = tmp.path().join("gone/bin/python3");
        let a = tmp.path().join("a-python3");
        let b = tmp.path().join("b-python3");
        let err = select_native_python_from(vec![a.clone(), b.clone()], |path| {
            if path == a.as_path() {
                // Image exists, but a required root does not: not a usable runtime.
                Ok(identity(
                    "cpython",
                    &image,
                    &[version_root.clone(), gone_stdlib.clone()],
                    &[],
                ))
            } else {
                // The reported image is not on this host at all.
                Ok(identity(
                    "cpython",
                    &gone_image,
                    std::slice::from_ref(&version_root),
                    &[],
                ))
            }
        })
        .expect_err("neither qualifies");
        assert!(
            err.contains(&format!(
                "{}: runtime root {} is not there",
                a.display(),
                gone_stdlib.display()
            )),
            "{err}"
        );
        assert!(
            err.contains(&format!(
                "{}: reported image {} is not there",
                b.display(),
                gone_image.display()
            )),
            "{err}"
        );
    }

    #[test]
    fn a_candidate_that_executes_as_a_usr_bin_image_or_is_not_cpython_is_rejected() {
        let (_tmp, version_root, image, _stdlib) = real_framework_runtime();
        let err = select_native_python_from(
            vec![
                PathBuf::from("/opt/a/python3"),
                PathBuf::from("/opt/b/python3"),
            ],
            |path| {
                if path == Path::new("/opt/a/python3") {
                    Ok(identity("cpython", Path::new("/usr/bin/env"), &[], &[]))
                } else {
                    Ok(identity(
                        "pypy",
                        &image,
                        std::slice::from_ref(&version_root),
                        &[],
                    ))
                }
            },
        )
        .expect_err("neither qualifies");
        assert!(
            err.contains("/opt/a/python3: executes as a /usr/bin image"),
            "{err}"
        );
        assert!(
            err.contains("/opt/b/python3: implementation \"pypy\" is not cpython"),
            "{err}"
        );
        let err = select_native_python_from(Vec::<PathBuf>::new(), |_| Err("unused".into()))
            .expect_err("no candidates");
        assert!(err.contains("no candidates"), "{err}");
    }

    #[test]
    fn the_probe_config_grants_only_the_runtime_directories_and_declares_the_search_path() {
        let template = "name = \"t\"\nbox_dir = \"/b/state\"\n\n[agent]\ncommand = {command}\nworkspace = \"/b/ws\"\n\n[agent.filesystem]\nread = [\"/b/ws\"]\nwrite = [\"/b/ws\"]\nread_file = [\"/h/.det-listed-settings.json\"]\n\n[tool.built]\ncommand = [\"/b/ws/out/built-hello\"]\nworkspace = \"/b/ws\"\n\n[tool.built.filesystem]\nread = [\"/b/ws\"]\n";
        let python = NativePython {
            executable: PathBuf::from(
                "/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
            ),
            runtime_reads: vec![PathBuf::from(
                "/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9",
            )],
            rejected_hints: vec![],
        };
        let config = native_probe_config(template, Path::new("/b/ws"), &python);
        assert!(config.contains("command = [\"/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python\"]"), "{config}");
        // The agent's read list gains exactly the runtime root beside the workspace; the tool's list is untouched.
        assert!(config.contains("[agent.filesystem]\nread = [\"/opt/clt/Library/Frameworks/Python3.framework/Versions/3.9\", \"/b/ws\"]"), "{config}");
        assert_eq!(config.matches("Python3.framework").count(), 2, "{config}");
        assert!(
            config.contains("[tool.built.filesystem]\nread = [\"/b/ws\"]"),
            "{config}"
        );
        // No home, no global exec tree, no widening beyond the declared entries.
        assert!(
            !config.contains("exec = [\"/\"")
                && !config.contains("read = [\"/\"")
                && !config.contains("/Users/")
                && !config.contains("/var/root"),
            "{config}"
        );
        assert!(
            config.contains("[agent.env]\nHOME = \"/b/ws\"\nPATH = \"/usr/bin:/bin\"\n"),
            "{config}"
        );
    }

    #[test]
    fn the_git_tool_config_declares_the_real_git_and_claims_nothing_about_lookup() {
        let template =
            "name = \"t\"\n[agent]\ncommand = [\"bash\"]\nworkspace = \"/b/ws\"\n".to_string();
        let config = git_tool_config(template, Path::new("/opt/clt/usr/bin/git"), "\"/b/ws\"");
        assert!(
            config.contains(
                "[tool.git]\ncommand = [\"/opt/clt/usr/bin/git\"]\nworkspace = \"/b/ws\""
            ),
            "{config}"
        );
        assert!(
            config.contains(
                "[tool.git.filesystem]\nread = [\"/opt/clt\", \"/b/ws\"]\nwrite = [\"/b/ws\"]\n"
            ),
            "{config}"
        );
        assert!(
            !config.contains("libexec"),
            "no exec grant on git's helpers: {config}"
        );
        // The hosted Shell resolves bare host-program names on the broker's own PATH; a declared
        // agent PATH would be a claim the box does not honour, so none is declared.
        assert!(
            !config.contains("[agent.env]") && !config.contains("PATH"),
            "{config}"
        );
    }

    #[test]
    fn the_git_only_policy_names_one_identity_by_spelling_and_by_resolved_path() {
        let policy = git_only_spawn_policy(Path::new("/opt/clt/usr/bin/git"));
        assert!(
            policy.contains("action == Box::Action::\"shell:spawn\""),
            "{policy}"
        );
        assert!(
            policy.contains("context.input.program == \"/opt/clt/usr/bin/git\""),
            "{policy}"
        );
        assert!(
            policy.contains("context.input.program_path == \"/opt/clt/usr/bin/git\""),
            "{policy}"
        );
        assert!(
            policy.contains(" && "),
            "both conditions are required: {policy}"
        );
        // Nothing a bare name or the shim could satisfy.
        assert!(
            !policy.contains("== \"git\"") && !policy.contains("\"/usr/bin/git\""),
            "{policy}"
        );
    }

    // ── forbid attribution: the authored @id lives in determining.ids, not in `rule` ────────────
    #[test]
    fn a_forbid_is_attributed_by_annotation_among_determining_ids_never_by_engine_rule_number() {
        // The native run of 2026-09-22 journaled rule `policy_6` for the fixture's `@id("no_deletes")`
        // forbid; the annotation reaches the journal only through strands.policy.determining.ids.
        let real = mediated_result(
            "rm: policy denied\nRM_RC=1\n",
            1,
            vec![deny(
                "fs:delete",
                "~/ws/cn-x-02.sh",
                "policy_6",
                FORBID_REASON,
                &["no_deletes"],
            )],
        );
        let d = real.assert_forbidden_by("fs:delete", "cn-x-02.sh", "no_deletes");
        assert_eq!(d.rule, "policy_6");

        // Default-deny is not the forbid, whatever ids it carries.
        let default_deny = mediated_result(
            "rm: policy denied\n",
            1,
            vec![deny(
                "fs:delete",
                "~/ws/cn-x-02.sh",
                "default-deny",
                "no permit matched",
                &[],
            )],
        );
        let msg = panics(|| {
            default_deny.assert_forbidden_by("fs:delete", "cn-x-02.sh", "no_deletes");
        })
        .expect("must not pass");
        assert!(
            msg.contains("caused by the forbid @id(\"no_deletes\")")
                && msg.contains("1 deny(ies) on it read otherwise"),
            "{msg}"
        );
        assert!(
            msg.contains("reason=\"no permit matched\"") && msg.contains("out=["),
            "context must be in the message: {msg}"
        );

        // A forbid from some OTHER policy (ids name only its engine number) is not this forbid.
        let other = mediated_result(
            "rm: policy denied\n",
            1,
            vec![deny(
                "fs:delete",
                "~/ws/cn-x-02.sh",
                "policy_6",
                FORBID_REASON,
                &["policy_6"],
            )],
        );
        assert!(
            panics(|| {
                other.assert_forbidden_by("fs:delete", "cn-x-02.sh", "no_deletes");
            })
            .is_some()
        );

        // A reach-floor refusal is not a forbid either, and a permit is not a deny.
        let floor = mediated_result(
            "",
            1,
            vec![deny(
                "fs:delete",
                "~/ws/cn-x-02.sh",
                "enforcement:reach-floor",
                "",
                &["no_deletes"],
            )],
        );
        assert!(
            panics(|| {
                floor.assert_forbidden_by("fs:delete", "cn-x-02.sh", "no_deletes");
            })
            .is_some()
        );
        let mut permitted = decision("fs:delete", "~/ws/cn-x-02.sh", "permit", "policy_9");
        permitted.determining_ids = vec!["no_deletes".into()];
        assert!(
            panics(|| {
                mediated_result("", 0, vec![permitted]).assert_forbidden_by(
                    "fs:delete",
                    "cn-x-02.sh",
                    "no_deletes",
                );
            })
            .is_some()
        );
    }

    #[test]
    fn an_exact_spawn_permit_requires_the_whole_resource_to_match() {
        let git = Path::new("/Library/Developer/CommandLineTools/usr/bin/git");
        let exact = mediated_result(
            "git version 2.39\n",
            0,
            vec![decision(
                "shell:spawn",
                "/Library/Developer/CommandLineTools/usr/bin/git",
                "permit",
                "policy_1",
            )],
        );
        exact.assert_spawn_permitted_exactly(git);
        // A permit on the shim, on a helper under git-core, or a deny on the right path: none pass.
        for (resource, verdict) in [
            ("/usr/bin/git", "permit"),
            (
                "/Library/Developer/CommandLineTools/usr/libexec/git-core/git",
                "permit",
            ),
            ("/Library/Developer/CommandLineTools/usr/bin/git", "deny"),
        ] {
            let r = mediated_result(
                "",
                0,
                vec![decision("shell:spawn", resource, verdict, "policy_1")],
            );
            let msg = panics(|| r.assert_spawn_permitted_exactly(git)).expect("must not pass");
            assert!(
                msg.contains("resource exactly") && msg.contains(resource),
                "{msg}"
            );
        }
        let none = mediated_result("", 0, vec![]);
        assert!(
            panics(|| none.assert_spawn_permitted_exactly(git))
                .expect("must not pass")
                .contains("(none)")
        );
    }

    #[test]
    fn framework_roots_and_shims_are_recognised() {
        assert_eq!(
            framework_root(Path::new("/L/Python3.framework/Versions/3.9/bin/python3")),
            Some(PathBuf::from("/L/Python3.framework/Versions/3.9"))
        );
        assert_eq!(framework_root(Path::new("/usr/local/bin/python3")), None);
        assert!(
            is_apple_shim(Path::new("/usr/bin/python3"))
                && is_apple_shim(Path::new("/usr/bin/git"))
        );
        assert!(!is_apple_shim(Path::new(
            "/Library/Developer/CommandLineTools/usr/bin/git"
        )));
    }

    #[test]
    fn the_identity_query_parses_what_this_hosts_python_reports() {
        // The real query against this host's python3 (any platform): CPython, an existing image, dirs.
        let Some(py) = std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("python3"))
                .find(|c| is_executable(c))
        }) else {
            return;
        };
        let id = query_python_identity(&py).expect("this host's python answers the identity query");
        assert_eq!(id.implementation, "cpython");
        assert!(id.image.exists(), "{:?}", id.image);
        assert_eq!(id.roots.len(), 2, "base_prefix and stdlib: {:?}", id.roots);
        assert!(
            id.roots.iter().all(|r| r.is_dir()),
            "a running interpreter's roots exist: {:?}",
            id.roots
        );
        assert!(
            !id.hints.is_empty(),
            "prefix and LIBDIR are reported as hints: {:?}",
            id.hints
        );
        // And the real selection over this interpreter grants only directories that exist.
        let chosen = select_native_python_from(vec![py], query_python_identity);
        if let Ok(chosen) = chosen {
            assert!(
                chosen.runtime_reads.iter().all(|d| d.is_dir()),
                "{:?}",
                chosen.runtime_reads
            );
        }
    }

    #[test]
    fn native_python_start_is_distinct_from_bash_and_monty() {
        for text in [
            "DET_ENTERED\nprobe ERR 1 denied\n",
            "DET_MONTY_ENTERED\nprobe ERR 1 denied\n",
            "DET_NATIVE_CPYTHON\\nprobe ERR 1 denied\n",
        ] {
            let r = RunResult {
                out: text.into(),
                rc: 0,
                decisions: vec![],
                route: Route::NativePython,
            };
            let msg = panics(|| r.assert_errno("probe", 1)).expect("wrong route must fail");
            assert!(
                msg.starts_with("DET_ERROR: native CPython did not start"),
                "{msg}"
            );
        }
        let r = RunResult {
            out: "DET_NATIVE_CPYTHON\nprobe ERR 1 denied\nother ERR 13 denied\nok OK True\n".into(),
            rc: 0,
            decisions: vec![],
            route: Route::NativePython,
        };
        r.assert_errno("probe", 1);
        r.assert_ok("ok", "True");
        assert_eq!(r.errno_for("other"), Some(13));
        assert!(panics(|| r.assert_errno("other", 1)).is_some());
    }

    #[test]
    fn mainline_shell_refusal_helper_needs_mediation_and_a_deny() {
        let bare = result("DET_ENTERED\npolicy denied\n", 1, vec![]);
        assert!(panics(|| bare.assert_shell_denied()).is_some());
        let missing = mediated_result("policy denied\n", 1, vec![]);
        assert!(panics(|| missing.assert_shell_denied()).is_some());
        let valid = mediated_result(
            "policy denied\n",
            1,
            vec![decision("fs:read", "/private/file", "deny", "default-deny")],
        );
        assert!(panics(|| valid.assert_shell_denied()).is_none());
    }
}
