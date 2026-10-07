//! Claude Code's Bash tool wraps every command in a bash preamble. The preamble is what an
//! unmodified agent sends, so each construct in it must run through the hosted Shell without a
//! diagnostic, as it does through bash.
//!
//! `fixtures/claude-code-snapshot-script.sh` is the snapshot-creation script Claude Code 2.1.285
//! passed to `bash -c -l`, captured with a logging shell on `PATH`; only the home path is
//! generalised. [`WRAPPER`] is the per-command string it passed to `bash -c`, with the sourced
//! snapshot and the command inserted the way Claude Code inserts them.

use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use strands_shell::os::{STDERR, STDOUT};
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, Shell};

const SNAPSHOT_SCRIPT: &str = include_str!("fixtures/claude-code-snapshot-script.sh");
const SNAPSHOT_FILE: &str =
    "/home/lash/.claude/shell-snapshots/snapshot-bash-1790732593649-42pi4m.sh";
const CWD_FILE: &str = "/home/lash/claude-1234-cwd";

/// The per-command wrapper, one command inserted.
fn wrapper(snapshot: Option<&str>, command: &str) -> String {
    let mut clauses = Vec::new();
    if let Some(snapshot) = snapshot {
        clauses.push(format!("source {snapshot} 2>/dev/null || true"));
    }
    clauses.push("shopt -u extglob 2>/dev/null || true".to_string());
    clauses.push(
        "{ \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true"
            .to_string(),
    );
    clauses.push(format!("eval '{command}' < /dev/null"));
    clauses.push(format!("pwd -P >| {CWD_FILE}"));
    clauses.join(" && ")
}

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (rt, tokio::task::LocalSet::new())
}

fn drained(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> String {
    let mut text = String::new();
    while let Ok(chunk) = rx.try_recv() {
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    text
}

/// A shell whose home holds an empty `.bashrc`, the branch of the snapshot script that walks
/// functions and shell options.
async fn shell_with_bashrc() -> Shell {
    let mut shell = Shell::builder().build().unwrap();
    let output = shell
        .run("mkdir -p /home/lash/.claude/shell-snapshots && : > /home/lash/.bashrc")
        .await;
    assert_eq!(output.status, 0, "{}", output.stderr);
    shell
}

/// The snapshot script's other branch: no `.bashrc`, so only `shopt -s expand_aliases` is recorded.
async fn shell_without_bashrc() -> Shell {
    let mut shell = Shell::builder().build().unwrap();
    let output = shell
        .run("mkdir -p /home/lash/.claude/shell-snapshots")
        .await;
    assert_eq!(output.status, 0, "{}", output.stderr);
    shell
}

fn snapshot_script_without_bashrc() -> String {
    let start = SNAPSHOT_SCRIPT
        .find("      # shopt before functions")
        .expect("the functions block");
    let end = SNAPSHOT_SCRIPT
        .find("      # Check for rg availability")
        .expect("the rg block");
    let mut script = String::new();
    script.push_str(&SNAPSHOT_SCRIPT[..start].replace(
        "source \"/home/lash/.bashrc\" < /dev/null",
        "# No user config file to source",
    ));
    script.push_str("      echo \"shopt -s expand_aliases\" >> \"$SNAPSHOT_FILE\"\n\n");
    script.push_str(&SNAPSHOT_SCRIPT[end..]);
    script
}

/// **The snapshot script writes its file, and every command wrapper after it is silent.**
#[test]
fn the_snapshot_script_writes_its_file_and_the_wrapper_is_silent() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = shell_with_bashrc().await;
        let created = shell.run(SNAPSHOT_SCRIPT).await;
        assert_eq!(created.status, 0, "stderr: {}", created.stderr);
        let written = shell.run(&format!("cat {SNAPSHOT_FILE}")).await;
        for section in [
            "# Aliases",
            "function rg {",
            "function pkill {",
            "export PATH=",
        ] {
            assert!(
                written.stdout.contains(section),
                "missing {section:?} in\n{}",
                written.stdout
            );
        }

        let ran = shell
            .run(&wrapper(Some(SNAPSHOT_FILE), "printf %s done"))
            .await;
        assert_eq!(ran.stderr, "", "the wrapper must produce no diagnostic");
        assert_eq!(ran.stdout, "done");
        assert_eq!(ran.status, 0);
        let cwd = shell.run(&format!("cat {CWD_FILE}")).await;
        assert_eq!(cwd.stdout, "/home/lash\n");

        let sourced = shell
            .run(&wrapper(Some(SNAPSHOT_FILE), "type pkill; type rg"))
            .await;
        assert_eq!(sourced.stderr, "");
        assert_eq!(
            sourced.stdout, "pkill is a shell function\nrg is a shell function\n",
            "the snapshot was sourced, not skipped behind its 2>/dev/null"
        );
    }));
}

/// **A special builtin runs inside a capture and under a redirect**, the two routes the wrapper's
/// `source … 2>/dev/null` takes.
#[test]
fn a_special_builtin_runs_inside_a_capture_and_under_a_redirect() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("printf 'printf sourced' > /home/lash/s.sh; printf '[%s][%s][%s]' \"$(eval printf evald)\" \"$(source /home/lash/s.sh)\" \"$(command printf cmd)\"; f() { printf in-f; }; printf '[%s]' \"$({ f; } 2>/dev/null)\"; eval 'printf %s redirected' 2>/dev/null; source /home/lash/s.sh >/home/lash/out; printf '[%s]' \"$(cat /home/lash/out)\"").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "[evald][sourced][cmd][in-f]redirected[sourced]");
    }));
}

/// **Without a `.bashrc` the snapshot script itself is silent**, so the branch Claude Code takes
/// on a host with no bash configuration produces nothing at all.
#[test]
fn without_a_bashrc_the_snapshot_script_and_the_wrapper_are_both_silent() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = shell_without_bashrc().await;
        let created = shell.run(&snapshot_script_without_bashrc()).await;
        assert_eq!(created.status, 0);
        assert_eq!(created.stderr, "");
        let ran = shell
            .run(&wrapper(Some(SNAPSHOT_FILE), "printf %s done"))
            .await;
        assert_eq!(ran.stderr, "");
        assert_eq!(ran.stdout, "done");
        assert_eq!(ran.status, 0);
    }));
}

/// **The wrapper is silent on an embedder's stderr channel too.** A box installs channel writers
/// on the shell's descriptors, the route a diagnostic took past `2>/dev/null` before.
#[test]
fn the_wrapper_sends_nothing_to_an_installed_stderr_channel() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = shell_without_bashrc().await;
        let created = shell.run(&snapshot_script_without_bashrc()).await;
        assert_eq!(created.status, 0);
        let (out_tx, mut out_rx) = strands_shell::os::pipe(64);
        let (err_tx, mut err_rx) = strands_shell::os::pipe(64);
        shell.proc.set_channel_writer(STDOUT, out_tx);
        shell.proc.set_channel_writer(STDERR, err_tx);

        let ran = shell
            .run(&wrapper(Some(SNAPSHOT_FILE), "printf %s done"))
            .await;
        assert_eq!(ran.status, 0);
        assert_eq!(
            drained(&mut err_rx),
            "",
            "nothing may reach the stderr channel"
        );
        assert_eq!(drained(&mut out_rx), "done");
    }));
}

/// **The wrapper without a snapshot is silent as well**, the shape Claude Code falls back to
/// when snapshot creation failed.
#[test]
fn the_wrapper_without_a_snapshot_is_silent() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let ran = shell.run(&wrapper(None, "printf %s done")).await;
        assert_eq!(ran.stderr, "");
        assert_eq!(ran.stdout, "done");
        assert_eq!(ran.status, 0);
    }));
}

async fn run(command: &str) -> strands_shell::Output {
    let mut shell = Shell::builder().build().unwrap();
    shell.run(command).await
}

#[test]
fn builtin_runs_the_named_builtin_past_a_function_of_that_name() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("echo() { printf shadow; }; builtin echo real; \\builtin printf %s ok").await;
        assert_eq!(out.stdout, "real\nok");
        assert_eq!(out.stderr, "");
        let refused = run("builtin nosuch; echo rc=$?").await;
        assert_eq!(
            refused.stderr,
            "strands-shell: builtin: nosuch: not a shell builtin\n"
        );
        assert_eq!(refused.stdout, "rc=1\n");
        let special = run("builtin eval 'printf %s evaluated'").await;
        assert_eq!(special.stdout, "evaluated");
    }));
}

/// Records the program of every admitted run and refuses one name.
struct ProgramGate {
    forbidden: &'static str,
    programs: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl EffectInterceptor for ProgramGate {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::ShellRun { program, .. } = effect {
            self.programs.lock().unwrap().push((*program).to_string());
            if *program == self.forbidden {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test policy denied program",
                ));
            }
        }
        Ok(Box::new(NoopPermit))
    }
}

struct NoopPermit;

#[async_trait]
impl EffectPermit for NoopPermit {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// **`builtin X` is admitted and recorded as the program `X`**, so a rule on `X` holds across the
/// prefix, and an unknown name still reaches the `builtin` builtin's own refusal.
#[test]
fn builtin_is_admitted_as_the_program_it_names() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let programs = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(ProgramGate {
            forbidden: "cd",
            programs: Arc::clone(&programs),
        });
        let mut shell = Shell::builder().effect_interceptor(gate).build().unwrap();

        let refused = shell.run("builtin cd /tmp; pwd").await;
        assert!(
            refused.stderr.contains("effect denied"),
            "a rule on `cd` must refuse `builtin cd`: {}",
            refused.stderr
        );
        assert_eq!(
            refused.stdout, "/home/lash\n",
            "the refused `cd` must not change the directory"
        );

        let unknown = shell.run("builtin nosuch; echo rc=$?").await;
        assert_eq!(
            unknown.stderr,
            "strands-shell: builtin: nosuch: not a shell builtin\n"
        );
        assert_eq!(unknown.stdout, "rc=1\n");

        let plain = shell.run("builtin echo hi").await;
        assert_eq!(plain.stderr, "");
        assert_eq!(plain.stdout, "hi\n");

        let recorded = programs.lock().unwrap().clone();
        assert_eq!(
            recorded,
            ["cd", "pwd", "builtin", "echo", "echo"],
            "the recorded program is the builtin named after the prefix"
        );
    }));
}

#[test]
fn unalias_and_unset_accept_a_double_dash() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out =
            run("alias x=y; f() { :; }; unalias -- x; unset -f -- f; alias; f; echo rc=$?").await;
        assert_eq!(out.stderr, "strands-shell: f: command not found\n");
        assert_eq!(out.stdout, "rc=127\n");
    }));
}

#[test]
fn shopt_records_state_and_refuses_an_unknown_name() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("shopt -q extglob; echo a=$?; shopt -s extglob; shopt -q extglob; echo b=$?; shopt -p extglob; shopt -u extglob; shopt -p extglob; shopt nosuch; echo c=$?").await;
        assert_eq!(out.stdout, "a=1\nb=0\nshopt -s extglob\nshopt -u extglob\nc=1\n");
        assert_eq!(out.stderr, "strands-shell: shopt: nosuch: invalid shell option name\n");
    }));
}

#[test]
fn a_quoted_word_inside_a_brace_expansion_expands_and_keeps_its_fields() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("set -- 'a b' c; printf '[%s]' ${1+\"$@\"}; printf '|'; printf '[%s]' \"${1+\"$@\"}\"; printf '|'; printf '[%s]' ${3+\"$@\"}; printf '|'; q=inner; echo ${p:-\"${q}\"}").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "[a b][c]|[a b][c]|[]|inner\n");
    }));
}

#[test]
fn a_subscript_on_a_scalar_reads_as_bash_does() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("x=a; echo \"${x[0]}-${x[@]}-${x[*]}-${x[1]}-${#x[@]}-${#y[@]}-${y[@]+set}-${x[@]+set}\"").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "a-a-a--1-0--set\n");
    }));
}

#[test]
fn the_function_keyword_defines_a_function() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out =
            run("function h { printf '%s-' \"$1\"; }; function k() { printf k; }; h 1; k").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "1-k");
    }));
}

#[test]
fn a_pipeline_can_feed_a_compound_command() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("printf '1\\n2\\n' | while read l; do printf '[%s]' \"$l\"; done; printf '|'; printf 'x' | if read l; then printf \"got $l\"; fi | tr x y").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "[1][2]|got y");
    }));
}

#[test]
fn a_redirect_on_source_and_on_a_builtin_covers_their_diagnostics() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("printf 'echo \"unterminated\\n' > /home/lash/bad.sh; source /home/lash/bad.sh 2>/dev/null || true; unalias nosuch 2>/dev/null; unalias nosuch 2>/home/lash/err; printf '[%s]' \"$(cat /home/lash/err)\"").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "[strands-shell: unalias: nosuch: not found]");
    }));
}

#[test]
fn a_groups_stderr_follows_the_redirects_in_order() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("{ echo out; echo err >&2; } >/dev/null 2>&1; printf '|'; { echo out; echo err >&2; } >/home/lash/o 2>&1; cat /home/lash/o; printf '|'; { echo out; echo err >&2; } 2>&1 >/home/lash/o2; cat /home/lash/o2").await;
        assert_eq!(out.stderr, "");
        assert_eq!(
            out.stdout, "|out\nerr\n|err\nout\n",
            "the third group's stderr goes to the stdout that stood before the file redirect"
        );
    }));
}

/// Three hundred lines, written by a loop whose every iteration goes through the shell's own
/// stderr path.
const MANY_STDERR_LINES: &str = "i=0; while [ $i -lt 300 ]; do echo line$i >&2; i=$((i+1)); done";

/// A redirected group must finish while it is still writing, so a hang is a failure here and
/// not a stall.
async fn within_deadline(command: &str) -> strands_shell::Output {
    tokio::time::timeout(std::time::Duration::from_secs(30), run(command))
        .await
        .expect("a redirected group that writes more than its channel holds must still finish")
}

#[test]
fn a_group_writing_many_stderr_lines_to_dev_null_is_silent_and_finishes() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = within_deadline(&format!(
            "{{ {MANY_STDERR_LINES}; echo done; }} 2>/dev/null"
        ))
        .await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "done\n");
    }));
}

#[test]
fn a_group_writing_many_stderr_lines_to_stdout_keeps_every_line_in_order() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = within_deadline(&format!("{{ {MANY_STDERR_LINES}; }} 2>&1")).await;
        assert_eq!(out.stderr, "");
        let expected: String = (0..300).map(|i| format!("line{i}\n")).collect();
        assert_eq!(
            out.stdout, expected,
            "every line reaches stdout, in the order written"
        );
    }));
}

#[test]
fn a_group_writing_many_stderr_lines_piped_to_tail_yields_the_last_lines() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = within_deadline(&format!("{{ {MANY_STDERR_LINES}; }} 2>&1 | tail -5")).await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "line295\nline296\nline297\nline298\nline299\n");
    }));
}

#[test]
fn head_and_tail_accept_a_bare_count() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("printf '1\\n2\\n3\\n' | head -2; printf '1\\n2\\n3\\n' | tail -1").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "1\n2\n3\n");
    }));
}

#[test]
fn a_scalar_append_appends() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("x=a; x+=b; unset y; y+=c; printf '%s %s' \"$x\" \"$y\"").await;
        assert_eq!(out.stderr, "");
        assert_eq!(out.stdout, "ab c");
    }));
}

/// **An array is parsed and refused when run**, so a function body holding one defines as in bash
/// and the refusal is the first thing a call reports.
#[test]
fn an_array_defines_inside_a_function_and_is_refused_when_run() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run("function pk { local -a probe=(); probe+=(\"$1\"); echo unreached; }; echo defined; pk x; echo rc=$?").await;
        assert_eq!(out.stdout, "defined\nrc=2\n");
        assert_eq!(out.stderr, "strands-shell: arrays are not supported\n");
    }));
}
