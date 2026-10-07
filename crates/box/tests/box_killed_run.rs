//! A `run` killed with `SIGKILL` while decisions are in flight: what the next run recovers.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{BOX_HOME, Configured, Request};

/// How many `shell:exec` requests the policy admits over a box's whole history.
const BUDGET: usize = 50;
/// Kill-and-restart rounds. Each runs under a fresh box.
const ROUNDS: usize = 3;
/// The whole test gives up starting new rounds after this long.
const TIME_LIMIT: Duration = Duration::from_secs(240);
/// Permits the writer must have received before the kill is sent.
const PERMITS_BEFORE_THE_KILL: usize = 6;
/// Parallel writer loops, so several requests can be in flight when the kill lands.
const WRITERS: [&str; 3] = ["a", "b", "c"];
/// The line the test appends to each writer log after `kill(2)` has returned.
const KILL_MARK: &str = "KILL";

fn counting_policy() -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.command == "printf tick" }};
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {{
    exists (issued: Long). (
        (count for (t: Timepoint). where (
            formerly within 3600s (
                Box::Action::"shell:exec"::request{{ input.command: _ }} && tp(t)
            )
        )) == issued
        && issued >= {BUDGET}
    )
}};
"#
    )
}

/// Three loops that each log a request before issuing it and its verdict after, and stop at the
/// first refusal.
const WRITER: &str = r#"
writer() {
    log="{box_home}/log-$1"
    n=0
    while [ "$n" -lt 10000 ]; do
        n=$((n + 1))
        printf 'start %s\n' "$n" >> "$log"
        if zsh -c "printf tick" >/dev/null 2>&1; then
            printf 'done %s 0\n' "$n" >> "$log"
        else
            printf 'done %s 1\n' "$n" >> "$log"
            break
        fi
    done
    printf 'end\n' >> "$log"
}
writer a & writer b & writer c &
wait
"#;

/// Spend the rest of the budget one request at a time and print one `ok` per permit.
fn meter() -> String {
    format!(
        r#"
n=0
while [ "$n" -lt {} ]; do
    n=$((n + 1))
    zsh -c "printf tick" >/dev/null 2>&1 || break
    printf 'ok\n'
done
printf 'meter-end\n'
"#,
        BUDGET + 10
    )
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// How many permits the meter received, or fail when the metering run did not complete.
fn permits_metered(box_: &Configured, what: &str) -> usize {
    let output = box_.bash(&meter());
    let out = stdout(&output);
    assert!(
        !stderr(&output).contains("strands-box: error:") && out.contains("meter-end"),
        "{what}: the metering run must start and run to its end: {output:?}"
    );
    out.lines().filter(|line| *line == "ok").count()
}

/// One writer log split at the kill mark.
struct WriterLog {
    before: Vec<String>,
    after: Vec<String>,
}

impl WriterLog {
    fn read(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut before = Vec::new();
        let mut after = Vec::new();
        let mut marked = false;
        for line in text.lines() {
            if line == KILL_MARK {
                marked = true;
            } else if marked {
                after.push(line.to_string());
            } else {
                before.push(line.to_string());
            }
        }
        Self { before, after }
    }

    fn started_before_the_kill(&self) -> usize {
        self.before
            .iter()
            .filter(|line| line.starts_with("start "))
            .count()
    }

    /// Permits returned for requests issued before the kill, wherever the writer logged them.
    fn permits_returned(&self) -> usize {
        let issued_before: Vec<&str> = self
            .before
            .iter()
            .filter_map(|line| line.strip_prefix("start "))
            .collect();
        self.before
            .iter()
            .chain(self.after.iter())
            .filter_map(|line| line.strip_prefix("done ")?.strip_suffix(" 0"))
            .filter(|number| issued_before.contains(number))
            .count()
    }

    /// Requests both issued and permitted after the kill mark.
    fn permits_after_the_kill(&self) -> Vec<String> {
        let started_after: Vec<&str> = self
            .after
            .iter()
            .filter_map(|line| line.strip_prefix("start "))
            .collect();
        self.after
            .iter()
            .filter(|line| line.starts_with("done ") && line.ends_with(" 0"))
            .filter(|line| {
                line.strip_prefix("done ")
                    .and_then(|rest| rest.strip_suffix(" 0"))
                    .is_some_and(|number| started_after.contains(&number))
            })
            .cloned()
            .collect()
    }
}

fn writer_logs(home: &Path) -> Vec<PathBuf> {
    WRITERS
        .iter()
        .map(|writer| home.join(format!("log-{writer}")))
        .collect()
}

fn permits_logged(logs: &[PathBuf]) -> usize {
    logs.iter()
        .map(|log| WriterLog::read(log).permits_returned())
        .sum()
}

fn total_log_bytes(logs: &[PathBuf]) -> u64 {
    logs.iter()
        .map(|log| std::fs::metadata(log).map(|meta| meta.len()).unwrap_or(0))
        .sum()
}

/// Wait until no writer log grows for one second, or the deadline passes.
fn wait_for_the_writers_to_settle(logs: &[PathBuf], deadline: Duration) {
    let started = Instant::now();
    let mut quiet_since = Instant::now();
    let mut seen = total_log_bytes(logs);
    while quiet_since.elapsed() < Duration::from_secs(1) && started.elapsed() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let now = total_log_bytes(logs);
        if now != seen {
            seen = now;
            quiet_since = Instant::now();
        }
    }
}

/// How many permits one box grants over its whole history under `policy`, measured on a box that
/// is never killed: it spends three, then meters the rest.
fn lifetime_permits(policy: &str) -> usize {
    let control = Request::with_policy("killed-run-control", policy).expect();
    let spent = control.bash(
        r#"zsh -c "printf tick" && zsh -c "printf tick" && zsh -c "printf tick" && printf 'spent-three'"#,
    );
    assert!(
        stdout(&spent).contains("spent-three"),
        "the control box must permit three requests: {spent:?}"
    );
    let metered = permits_metered(&control, "control");
    assert!(
        metered > 0 && metered + 3 <= BUDGET,
        "the control box must stop the meter inside the budget: metered={metered}"
    );
    3 + metered
}

/// **A `run` killed mid-decision leaves a history whose recovered count lies between the permits
/// the workload received and the requests it had issued, and nothing is permitted after the kill.**
#[test]
fn a_run_killed_mid_decision_leaves_a_recoverable_count_and_grants_nothing_after_the_kill() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let started = Instant::now();
    let policy = counting_policy();
    let lifetime = lifetime_permits(&policy);

    let mut rounds = 0;
    for round in 0..ROUNDS {
        if started.elapsed() > TIME_LIMIT {
            break;
        }
        rounds += 1;
        let box_ = Request::with_policy(&format!("killed-run-{round}"), &policy).expect();
        let home = box_.box_home();
        let logs = writer_logs(&home);
        let run_stderr = std::fs::File::create(home.join("run.stderr")).expect("a stderr file");

        let mut run = box_.command_for("/bin/bash");
        run.arg("-c")
            .arg(WRITER.replace(BOX_HOME, &home.display().to_string()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(run_stderr));
        let mut running = run.spawn().expect("spawn strands-box run");

        let waiting = Instant::now();
        while permits_logged(&logs) < PERMITS_BEFORE_THE_KILL {
            if let Some(status) = running.try_wait().expect("poll the run") {
                panic!(
                    "round {round}: the run ended with {status} before the kill: {}",
                    std::fs::read_to_string(home.join("run.stderr")).unwrap_or_default()
                );
            }
            assert!(
                waiting.elapsed() < Duration::from_secs(60),
                "round {round}: the writers never reached {PERMITS_BEFORE_THE_KILL} permits: {}",
                std::fs::read_to_string(home.join("run.stderr")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        running.kill().expect("SIGKILL the run");
        let _ = running.wait();
        for log in &logs {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(log)
                .expect("the writer log exists");
            writeln!(file, "{KILL_MARK}").expect("mark the kill");
        }
        wait_for_the_writers_to_settle(&logs, Duration::from_secs(30));

        let read: Vec<WriterLog> = logs.iter().map(|log| WriterLog::read(log)).collect();
        let permitted: usize = read.iter().map(WriterLog::permits_returned).sum();
        let issued: usize = read.iter().map(WriterLog::started_before_the_kill).sum();
        let after: Vec<String> = read
            .iter()
            .flat_map(WriterLog::permits_after_the_kill)
            .collect();
        assert!(
            after.is_empty(),
            "round {round}: a request issued after the kill was permitted: {after:?}"
        );
        assert!(
            permitted >= PERMITS_BEFORE_THE_KILL && issued < lifetime,
            "round {round}: the kill must land inside the budget with permits outstanding: \
             permitted={permitted} issued={issued} lifetime={lifetime}"
        );

        let metered = permits_metered(&box_, &format!("round {round}"));
        let recovered = lifetime as i64 - metered as i64;
        assert!(
            recovered >= permitted as i64 && recovered <= issued as i64,
            "round {round}: the recovered count must lie between the permits returned and the \
             requests issued: recovered={recovered} permitted={permitted} issued={issued} \
             metered={metered}"
        );
    }
    assert!(
        rounds > 0,
        "at least one round must run inside {TIME_LIMIT:?}"
    );
}
