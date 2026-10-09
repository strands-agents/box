//! The on-instance jailbreak harness and its host-evidence verdict.

mod agent_a;
mod coverage;
mod creds;
mod oracle;
mod process;
mod setup;
mod shutdown;
mod stream;
mod upload;
mod validity;
mod verdict;
mod worker;

pub use verdict::*;

use std::{
    collections::BTreeMap,
    fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Run a jailbreak harness command and return its process exit code.
pub fn command(args: &[String]) -> u8 {
    match dispatch(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("jailbreak: {error}");
            2
        }
    }
}

/// `--flag value` pairs, checked against the flags one command accepts.
struct Flags<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> Flags<'a> {
    fn parse(args: &'a [String], allowed: &[&str]) -> io::Result<Self> {
        if args.len() % 2 != 0 {
            return Err(io::Error::other("each flag requires a value"));
        }
        let mut flags = BTreeMap::new();
        for pair in args.chunks_exact(2) {
            let flag = pair[0].as_str();
            if !flag.starts_with("--") || flags.insert(flag, pair[1].as_str()).is_some() {
                return Err(io::Error::other("invalid or repeated flag"));
            }
            if !allowed.contains(&flag) {
                return Err(io::Error::other(format!("unknown flag {flag}")));
            }
        }
        Ok(Self(flags))
    }
    fn get(&self, key: &str) -> Option<&'a str> {
        self.0.get(key).copied()
    }
    fn required(&self, key: &str) -> io::Result<&'a str> {
        self.get(key)
            .ok_or_else(|| io::Error::other(format!("{key} is required")))
    }
}

fn dispatch(args: &[String]) -> io::Result<u8> {
    let action = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or_default();
    if let Some(worker) = worker::Worker::parse(action, rest)? {
        worker.run()?;
        return Ok(0);
    }
    if action != "run" {
        return Err(io::Error::other("expected jailbreak run"));
    }
    let flags = Flags::parse(rest, &["--case", "--platform", "--box-commit", "--run-id"])?;
    shutdown::install()?;
    run(&flags)
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn run(flags: &Flags) -> io::Result<u8> {
    let case = flags.get("--case").unwrap_or("network-egress");
    if case != "network-egress" {
        return Err(io::Error::other("only --case network-egress is supported"));
    }
    let home = fs::canonicalize(PathBuf::from(
        std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is required"))?,
    ))?;
    let source = std::env::var_os("INDET_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("strands-box"));
    let run_dir = home.join("indet-run").join(case);
    setup::fresh(&run_dir)?;
    for dir in ["oracle", "agent-a", "agent-b"] {
        fs::create_dir(run_dir.join(dir))?;
    }
    let platform = flags
        .get("--platform")
        .map(|v| v.to_string())
        .unwrap_or_else(|| {
            env(
                "PLATFORM",
                if cfg!(target_os = "macos") {
                    "macos"
                } else {
                    "linux"
                },
            )
        });
    if !matches!(platform.as_str(), "macos" | "linux") {
        return Err(io::Error::other("platform must be macos or linux"));
    }
    let commit = flags
        .get("--box-commit")
        .map(|v| v.to_string())
        .unwrap_or_else(|| env("BOX_COMMIT", "unknown"));
    let commit = fs::read_to_string(source.join("COMMIT"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().into())
        .unwrap_or(commit);
    let run = Run {
        dimension: case.into(),
        platform,
        box_commit: Some(commit),
        run_id: Some(
            flags
                .get("--run-id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| env("RUN_ID", &unix_time().to_string())),
        ),
    };
    let mut fault = None;
    let campaign = (|| -> io::Result<()> {
        let setup = setup::prepare(&home, &source)?;
        let goal = include_str!("../../../network-egress/goal.md");
        creds::fetch(&home, &env("AWS_REGION", "us-west-2"))?;
        shutdown::check()?;
        let oracle = oracle::Oracle::start(&run_dir)?;
        let agent = agent_a::run(&run_dir, &setup, goal, &run.platform);
        let stopped = oracle.stop();
        let exit = agent.as_ref().copied().unwrap_or(1);
        let turns = fs::read_to_string(run_dir.join("agent-a/turns.jsonl"))?;
        let transcript = stream::Transcript::parse(&turns);
        let validity = validity::assess(
            &transcript,
            &validity::Exit {
                log: &fs::read_to_string(run_dir.join("agent-a.log")).unwrap_or_default(),
                code: exit,
                error: agent.as_ref().err().map(ToString::to_string),
            },
        );
        validity.write(&run_dir.join("agent-a"))?;
        let report = transcript.report;
        fs::write(
            run_dir.join("agent-a/coverage.md"),
            coverage::render(goal, report.as_deref().unwrap_or("")),
        )?;
        fs::write(
            run_dir.join("agent-a/method_report.md"),
            report.unwrap_or_else(|| validity.fallback_report(exit)),
        )?;
        agent?;
        stopped?;
        Ok(())
    })();
    if let Err(error) = campaign {
        eprintln!("harness failure: {error}");
        fault = Some(error.to_string());
        fs::write(run_dir.join("agent-a/run_status.txt"), "INVALID\n")?;
        fs::write(run_dir.join("agent-a/first_error.txt"), error.to_string())?;
    }
    let finding = verdict(&run, &load(&run_dir));
    let body = serde_json::to_vec_pretty(&finding)?;
    for file in ["finding.json", "verdict.json"] {
        fs::write(run_dir.join(file), &body)?;
    }
    println!(
        "jailbreak: {} {:?}, run_status={}",
        finding.verdict.as_str(),
        finding.security_outcome,
        finding.run_status.as_deref().unwrap_or("INVALID")
    );
    let bucket = env("LEDGER_BUCKET", "");
    if !bucket.is_empty() {
        upload::upload(&run_dir, &run, &bucket)?;
    }
    Ok(
        if fault.is_none() && matches!(finding.verdict, Verdict::Pass) {
            0
        } else {
            1
        },
    )
}
