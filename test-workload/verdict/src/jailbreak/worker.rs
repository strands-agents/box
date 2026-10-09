//! Internal subcommands. The harness re-executes its own binary for children that
//! must start in a controlled way, and this module both builds and parses their
//! arguments so the two sides cannot drift.

use super::{Flags, agent_a, oracle, shutdown};
use std::{io, net::IpAddr, path::PathBuf, process::Command, thread, time::Duration};

#[derive(Debug, PartialEq)]
pub(super) enum Worker {
    /// Waits for a launch token on stdin, then execs the box, so the harness can
    /// register the PID as an oracle root before the box runs anything.
    Agent {
        config: PathBuf,
        workspace: PathBuf,
        prompt: String,
    },
    /// Opens the positive-control connection the oracle must observe.
    Control {
        target: IpAddr,
        port: u16,
        timeout: Duration,
        state: PathBuf,
    },
    /// Hosts an oracle until SIGINT or SIGTERM, so tests can drive its signal handling.
    Oracle { run_dir: PathBuf },
}

impl Worker {
    /// The command that runs this worker in a child process.
    pub(super) fn command(&self) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("jailbreak");
        match self {
            Self::Agent {
                config,
                workspace,
                prompt,
            } => command
                .args(["agent-worker", "--config"])
                .arg(config)
                .arg("--workspace")
                .arg(workspace)
                .args(["--prompt", prompt]),
            Self::Control {
                target,
                port,
                timeout,
                state,
            } => command
                .args(["control-worker", "--target", &target.to_string()])
                .args(["--port", &port.to_string()])
                .args(["--timeout", &timeout.as_secs_f64().to_string()])
                .arg("--state")
                .arg(state),
            Self::Oracle { run_dir } => command.args(["oracle-worker", "--run-dir"]).arg(run_dir),
        };
        Ok(command)
    }

    /// Parse a worker invocation, or `None` when `action` names no worker.
    pub(super) fn parse(action: &str, args: &[String]) -> io::Result<Option<Self>> {
        Ok(Some(match action {
            "agent-worker" => {
                let flags = Flags::parse(args, &["--config", "--workspace", "--prompt"])?;
                Self::Agent {
                    config: flags.required("--config")?.into(),
                    workspace: flags.required("--workspace")?.into(),
                    prompt: flags.required("--prompt")?.into(),
                }
            }
            "control-worker" => {
                let flags = Flags::parse(args, &["--target", "--port", "--timeout", "--state"])?;
                let seconds: f64 = flags
                    .required("--timeout")?
                    .parse()
                    .map_err(io::Error::other)?;
                if !seconds.is_finite() || seconds <= 0.0 || seconds > 120.0 {
                    return Err(io::Error::other("invalid timeout"));
                }
                Self::Control {
                    target: flags
                        .required("--target")?
                        .parse()
                        .map_err(io::Error::other)?,
                    port: flags
                        .required("--port")?
                        .parse()
                        .map_err(io::Error::other)?,
                    timeout: Duration::from_secs_f64(seconds),
                    state: flags.required("--state")?.into(),
                }
            }
            "oracle-worker" => Self::Oracle {
                run_dir: Flags::parse(args, &["--run-dir"])?
                    .required("--run-dir")?
                    .into(),
            },
            _ => return Ok(None),
        }))
    }

    pub(super) fn run(self) -> io::Result<()> {
        match self {
            Self::Agent {
                config,
                workspace,
                prompt,
            } => agent_a::worker(&config, &workspace, &prompt),
            Self::Control {
                target,
                port,
                timeout,
                state,
            } => oracle::control_worker(target, port, timeout, &state),
            Self::Oracle { run_dir } => {
                shutdown::install()?;
                let _oracle = oracle::Oracle::start(&run_dir)?;
                loop {
                    shutdown::check()?;
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        for worker in [
            Worker::Agent {
                config: "/ws/.strands-box/box.toml".into(),
                workspace: "/ws".into(),
                prompt: "--goal with spaces\nand lines".into(),
            },
            Worker::Control {
                target: "169.254.255.254".parse().unwrap(),
                port: 80,
                timeout: Duration::from_millis(12_500),
                state: "/run/oracle/control-state".into(),
            },
            Worker::Oracle {
                run_dir: "/run".into(),
            },
        ] {
            let args: Vec<String> = worker
                .command()
                .unwrap()
                .get_args()
                .map(|a| a.to_str().unwrap().to_owned())
                .collect();
            assert_eq!(args[0], "jailbreak");
            assert_eq!(Worker::parse(&args[1], &args[2..]).unwrap(), Some(worker));
        }
        assert_eq!(Worker::parse("run", &[]).unwrap(), None);
    }
}
