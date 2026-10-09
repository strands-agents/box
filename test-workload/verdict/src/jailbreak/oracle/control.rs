use super::super::{
    process::{self, Owned},
    worker::Worker,
};
use super::{sample, sockets::FORBIDDEN};
use std::{
    fs, io,
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq)]
pub(super) enum Outcome {
    Detected(String),
    Unreachable(String),
    Missed,
}

pub(super) fn run(dir: &Path, interval: Duration) -> io::Result<Outcome> {
    let target =
        std::env::var("ORACLE_CONTROL_TARGET").unwrap_or_else(|_| "169.254.255.254".into());
    let address: IpAddr = target.parse().map_err(io::Error::other)?;
    if !FORBIDDEN.contains(address)
        || address == "169.254.169.254".parse::<IpAddr>().expect("metadata IP")
    {
        return Err(io::Error::other(
            "control sink must be in the forbidden range and must not be IMDS",
        ));
    }
    let port = std::env::var("ORACLE_CONTROL_PORT")
        .map_or(Ok(80), |p| p.parse().map_err(io::Error::other))?;
    let timeout = super::seconds("ORACLE_CONTROL_TIMEOUT", 12.0)?;
    let state = dir.join("control-state");
    fs::write(&state, "pending")?;
    let worker = Worker::Control {
        target: address,
        port,
        timeout,
        state: state.clone(),
    };
    let child = Owned::spawn(
        worker
            .command()?
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )?;
    observe(dir, child, interval, timeout, sample)
}

fn observe(
    dir: &Path,
    child: Owned,
    interval: Duration,
    timeout: Duration,
    mut sample: impl FnMut(&[u32]) -> io::Result<Vec<super::sockets::Socket>>,
) -> io::Result<Outcome> {
    let state = dir.join("control-state");
    let roots = [child.id()];
    fs::write(dir.join("control-roots"), format!("{}\n", roots[0]))?;
    let deadline = Instant::now() + timeout;
    let settled = process::wait_until(deadline, interval, || {
        if let Some(hit) = sample(&roots)?.into_iter().next() {
            return Ok(Some(Outcome::Detected(format!(
                "{} pid={} peer={} state={}",
                hit.command, hit.pid, hit.peer, hit.state
            ))));
        }
        let current = fs::read_to_string(&state)?;
        Ok(current
            .starts_with("unreachable")
            .then_some(Outcome::Unreachable(current)))
    })?;
    drop(child);
    Ok(match settled {
        Some(outcome) => outcome,
        None => match fs::read_to_string(&state)? {
            opened if opened == "opened" => Outcome::Missed,
            current => Outcome::Unreachable(current),
        },
    })
}

pub(super) fn connect(
    target: IpAddr,
    port: u16,
    timeout: Duration,
    state: &Path,
) -> io::Result<()> {
    let addr = SocketAddr::new(target, port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_stream) => {
            fs::write(state, "opened")?;
            thread::sleep(timeout);
        }
        Err(error) => {
            fs::write(state, format!("unreachable: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    #[test]
    fn own_roots_and_reaped() {
        let dir = std::env::temp_dir().join(format!("jailbreak-control-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("subtree-roots"), "").unwrap();
        fs::write(dir.join("control-state"), "pending").unwrap();
        let child = Owned::spawn(Command::new("sleep").arg("30")).unwrap();
        let pid = child.id();
        let result = observe(
            &dir,
            child,
            Duration::from_millis(1),
            Duration::from_secs(1),
            |roots| {
                assert_eq!(roots, &[pid]);
                Ok(vec![super::super::sockets::Socket {
                    command: "unnamed".into(),
                    pid,
                    peer: "169.254.1.2:80".into(),
                    state: "SYN_SENT".into(),
                }])
            },
        )
        .unwrap();
        assert!(matches!(result, Outcome::Detected(_)));
        assert_eq!(
            fs::read_to_string(dir.join("control-roots")).unwrap(),
            format!("{pid}\n")
        );
        assert_eq!(fs::read_to_string(dir.join("subtree-roots")).unwrap(), "");
        assert!(
            !Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
