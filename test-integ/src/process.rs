//! Concurrent workload execution and output capture.

use super::{BoxFixture, Command, Route, RunResult, count_launch, native};

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

struct WorkloadChild(std::process::Child);

impl std::ops::Deref for WorkloadChild {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for WorkloadChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl WorkloadChild {
    fn stop(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if let Some(status) = self.0.try_wait()? {
            return Ok(status);
        }
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &self.0.id().to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = self.0.kill();
        self.0.wait()
    }
}

impl Drop for WorkloadChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl BoxFixture {
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
        self.restore_command_after(|| self.spawn_meanwhile(cmd, &[], meanwhile))
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
        self.restore_command_after(|| self.spawn_meanwhile(cmd, env, meanwhile))
    }

    fn restore_command_after<F: FnOnce() -> RunResult>(&self, run: F) -> RunResult {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        self.write_command("bash");
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn spawn_meanwhile<F: FnOnce()>(
        &self,
        cmd: &str,
        env: &[(&str, &str)],
        meanwhile: F,
    ) -> RunResult {
        self.spawn_meanwhile_with_timeouts(
            cmd,
            env,
            meanwhile,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(45),
        )
    }

    fn spawn_meanwhile_with_timeouts<F: FnOnce()>(
        &self,
        cmd: &str,
        env: &[(&str, &str)],
        meanwhile: F,
        ready_timeout: std::time::Duration,
        exit_timeout: std::time::Duration,
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
            Ok(child) => WorkloadChild(child),
            Err(e) => {
                return RunResult::bare(format!("strands-box spawn error: {e}"), -1);
            }
        };
        // Drain both pipes on their own threads from the start. The box writes its startup
        // disclosures before the workload runs; left undrained past the pipe buffer, that write
        // would block the box before it ever touched the ready marker.
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        let deadline = std::time::Instant::now() + ready_timeout;
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
        // deadline, stop the box so its own teardown can close the workload's pipes.
        let mut hung = false;
        let status = match exited_early {
            Some(status) => Ok(status),
            None => {
                let deadline = std::time::Instant::now() + exit_timeout;
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break Ok(status),
                        Ok(None) if std::time::Instant::now() >= deadline => {
                            hung = true;
                            break child.stop();
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
                    format!(
                        "box did not exit within {exit_timeout:?} (stopped; likely a teardown hang): {out}"
                    )
                } else {
                    out
                },
                rc: if hung {
                    -1
                } else {
                    status.code().unwrap_or(-1)
                },
                decisions,
                route: Route::Native,
            },
            Err(e) => RunResult::bare(format!("strands-box wait error: {e}"), -1),
        }
    }
}

#[cfg(test)]
mod tests;
