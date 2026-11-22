//! A contained process that checks asynchronous storage admission through the normal Box launcher.

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("box-storage-probe: unsupported platform; this probe requires Linux");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match linux::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("box-storage-probe: {reason}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    const BOUND: Duration = Duration::from_secs(25);
    const FAILURE_BOUND: Duration = Duration::from_secs(60);
    const STEP: Duration = Duration::from_millis(2);
    const PUBLIC: [&[u8]; 2] = [b"captured-first", b"captured-second"];
    const NAMES: [&str; 2] = ["first", "second"];
    const IMMUTABLE: &[u8] = b"readable but immutable";

    fn require(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
        if condition { Ok(()) } else { Err(message()) }
    }

    fn read_expected(path: &Path, expected: &[u8]) -> Result<(), String> {
        let actual = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
        require(actual == expected, || {
            format!("wrong bytes at {}: {actual:?}", path.display())
        })
    }

    fn denied(path: &Path) -> Result<(), String> {
        match fs::read(path) {
            Err(_) => Ok(()),
            Ok(bytes) => Err(format!(
                "denied path became readable: {} ({} bytes)",
                path.display(),
                bytes.len()
            )),
        }
    }

    fn denial_pass(roots: &[PathBuf; 2]) -> Result<(), String> {
        for (index, root) in roots.iter().enumerate() {
            denied(&root.join("secret/token"))?;
            denied(&root.join("underlay-marker"))?;
            if let Ok(bytes) = fs::read(root.join("public")) {
                require(bytes == PUBLIC[index], || {
                    format!("wrong public bytes at {}: {bytes:?}", root.display())
                })?;
            }
        }
        Ok(())
    }

    fn pending(root: &Path) -> Result<(), String> {
        for relative in [
            "public",
            "secret/token",
            "underlay-marker",
            "writable/frozen/existing",
            "run-true",
        ] {
            denied(&root.join(relative))?;
        }
        match fs::read_dir(root) {
            Ok(mut entries) => require(entries.next().is_none(), || {
                format!("pending root exposes directory entries: {}", root.display())
            })?,
            Err(error) => require(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                ),
                || {
                    format!(
                        "unexpected pending-directory error at {}: {error}",
                        root.display()
                    )
                },
            )?,
        }
        require(
            fs::write(root.join("writable/created"), b"forbidden while pending").is_err(),
            || format!("pending root permits writes: {}", root.display()),
        )
    }

    fn marker(output: &Path, name: &str, value: &Value) -> Result<(), String> {
        let final_path = output.join(name);
        let temporary = output.join(format!(".{name}.pending-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create marker {}: {error}", temporary.display()))?;
        let bytes =
            serde_json::to_vec(value).map_err(|error| format!("encode marker {name}: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write marker {name}: {error}"))?;
        drop(file);
        fs::rename(&temporary, &final_path)
            .map_err(|error| format!("publish marker {name}: {error}"))
    }

    fn capability_evidence(path: &str) -> Result<Value, String> {
        let status = match fs::read_to_string(path) {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                ) =>
            {
                return Ok(json!({"checked": false, "reason": error.to_string()}));
            }
            Err(error) => return Err(format!("read {path}: {error}")),
        };
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let value = status
                .lines()
                .find(|line| line.starts_with(field))
                .and_then(|line| line.split_whitespace().nth(1))
                .ok_or_else(|| format!("{path} is missing {field}"))?;
            let value = u64::from_str_radix(value, 16)
                .map_err(|error| format!("parse {field} in {path}: {error}"))?;
            require(value == 0, || format!("{path} retains {field} {value:#x}"))?;
        }
        let no_new_privs = status
            .lines()
            .find(|line| line.starts_with("NoNewPrivs:"))
            .and_then(|line| line.split_whitespace().nth(1));
        require(no_new_privs == Some("1"), || {
            format!("{path} does not have NoNewPrivs=1")
        })?;
        Ok(json!({"checked": true, "zero": true, "no_new_privs": true}))
    }

    fn positive_exec(path: &Path, deadline: Instant) -> Result<(), String> {
        let mut child = Command::new(path)
            .spawn()
            .map_err(|error| format!("positive execution {}: {error}", path.display()))?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return require(status.success(), || {
                        format!("positive execution {} exited {status}", path.display())
                    });
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(STEP),
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "positive execution {} did not finish within the fixture bound: {result:?}",
                        path.display()
                    ));
                }
            }
        }
    }

    fn noexec(root: &Path) -> Result<(), String> {
        let path = root.join("run-true");
        let bytes = fs::read(&path)
            .map_err(|error| format!("read noexec binary {}: {error}", path.display()))?;
        require(bytes.starts_with(b"\x7fELF"), || {
            format!(
                "noexec control is not an ELF executable: {}",
                path.display()
            )
        })?;
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("stat noexec binary {}: {error}", path.display()))?;
        require(metadata.permissions().mode() & 0o111 != 0, || {
            format!(
                "noexec control lacks executable mode bits: {}",
                path.display()
            )
        })?;
        match Command::new(&path).spawn() {
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(()),
            Err(error) => Err(format!(
                "noexec control {} failed for the wrong reason: {error}",
                path.display()
            )),
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(format!(
                    "storage binary executed without an exec grant: {}",
                    path.display()
                ))
            }
        }
    }

    fn admitted(root: &Path, index: usize) -> Result<(), String> {
        let public = root.join("public");
        read_expected(&public, PUBLIC[index])?;
        require(
            fs::write(&public, b"forbidden public overwrite").is_err(),
            || format!("public file is writable: {}", public.display()),
        )?;
        read_expected(&public, PUBLIC[index])?;
        denied(&root.join("secret/token"))?;
        denied(&root.join("underlay-marker"))?;
        let writable = root.join("writable/created");
        fs::write(&writable, b"allowed storage write")
            .map_err(|error| format!("allowed write {}: {error}", writable.display()))?;
        read_expected(&writable, b"allowed storage write")?;
        let immutable = root.join("writable/frozen/existing");
        read_expected(&immutable, IMMUTABLE)?;
        require(
            fs::write(&immutable, b"forbidden frozen overwrite").is_err(),
            || format!("deny_write permits overwrite: {}", immutable.display()),
        )?;
        require(
            fs::write(
                root.join("writable/frozen/new"),
                b"forbidden frozen creation",
            )
            .is_err(),
            || {
                format!(
                    "deny_write permits creation below {}",
                    root.join("writable/frozen").display()
                )
            },
        )?;
        read_expected(&immutable, IMMUTABLE)?;
        noexec(root)
    }

    struct Watcher {
        stop: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
        checks: Arc<AtomicU64>,
        thread: Option<thread::JoinHandle<Result<(), String>>>,
    }

    impl Watcher {
        fn start(roots: [PathBuf; 2], deadline: Instant) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let failed = Arc::new(AtomicBool::new(false));
            let checks = Arc::new(AtomicU64::new(0));
            let worker_stop = Arc::clone(&stop);
            let worker_failed = Arc::clone(&failed);
            let worker_checks = Arc::clone(&checks);
            let thread = thread::spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    let result = denial_pass(&roots).and_then(|()| {
                        require(Instant::now() < deadline, || {
                            "background denial checks exceeded the fixture bound".into()
                        })
                    });
                    if let Err(reason) = result {
                        worker_failed.store(true, Ordering::Release);
                        return Err(reason);
                    }
                    worker_checks.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(STEP);
                }
                Ok(())
            });
            Self {
                stop,
                failed,
                checks,
                thread: Some(thread),
            }
        }

        fn finish(&mut self) -> Result<(), String> {
            self.stop.store(true, Ordering::Release);
            self.thread
                .take()
                .expect("watcher is joined once")
                .join()
                .map_err(|_| "background denial checker panicked".to_owned())?
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn forbid_publication(output: &Path, roots: &[PathBuf; 2]) -> Result<(), String> {
        for (index, root) in roots.iter().enumerate() {
            if let Ok(bytes) = fs::read(root.join("public")) {
                marker(
                    output,
                    "unexpected-publication",
                    &json!({
                        "root": root, "index": index, "bytes": bytes.len(),
                    }),
                )?;
                return Err(format!(
                    "compile-failure mode exposed public bytes at {} (root {index})",
                    root.display()
                ));
            }
        }
        Ok(())
    }

    fn compile_failure(
        output: &Path,
        roots: &[PathBuf; 2],
        watcher: &Watcher,
        deadline: Instant,
        caps: &Value,
    ) -> Result<(), String> {
        forbid_publication(output, roots)?;
        for root in roots {
            pending(root)?;
        }
        marker(
            output,
            "started",
            &json!({"pending_checked": true, "mode": "compile-failure"}),
        )?;
        let mut checks = 0_u64;
        let mut active = false;
        loop {
            forbid_publication(output, roots)?;
            denial_pass(roots)?;
            require(!watcher.failed.load(Ordering::Acquire), || {
                "background denial checker failed".into()
            })?;
            require(Instant::now() < deadline, || {
                "compile-failure mode exceeded the 60-second fixture bound; Box did not stop the workload".into()
            })?;
            checks += 1;
            let background_checks = watcher.checks.load(Ordering::Relaxed);
            if checks >= 3 && background_checks > 0 && !active {
                marker(
                    output,
                    "probe-active",
                    &json!({
                        "mode": "compile-failure", "checks": checks, "background_checks": background_checks,
                        "caps": caps, "no_new_privs": true, "positive_exec": true,
                        "secret_denied": true, "underlay_denied": true, "public_denied": true,
                    }),
                )?;
                active = true;
            }
            thread::sleep(STEP);
        }
    }

    fn exercise(
        mode: &str,
        output: &Path,
        roots: &[PathBuf; 2],
        positive: &Path,
        watcher: &Watcher,
        deadline: Instant,
    ) -> Result<(), String> {
        let first = match mode {
            "before" | "compile-failure" => None,
            "after-first" => Some(0),
            "after-second" => Some(1),
            _ => return Err(format!("unknown mode {mode}")),
        };
        // SAFETY: PR_GET_NO_NEW_PRIVS reads one process attribute and takes no pointer.
        require(
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
            || "workload does not have NoNewPrivs=1".into(),
        )?;
        let caps = json!({"self": capability_evidence("/proc/self/status")?, "pid1": capability_evidence("/proc/1/status")?});
        positive_exec(positive, deadline)?;
        if mode == "compile-failure" {
            return compile_failure(output, roots, watcher, deadline, &caps);
        }
        if first.is_some() {
            for root in roots {
                pending(root)?;
            }
        }
        marker(
            output,
            "started",
            &json!({"pending_checked": first.is_some()}),
        )?;
        let mut complete = [false; 2];
        let mut independent = false;
        let mut published_pass = false;
        let mut checks = 0_u64;
        loop {
            require(Instant::now() < deadline, || {
                format!(
                    "mode {mode} exceeded the 25-second fixture bound; admitted={complete:?}, passed={published_pass}"
                )
            })?;
            require(!watcher.failed.load(Ordering::Acquire), || {
                "background denial checker failed".into()
            })?;
            denial_pass(roots)?;
            checks += 1;
            for index in 0..2 {
                if complete[index] {
                    read_expected(&roots[index].join("public"), PUBLIC[index])?;
                    continue;
                }
                let Ok(bytes) = fs::read(roots[index].join("public")) else {
                    continue;
                };
                require(bytes == PUBLIC[index], || {
                    format!(
                        "wrong public bytes at {}: {bytes:?}",
                        roots[index].display()
                    )
                })?;
                if let Some(first) = first {
                    require(index == first || independent, || {
                        format!(
                            "{} root arrived before the required independent {} admission",
                            NAMES[index], NAMES[first]
                        )
                    })?;
                }
                admitted(&roots[index], index)?;
                complete[index] = true;
                if first == Some(index) && !independent {
                    pending(&roots[1 - index])?;
                    marker(
                        output,
                        &format!("admitted-{}", NAMES[index]),
                        &json!({"protected": true}),
                    )?;
                    marker(
                        output,
                        &format!("independent-{}", NAMES[index]),
                        &json!({"other_pending": true}),
                    )?;
                    independent = true;
                } else {
                    marker(
                        output,
                        &format!("admitted-{}", NAMES[index]),
                        &json!({"protected": true}),
                    )?;
                }
            }
            if complete == [true, true]
                && !published_pass
                && watcher.checks.load(Ordering::Relaxed) > 0
            {
                marker(
                    output,
                    "passed",
                    &json!({
                        "status": "passed", "mode": mode, "checks": checks,
                        "background_checks": watcher.checks.load(Ordering::Relaxed),
                        "caps": caps, "no_new_privs": true, "positive_exec": true,
                        "noexec": [true, true], "read_only_public": [true, true],
                        "allowed_write": [true, true], "deny_write": [true, true],
                        "secret_denied": true, "underlay_denied": true,
                        "independent": independent,
                    }),
                )?;
                published_pass = true;
            }
            if output.join("finish").exists() {
                require(published_pass, || {
                    "finish arrived before both protected admissions passed".into()
                })?;
                denial_pass(roots)?;
                return Ok(());
            }
            thread::sleep(STEP);
        }
    }

    mod roles {
        use super::{STEP, capability_evidence, marker, require};
        use serde_json::{Value, json};
        use std::fs;
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::path::{Path, PathBuf};
        use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        const NAMES: [&str; 3] = ["agent", "tool", "server"];

        #[derive(Clone)]
        struct Role {
            name: &'static str,
            output: PathBuf,
            root: PathBuf,
            incarnation: String,
            deadline: Instant,
            fixture_deadline_unix_ms: u64,
            expect_failure: bool,
        }

        impl Role {
            fn start(
                name: &'static str,
                output: &Path,
                root: &Path,
                expect_failure: bool,
            ) -> Result<Self, String> {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| format!("read fixture clock: {error}"))?;
                let role = Self {
                    name,
                    output: output.to_path_buf(),
                    root: root.to_path_buf(),
                    incarnation: format!("{name}-{}-{}", std::process::id(), now.as_nanos()),
                    deadline: Instant::now() + Duration::from_secs(45),
                    fixture_deadline_unix_ms: u64::try_from(now.as_millis() + 45_000)
                        .map_err(|error| format!("encode fixture deadline: {error}"))?,
                    expect_failure,
                };
                for _ in 0..3 {
                    for other in NAMES {
                        read_denied(&root.join(other).join("value"))?;
                        write_denied(&root.join(other).join(format!("pending-by-{name}")))?;
                    }
                    read_denied(&root.join("underlay-marker"))?;
                    thread::sleep(STEP);
                }
                marker(
                    &output.join(name),
                    "pending",
                    &json!({
                        "role": name, "incarnation": role.incarnation,
                        "pending_checks": 3, "caps": checked_capabilities()?,
                        "fixture_deadline_unix_ms":role.fixture_deadline_unix_ms,
                    }),
                )?;
                role.state("pending", json!({}))?;
                Ok(role)
            }

            fn state(&self, phase: &str, detail: Value) -> Result<(), String> {
                marker(
                    &self.output.join(self.name),
                    "state",
                    &json!({
                        "role":self.name, "incarnation":self.incarnation,
                        "phase":phase, "detail":detail,
                    }),
                )
            }

            fn check_deadline(&self) -> Result<(), String> {
                require(Instant::now() < self.deadline, || {
                    format!("{} storage-role fixture exceeded its deadline", self.name)
                })
            }

            fn cross_role_reads(&self) -> Result<(), String> {
                read_denied(&self.root.join("underlay-marker"))?;
                read_denied(&self.root.join("required-secret/token"))?;
                for other in NAMES.into_iter().filter(|other| *other != self.name) {
                    read_denied(&self.root.join(other).join("value"))?;
                }
                Ok(())
            }

            fn cross_role_denials(&self) -> Result<(), String> {
                self.cross_role_reads()?;
                for other in NAMES.into_iter().filter(|other| *other != self.name) {
                    write_denied(
                        &self
                            .root
                            .join(other)
                            .join(format!("denied-from-{}", self.name)),
                    )?;
                }
                Ok(())
            }

            fn failure_sample(&self) -> Result<(), String> {
                for target in NAMES
                    .into_iter()
                    .map(|name| self.root.join(name).join("value"))
                    .chain(std::iter::once(self.root.join("underlay-marker")))
                {
                    match fs::read(&target) {
                        Ok(_) => {
                            marker(
                                &self.output.join(self.name),
                                "unexpected-publication",
                                &json!({
                                    "role":self.name, "incarnation":self.incarnation,
                                    "path":target, "readable":true,
                                }),
                            )?;
                            return Err(format!(
                                "{} read storage during failed admission: {}",
                                self.name,
                                target.display()
                            ));
                        }
                        Err(error) if expected_denial(&error) => {}
                        Err(error) => {
                            return Err(format!(
                                "unexpected failed-admission read at {}: {error}",
                                target.display()
                            ));
                        }
                    }
                }
                Ok(())
            }

            fn wait_for_failed_admission(
                &self,
                monitor: Option<&ReadMonitor>,
            ) -> Result<(), String> {
                self.state("sampling-failed-admission", json!({}))?;
                let mut checks = 0_u64;
                loop {
                    self.check_deadline()?;
                    self.failure_sample()?;
                    if let Some(monitor) = monitor {
                        monitor.check()?;
                    }
                    checks += 1;
                    if checks == 3 {
                        marker(
                            &self.output.join(self.name),
                            "active",
                            &json!({
                                "role":self.name, "incarnation":self.incarnation,
                                "checks":checks, "caps":checked_capabilities()?,
                            }),
                        )?;
                    }
                    thread::sleep(STEP);
                }
            }

            fn admit(&self, monitor: Option<&ReadMonitor>) -> Result<Value, String> {
                if self.expect_failure {
                    self.wait_for_failed_admission(monitor)?;
                    return Err("failed-admission probe unexpectedly returned".into());
                }
                let own = self.root.join(self.name);
                let expected = format!("captured-{}", self.name);
                self.state("waiting-own-storage", json!({}))?;
                let mut next_diagnostic = Instant::now();
                loop {
                    self.check_deadline()?;
                    self.cross_role_denials()?;
                    if let Some(monitor) = monitor {
                        monitor.check()?;
                    }
                    match fs::read(own.join("value")) {
                        Ok(bytes) => {
                            require(bytes == expected.as_bytes(), || {
                                format!(
                                    "{} read unexpected provider or underlay bytes: {bytes:?}",
                                    self.name
                                )
                            })?;
                            break;
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                            ) =>
                        {
                            if Instant::now() >= next_diagnostic {
                                self.state(
                                    "waiting-own-storage",
                                    json!({
                                        "error":error.to_string(), "errno":error.raw_os_error(),
                                        "monitor_checks":monitor.map(ReadMonitor::checks),
                                    }),
                                )?;
                                next_diagnostic = Instant::now() + Duration::from_secs(2);
                            }
                        }
                        Err(error) => {
                            return Err(format!("{} read own storage: {error}", self.name));
                        }
                    }
                    thread::sleep(STEP);
                }
                self.state("checking-own-write", json!({}))?;
                let written = format!("written-by-{}", self.name);
                fs::write(own.join("created"), &written)
                    .map_err(|error| format!("{} write own storage: {error}", self.name))?;
                require(
                    fs::read(own.join("created")).map_err(|error| error.to_string())?
                        == written.as_bytes(),
                    || format!("{} cannot read back its permitted write", self.name),
                )?;
                self.cross_role_denials()?;
                if let Some(monitor) = monitor {
                    // Require a successful monitor pass after this process observed publication.
                    let previous = monitor.checks();
                    while monitor.checks() == previous {
                        self.check_deadline()?;
                        monitor.check()?;
                        thread::sleep(STEP);
                    }
                    monitor.check()?;
                }
                let denials: serde_json::Map<String, Value> = NAMES
                    .into_iter()
                    .filter(|other| *other != self.name)
                    .map(|other| (other.to_string(), json!({"read": true, "write": true})))
                    .collect();
                let receipt = json!({
                    "role": self.name, "incarnation": self.incarnation,
                    "read": true, "write": true, "denied": denials,
                    "caps": checked_capabilities()?,
                    "background_checks": monitor.map_or(0, ReadMonitor::checks),
                });
                marker(&self.output.join(self.name), "passed", &receipt)?;
                self.state("permissions-passed", json!({}))?;
                Ok(receipt)
            }

            fn hold_until_finish(&self) -> Result<(), String> {
                self.state("holding-until-finish", json!({}))?;
                while !self.output.join("finish").exists() {
                    self.check_deadline()?;
                    self.cross_role_denials()?;
                    thread::sleep(STEP);
                }
                self.cross_role_denials()
            }
        }

        fn expected_denial(error: &std::io::Error) -> bool {
            matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EPERM | libc::ENOENT)
            )
        }

        fn read_denied(path: &Path) -> Result<(), String> {
            match fs::read(path) {
                Err(error) if expected_denial(&error) => Ok(()),
                Err(error) => Err(format!(
                    "unexpected denied-read error at {}: {error}",
                    path.display()
                )),
                Ok(_) => Err(format!("forbidden read succeeded at {}", path.display())),
            }
        }

        fn checked_capabilities() -> Result<Value, String> {
            let caps = capability_evidence("/proc/self/status")?;
            require(
                caps["checked"] == true && caps["zero"] == true && caps["no_new_privs"] == true,
                || format!("role capability evidence was unavailable or nonzero: {caps}"),
            )?;
            Ok(caps)
        }

        struct ReadMonitor {
            stop: Arc<AtomicBool>,
            checks: Arc<AtomicU64>,
            failure: Arc<Mutex<Option<String>>>,
            worker: Option<thread::JoinHandle<()>>,
        }

        impl ReadMonitor {
            fn start(role: &Role) -> Self {
                let stop = Arc::new(AtomicBool::new(false));
                let checks = Arc::new(AtomicU64::new(0));
                let failure = Arc::new(Mutex::new(None));
                let worker_stop = Arc::clone(&stop);
                let worker_checks = Arc::clone(&checks);
                let worker_failure = Arc::clone(&failure);
                let role = role.clone();
                let worker = thread::spawn(move || {
                    while !worker_stop.load(Ordering::Acquire) {
                        let result = if role.expect_failure {
                            role.failure_sample()
                        } else {
                            role.cross_role_reads()
                        };
                        if let Err(reason) = result {
                            let _ = marker(
                                &role.output.join(role.name),
                                "monitor-state",
                                &json!({
                                    "incarnation":role.incarnation, "failure":reason,
                                    "checks":worker_checks.load(Ordering::Acquire),
                                }),
                            );
                            *worker_failure.lock().expect("monitor failure lock") = Some(reason);
                            break;
                        }
                        worker_checks.fetch_add(1, Ordering::Release);
                        thread::sleep(STEP);
                    }
                });
                Self {
                    stop,
                    checks,
                    failure,
                    worker: Some(worker),
                }
            }

            fn checks(&self) -> u64 {
                self.checks.load(Ordering::Acquire)
            }

            fn check(&self) -> Result<(), String> {
                let failure = self
                    .failure
                    .lock()
                    .map_err(|_| "storage read monitor poisoned".to_owned())?;
                match &*failure {
                    Some(reason) => Err(reason.clone()),
                    None => Ok(()),
                }
            }

            fn started(&self, role: &Role) -> Result<(), String> {
                while self.checks() < 3 {
                    role.check_deadline()?;
                    self.check()?;
                    thread::sleep(STEP);
                }
                self.check()?;
                marker(
                    &role.output.join(role.name),
                    "monitoring",
                    &json!({
                        "role":role.name, "incarnation":role.incarnation, "checks":self.checks(),
                    }),
                )
            }

            fn finish(&mut self) -> Result<(), String> {
                self.stop.store(true, Ordering::Release);
                if let Some(worker) = self.worker.take() {
                    worker
                        .join()
                        .map_err(|_| "storage read monitor panicked".to_owned())?;
                }
                self.check()
            }
        }

        impl Drop for ReadMonitor {
            fn drop(&mut self) {
                let _ = self.finish();
            }
        }

        fn write_denied(path: &Path) -> Result<(), String> {
            match fs::write(path, b"forbidden cross-role or pending write") {
                Err(error)
                    if expected_denial(&error) || error.raw_os_error() == Some(libc::EROFS) =>
                {
                    Ok(())
                }
                Err(error) => Err(format!(
                    "unexpected denied-write error at {}: {error}",
                    path.display()
                )),
                Ok(()) => Err(format!("forbidden write succeeded at {}", path.display())),
            }
        }

        struct ServerClient {
            child: Child,
            input: ChildStdin,
            output: BufReader<ChildStdout>,
        }

        impl ServerClient {
            fn start(output: &Path, root: &Path, expect_failure: bool) -> Result<Self, String> {
                // Resolve the configured local-server alias from Box's injected PATH.
                let mut child = Command::new("storage-server")
                    .arg(if expect_failure {
                        "role-server-failure"
                    } else {
                        "role-server"
                    })
                    .arg(output)
                    .arg(root)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|error| format!("start configured local MCP alias: {error}"))?;
                let input = child.stdin.take().ok_or("missing MCP client input")?;
                let output =
                    BufReader::new(child.stdout.take().ok_or("missing MCP client output")?);
                let mut client = Self {
                    child,
                    input,
                    output,
                };
                client.request(
                    1,
                    "initialize",
                    json!({
                        "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "storage-role-probe", "version": "1"},
                    }),
                )?;
                client.send(&json!({"jsonrpc":"2.0", "method":"notifications/initialized"}))?;
                let listed = client.request(2, "tools/list", json!({}))?;
                require(
                    listed["tools"].as_array().is_some_and(|tools| {
                        ["storage_check", "storage_finish"]
                            .into_iter()
                            .all(|name| tools.iter().any(|tool| tool["name"] == name))
                    }),
                    || format!("storage tools missing from local MCP discovery: {listed}"),
                )?;
                Ok(client)
            }

            fn send(&mut self, value: &Value) -> Result<(), String> {
                writeln!(self.input, "{value}")
                    .map_err(|error| format!("write local MCP request: {error}"))?;
                self.input
                    .flush()
                    .map_err(|error| format!("flush local MCP request: {error}"))
            }

            fn request(&mut self, id: u64, method: &str, params: Value) -> Result<Value, String> {
                self.send(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))?;
                loop {
                    let mut line = String::new();
                    require(
                        self.output
                            .read_line(&mut line)
                            .map_err(|error| error.to_string())?
                            != 0,
                        || format!("local MCP alias closed before response {id}"),
                    )?;
                    let response: Value =
                        serde_json::from_str(&line).map_err(|error| error.to_string())?;
                    if response["id"] != id {
                        continue;
                    }
                    require(response.get("error").is_none(), || {
                        format!("local MCP {method} failed: {response}")
                    })?;
                    return response
                        .get("result")
                        .cloned()
                        .ok_or_else(|| format!("local MCP response has no result: {response}"));
                }
            }

            fn finish(mut self, checked: &Value) -> Result<(), String> {
                // The MCP alias may close its transport immediately after stdin EOF. Obtain the
                // server's joined-monitor receipt before that close can reap the server.
                let called = self.request(
                    4,
                    "tools/call",
                    json!({"name":"storage_finish", "arguments":{}}),
                )?;
                require(called["isError"] != true, || {
                    format!("local MCP monitor finish failed: {called}")
                })?;
                let text = called["content"][0]["text"]
                    .as_str()
                    .ok_or("local MCP finish receipt has no text")?;
                let joined: Value =
                    serde_json::from_str(text).map_err(|error| error.to_string())?;
                require(
                    joined["joined"] == true
                        && joined["incarnation"] == checked["incarnation"]
                        && joined["checks"].as_u64().is_some_and(|count| {
                            checked["background_checks"]
                                .as_u64()
                                .is_some_and(|previous| count >= previous)
                        }),
                    || format!("local MCP finish did not join the checked monitor: {joined}"),
                )?;
                let Self {
                    mut child,
                    input,
                    output,
                } = self;
                drop(input);
                drop(output);
                require(
                    child.wait().map_err(|error| error.to_string())?.success(),
                    || "configured local MCP alias failed at normal completion".into(),
                )
            }
        }

        fn read_receipt(output: &Path, role: &str, name: &str) -> Result<Value, String> {
            let path = output.join(role).join(name);
            serde_json::from_slice(
                &fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("parse {}: {error}", path.display()))
        }

        fn validate_receipt(role: &str, pending: &Value, passed: &Value) -> Result<(), String> {
            require(
                pending["role"] == role
                    && passed["role"] == role
                    && pending["pending_checks"]
                        .as_u64()
                        .is_some_and(|checks| checks >= 3)
                    && pending["incarnation"].is_string()
                    && pending["incarnation"] == passed["incarnation"]
                    && passed["read"] == true
                    && passed["write"] == true
                    && pending["caps"]["checked"] == true
                    && pending["caps"]["zero"] == true
                    && pending["caps"]["no_new_privs"] == true
                    && passed["caps"]["checked"] == true
                    && passed["caps"]["zero"] == true
                    && passed["caps"]["no_new_privs"] == true,
                || {
                    format!(
                        "{role} did not retain its pending process and permitted access: {pending}; {passed}"
                    )
                },
            )?;
            for other in NAMES.into_iter().filter(|other| *other != role) {
                require(
                    passed["denied"][other]["read"] == true
                        && passed["denied"][other]["write"] == true,
                    || format!("{role} did not deny {other} storage: {passed}"),
                )?;
            }
            Ok(())
        }

        fn agent(output: &Path, root: &Path, expect_failure: bool) -> Result<(), String> {
            let role = Role::start("agent", output, root, expect_failure)?;
            role.state("starting-local-mcp", json!({}))?;
            let mut server = ServerClient::start(output, root, expect_failure)?;
            role.state("starting-tool", json!({}))?;
            let server_pending = read_receipt(output, "server", "pending")?;
            // The hosted shell routes this configured command to a tool process with its own grants.
            let mut tool = Command::new("zsh")
                .args([
                    "-c",
                    &format!(
                        "storage-tool {} '{}' '{}'",
                        if expect_failure {
                            "role-tool-failure"
                        } else {
                            "role-tool"
                        },
                        output.display(),
                        root.display()
                    ),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|error| format!("start configured tool through hosted shell: {error}"))?;
            role.state("waiting-tool-pending", json!({}))?;
            while !output.join("tool/pending").exists() {
                role.check_deadline()?;
                require(
                    tool.try_wait()
                        .map_err(|error| error.to_string())?
                        .is_none(),
                    || "tool exited before pending proof".into(),
                )?;
                thread::sleep(STEP);
            }
            require(
                server
                    .child
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_none(),
                || "local MCP alias exited before pending proof".into(),
            )?;
            require(
                tool.try_wait()
                    .map_err(|error| error.to_string())?
                    .is_none(),
                || "tool exited before pending proof".into(),
            )?;
            marker(
                &output.join("agent"),
                "all-live",
                &json!({
                    "mcp_initialized":true, "mcp_listed":true, "tool_running":true,
                    "agent":role.incarnation, "server":server_pending["incarnation"],
                    "tool":read_receipt(output, "tool", "pending")?["incarnation"],
                }),
            )?;
            if expect_failure {
                server.send(&json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"storage_check", "arguments":{}}}))?;
                return role.wait_for_failed_admission(None);
            }
            let own = role.admit(None)?;
            role.state("waiting-server-storage-check", json!({}))?;
            let called = server.request(
                3,
                "tools/call",
                json!({"name":"storage_check", "arguments":{}}),
            )?;
            require(called["isError"] != true, || {
                format!("local MCP filesystem check failed: {called}")
            })?;
            let text = called["content"][0]["text"]
                .as_str()
                .ok_or("local MCP receipt has no text")?;
            let server_receipt: Value =
                serde_json::from_str(text).map_err(|error| error.to_string())?;
            validate_receipt("server", &server_pending, &server_receipt)?;
            require(
                server_receipt["background_checks"]
                    .as_u64()
                    .is_some_and(|checks| checks >= 3),
                || format!("MCP read monitor has no successful samples: {server_receipt}"),
            )?;
            role.state("waiting-tool-passed", json!({}))?;
            while !output.join("tool/passed").exists() {
                role.check_deadline()?;
                role.cross_role_denials()?;
                require(
                    tool.try_wait()
                        .map_err(|error| error.to_string())?
                        .is_none(),
                    || "tool exited before its permission receipt".into(),
                )?;
                thread::sleep(STEP);
            }
            let tool_pending = read_receipt(output, "tool", "pending")?;
            let tool_receipt = read_receipt(output, "tool", "passed")?;
            validate_receipt("tool", &tool_pending, &tool_receipt)?;
            validate_receipt("agent", &read_receipt(output, "agent", "pending")?, &own)?;
            require(
                server
                    .child
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_none(),
                || "local MCP alias exited before completion signal".into(),
            )?;
            require(
                tool.try_wait()
                    .map_err(|error| error.to_string())?
                    .is_none(),
                || "tool exited before completion signal".into(),
            )?;
            marker(
                &output.join("agent"),
                "all-passed",
                &json!({
                    "status":"passed", "agent":own, "tool":tool_receipt, "server":server_receipt,
                }),
            )?;
            role.hold_until_finish()?;
            server.finish(&server_receipt)?;
            require(
                tool.wait().map_err(|error| error.to_string())?.success(),
                || "configured tool failed at normal completion".into(),
            )
        }

        fn server(output: &Path, root: &Path, expect_failure: bool) -> Result<(), String> {
            let role = Role::start("server", output, root, expect_failure)?;
            let mut monitor = ReadMonitor::start(&role);
            monitor.started(&role)?;
            role.state("waiting-mcp-request", json!({}))?;
            let mut checked = false;
            let mut finished = false;
            for line in std::io::stdin().lock().lines() {
                let request: Value =
                    serde_json::from_str(&line.map_err(|error| error.to_string())?)
                        .map_err(|error| error.to_string())?;
                let Some(id) = request.get("id") else {
                    continue;
                };
                role.state(
                    "processing-mcp-request",
                    json!({
                        "method":request["method"], "id":id, "tool":request["params"]["name"],
                    }),
                )?;
                let result = match request["method"].as_str() {
                    Some("initialize") => {
                        json!({"protocolVersion":"2024-11-05", "capabilities":{"tools":{}}, "serverInfo":{"name":"storage-role-probe", "version":"1"}})
                    }
                    Some("tools/list") => {
                        json!({"tools":[
                            {"name":"storage_check", "description":"Check the local server storage permissions", "inputSchema":{"type":"object", "properties":{}, "additionalProperties":false}},
                            {"name":"storage_finish", "description":"Join the storage monitor after the fixture completes", "inputSchema":{"type":"object", "properties":{}, "additionalProperties":false}},
                        ]})
                    }
                    Some("tools/call") => {
                        require(
                            request["params"]["arguments"]
                                .as_object()
                                .is_some_and(|arguments| arguments.is_empty()),
                            || format!("unexpected local MCP tool arguments: {request}"),
                        )?;
                        let receipt = match request["params"]["name"].as_str() {
                            Some("storage_check") => {
                                require(!checked && !finished, || {
                                    "storage_check may run only once before storage_finish".into()
                                })?;
                                monitor.check()?;
                                let receipt = role.admit(Some(&monitor))?;
                                monitor.check()?;
                                checked = true;
                                receipt
                            }
                            Some("storage_finish") => {
                                require(!expect_failure && checked && !finished, || {
                                    "storage_finish requires one successful storage_check".into()
                                })?;
                                require(output.join("finish").is_file(), || {
                                    "storage_finish arrived before the fixture completion signal"
                                        .into()
                                })?;
                                monitor.finish()?;
                                let receipt = json!({
                                    "incarnation":role.incarnation,
                                    "checks":monitor.checks(), "joined":true,
                                });
                                marker(&output.join("server"), "monitor-joined", &receipt)?;
                                finished = true;
                                receipt
                            }
                            _ => return Err(format!("unexpected local MCP tool call: {request}")),
                        };
                        json!({"content":[{"type":"text", "text":receipt.to_string()}], "isError":false})
                    }
                    _ => return Err(format!("unexpected local MCP request: {request}")),
                };
                let mut stdout = std::io::stdout().lock();
                writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc":"2.0", "id":id, "result":result})
                )
                .map_err(|error| error.to_string())?;
                stdout.flush().map_err(|error| error.to_string())?;
                role.state(
                    "waiting-mcp-request",
                    json!({"last_method":request["method"]}),
                )?;
            }
            role.state("joining-monitor-after-eof", json!({}))?;
            monitor.finish()?;
            require(finished, || {
                "local MCP input closed without a completed storage_finish".into()
            })
        }

        pub(super) fn run(mode: &str, output: &Path, root: &Path) -> Result<(), String> {
            for path in [output, root] {
                require(
                    path.is_absolute() && !path.as_os_str().to_string_lossy().contains('\''),
                    || format!("invalid storage role fixture path: {}", path.display()),
                )?;
            }
            let expect_failure = mode.ends_with("-failure");
            let mode = mode.strip_suffix("-failure").unwrap_or(mode);
            let result = match mode {
                "role-agent" => agent(output, root, expect_failure),
                "role-tool" => (|| {
                    let role = Role::start("tool", output, root, expect_failure)?;
                    role.admit(None)?;
                    role.hold_until_finish()
                })(),
                "role-server" => server(output, root, expect_failure),
                _ => Err(format!("unknown storage role: {mode}")),
            };
            if let Err(reason) = &result {
                let name = mode.strip_prefix("role-").unwrap_or("unknown");
                let _ = marker(
                    &output.join(name),
                    "error",
                    &json!({"mode":mode, "error":reason}),
                );
            }
            result
        }
    }

    fn first_read(root: &Path, missing: &Path) -> Result<(), String> {
        read_expected(&root.join("public"), PUBLIC[0])?;
        denied(&root.join("secret/token"))?;
        require(
            fs::write(root.join("public"), b"forbidden").is_err(),
            || "read-only storage became writable".into(),
        )?;
        pending(missing)
    }

    fn first_read_server(root: &Path, missing: &Path) -> Result<(), String> {
        use std::io::BufRead as _;
        first_read(root, missing)?;
        for line in std::io::stdin().lock().lines() {
            let request: Value = serde_json::from_str(&line.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
            let Some(id) = request.get("id") else {
                continue;
            };
            let result = match request["method"].as_str() {
                Some("initialize") => {
                    json!({"protocolVersion":"2024-11-05", "capabilities":{"tools":{}}, "serverInfo":{"name":"first-read-probe", "version":"1"}})
                }
                Some("tools/list") => {
                    json!({"tools":[{"name":"initial_read", "description":"Report a storage read completed before the server accepted input", "inputSchema":{"type":"object", "properties":{}, "additionalProperties":false}}]})
                }
                Some("tools/call") => {
                    json!({"content":[{"type":"text", "text":"server-first-read-passed"}], "isError":false})
                }
                method => return Err(format!("unexpected first-read MCP method: {method:?}")),
            };
            println!("{}", json!({"jsonrpc":"2.0", "id":id, "result":result}));
            std::io::stdout()
                .flush()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn first_read_client(root: &Path, missing: &Path) -> Result<(), String> {
        use std::io::{BufRead as _, BufReader};
        use std::process::Stdio;
        denied(&root.join("public"))?;
        for _ in 0..3 {
            let result = Command::new("sh")
                .args([
                    "-c",
                    &format!(
                        "storage-tool first-read-tool {} {}",
                        root.display(),
                        missing.display()
                    ),
                ])
                .output()
                .map_err(|error| error.to_string())?;
            require(result.status.success(), || {
                format!(
                    "first-read tool failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                )
            })?;
            require(result.stdout == b"tool-first-read-passed\n", || {
                format!("unexpected tool receipt: {:?}", result.stdout)
            })?;
        }
        let mut child = Command::new("storage-server")
            .arg("first-read-server")
            .arg(root)
            .arg(missing)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| error.to_string())?;
        let mut input = child.stdin.take().ok_or("missing server input")?;
        let mut output = BufReader::new(child.stdout.take().ok_or("missing server output")?);
        for (id, method, params) in [
            (
                1,
                "initialize",
                json!({"protocolVersion":"2024-11-05", "capabilities":{}, "clientInfo":{"name":"first-read-client", "version":"1"}}),
            ),
            (2, "tools/list", json!({})),
            (
                3,
                "tools/call",
                json!({"name":"initial_read", "arguments":{}}),
            ),
        ] {
            writeln!(
                input,
                "{}",
                json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})
            )
            .map_err(|error| error.to_string())?;
            input.flush().map_err(|error| error.to_string())?;
            let mut line = String::new();
            require(
                output
                    .read_line(&mut line)
                    .map_err(|error| error.to_string())?
                    > 0,
                || "server closed before its first-read receipt".into(),
            )?;
            let response: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
            require(
                response["id"] == id && response.get("error").is_none(),
                || format!("server first-read request failed: {response}"),
            )?;
            if id == 1 {
                writeln!(
                    input,
                    "{}",
                    json!({"jsonrpc":"2.0", "method":"notifications/initialized"})
                )
                .map_err(|error| error.to_string())?;
                input.flush().map_err(|error| error.to_string())?;
            }
            if id == 3 {
                require(
                    response["result"]["content"][0]["text"] == "server-first-read-passed",
                    || format!("unexpected server receipt: {response}"),
                )?;
            }
        }
        drop(input);
        let status = child.wait().map_err(|error| error.to_string())?;
        require(status.success(), || {
            format!("server alias exited with {status}")
        })?;
        println!("three-tool-and-server-first-reads-passed");
        Ok(())
    }

    pub(super) fn run() -> Result<(), String> {
        let args = std::env::args_os().collect::<Vec<_>>();
        if let Some(mode) = args.get(1).and_then(|mode| mode.to_str())
            && matches!(
                mode,
                "first-read-native"
                    | "first-read-tool"
                    | "first-read-server"
                    | "first-read-client"
                    | "first-read-wait"
                    | "first-read-pending"
            )
        {
            if args.len() != 4 {
                return Err("first-read probe requires one mounted and one absent root".into());
            }
            let root = Path::new(&args[2]);
            let missing = Path::new(&args[3]);
            return match mode {
                "first-read-pending" => {
                    pending(root)?;
                    pending(missing)?;
                    println!("pending-first-read-passed");
                    Ok(())
                }
                "first-read-server" => first_read_server(root, missing),
                "first-read-client" => first_read_client(root, missing),
                "first-read-wait" => {
                    let output = Path::new("/mnt/storage-output");
                    marker(output, "waiting-to-launch", &json!({"started":true}))?;
                    let deadline = Instant::now() + BOUND;
                    while !output.join("launch-now").exists() {
                        require(Instant::now() < deadline, || {
                            "fixture did not release tool launch".into()
                        })?;
                        thread::sleep(STEP);
                    }
                    first_read_client(root, missing)
                }
                _ => {
                    first_read(root, missing)?;
                    println!(
                        "{}-first-read-passed",
                        if mode == "first-read-tool" {
                            "tool"
                        } else {
                            "native"
                        }
                    );
                    Ok(())
                }
            };
        }
        if let Some(mode) = args.get(1).and_then(|mode| mode.to_str())
            && matches!(
                mode,
                "role-agent"
                    | "role-tool"
                    | "role-server"
                    | "role-agent-failure"
                    | "role-tool-failure"
                    | "role-server-failure"
            )
        {
            if args.len() != 4 {
                return Err(
                    "usage: storage role probe <role-agent|role-tool|role-server> <output> <root>"
                        .into(),
                );
            }
            return roles::run(mode, Path::new(&args[2]), Path::new(&args[3]));
        }
        if args.len() != 6 {
            return Err("usage: box-storage-probe <before|after-first|after-second|compile-failure> <output> <rootA> <rootB> <positiveTrue>".into());
        }
        let mode = args[1]
            .to_str()
            .ok_or_else(|| "mode must be UTF-8".to_owned())?;
        let output = Path::new(&args[2]);
        let roots = [PathBuf::from(&args[3]), PathBuf::from(&args[4])];
        let positive = Path::new(&args[5]);
        for path in [output, roots[0].as_path(), roots[1].as_path(), positive] {
            require(path.is_absolute(), || {
                format!("fixture path is not absolute: {}", path.display())
            })?;
        }
        let deadline = Instant::now()
            + if mode == "compile-failure" {
                FAILURE_BOUND
            } else {
                BOUND
            };
        let mut watcher = Watcher::start(roots.clone(), deadline);
        let result = exercise(mode, output, &roots, positive, &watcher, deadline);
        let watched = watcher.finish();
        watched.and(result)
    }
}
