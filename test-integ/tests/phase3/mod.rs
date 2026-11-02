#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use strands_det_harness::{BoxFixture, Platform, RunResult, macos_git_identity, sh_quote};

pub const SOURCE: &str = include_str!("probe.rs");
pub const SIGNAL: i32 = if cfg!(target_os = "macos") { 30 } else { 10 };

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

pub fn q(path: &Path) -> String {
    sh_quote(&path.to_string_lossy())
}

pub fn compile(b: &BoxFixture) -> PathBuf {
    b.compile_probe("phase3-probe", SOURCE)
}

pub fn git_identity() -> PathBuf {
    if Platform::current() == Platform::Macos {
        return macos_git_identity();
    }
    std::env::split_paths(&std::env::var_os("PATH").expect("DET_ERROR: PATH is set"))
        .map(|directory| directory.join("git"))
        .find(|path| path.is_file())
        .expect("DET_ERROR: Git is installed")
        .canonicalize()
        .expect("DET_ERROR: resolve Git")
}

pub fn with_git(b: &BoxFixture, text: String) -> String {
    if Platform::current() == Platform::Macos {
        return b.with_macos_git_tool()(text);
    }
    let git = git_identity();
    let output = Command::new(&git)
        .arg("--exec-path")
        .env_remove("GIT_EXEC_PATH")
        .output()
        .expect("DET_ERROR: query Git's helper directory");
    let helpers = PathBuf::from(self::text(output).trim())
        .canonicalize()
        .expect("DET_ERROR: resolve Git's helper directory");
    let roots: std::collections::BTreeSet<_> = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .into_iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .chain([helpers, b.workspace().to_path_buf()])
        .collect();
    let json = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
    let reads = roots
        .iter()
        .filter(|path| {
            !roots
                .iter()
                .any(|other| other != *path && path.starts_with(other))
        })
        .map(|path| json(path))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{text}\n[tool.git]\ncommand = [{}]\nworkspace = {ws}\n\
         [tool.git.env]\nGIT_CONFIG_NOSYSTEM = \"1\"\nGIT_TEMPLATE_DIR = \"\"\n\
         [tool.git.filesystem]\nread = [{reads}]\nwrite = [{ws}]\n",
        json(&git),
        ws = json(b.workspace()),
    )
}

pub fn host(probe: &Path, args: &[&str]) -> String {
    let output = Command::new(probe)
        .env_clear()
        .args(args)
        .output()
        .expect("DET_ERROR: launch host positive control");
    text(output)
}

pub fn text(output: Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "DET_ERROR: host probe failed: {text}"
    );
    text
}

pub fn native_ok(r: &RunResult, entered: &str) {
    assert!(
        r.route == strands_det_harness::Route::Native,
        "DET_ERROR: wrong probe route"
    );
    r.assert_entered();
    assert!(
        !r.out.contains("DET_ERROR:"),
        "DET_ERROR: native probe setup failed: {}",
        r.out
    );
    assert!(
        r.out.lines().any(|line| line.starts_with(entered)),
        "DET_ERROR: intended native probe never entered ({entered}): {}",
        r.out
    );
    r.assert_contains(entered);
    assert_eq!(r.rc, 0, "probe did not finish: {}", r.out);
    assert!(
        !r.decisions
            .iter()
            .any(|d| d.is_action("shell:exec") || d.is_action("shell:spawn")),
        "native probe unexpectedly used the broker: {:?}",
        r.decisions
    );
}

pub fn until(mut condition: impl FnMut() -> bool, duration: Duration, description: &str) {
    let end = Instant::now() + duration;
    while !condition() {
        assert!(Instant::now() < end, "DET_ERROR: timeout: {description}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn number(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("DET_ERROR: read {}: {e}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("DET_ERROR: parse {}: {e}", path.display()))
}

pub struct Marker {
    child: Child,
    dir: PathBuf,
    pub token: String,
}

impl Marker {
    pub fn start(probe: &Path, dir: &Path, trace: bool) -> Self {
        std::fs::create_dir_all(dir).expect("DET_ERROR: marker directory");
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        dir.hash(&mut hash);
        let token = format!("p3{:012x}", hash.finish() & 0xffff_ffff_ffff);
        let child = Command::new(probe)
            .env_clear()
            .args(["marker", &token])
            .arg(dir)
            .arg(if trace { "trace" } else { "signal" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("DET_ERROR: start owned marker");
        let mut marker = Self {
            child,
            dir: dir.to_path_buf(),
            token,
        };
        until(
            || {
                marker.alive();
                marker.dir.join("ready").exists()
            },
            Duration::from_secs(5),
            "owned marker readiness",
        );
        marker.advance();
        marker
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn alive(&mut self) {
        assert!(
            self.child
                .try_wait()
                .expect("DET_ERROR: poll owned marker")
                .is_none(),
            "DET_ERROR: owned marker exited before observation"
        );
    }

    pub fn advance(&mut self) {
        self.alive();
        let before = number(&self.dir.join("heartbeat"));
        until(
            || {
                self.alive();
                number(&self.dir.join("heartbeat")) > before
            },
            Duration::from_secs(3),
            "owned marker heartbeat",
        );
    }

    pub fn count(&self) -> u64 {
        number(&self.dir.join("signals"))
    }

    pub fn signal_control(&mut self, expected: u64) {
        self.alive();
        assert_eq!(
            unsafe { kill(self.pid() as i32, SIGNAL) },
            0,
            "DET_ERROR: signal owned marker: {}",
            std::io::Error::last_os_error()
        );
        until(
            || self.count() == expected,
            Duration::from_secs(3),
            "host signal observer",
        );
        self.advance();
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn require_refusal(out: &str, label: &str, permitted_errno: &[i32]) {
    let prefix = format!("{label}_REFUSED ");
    let lines: Vec<_> = out
        .lines()
        .filter_map(|s| s.strip_prefix(&prefix))
        .collect();
    assert_eq!(lines.len(), 1, "missing or duplicate {label} result: {out}");
    let errno: i32 = lines[0].parse().expect("numeric refusal errno");
    assert!(
        permitted_errno.contains(&errno),
        "unexpected {label} errno {errno}: {out}"
    );
    assert!(
        !out.contains(&format!("{label}_REACHED")),
        "{label} reached host: {out}"
    );
}

pub struct StopDescendant(pub PathBuf);

impl Drop for StopDescendant {
    fn drop(&mut self) {
        let _ = std::fs::write(self.0.join("stop"), "stop");
    }
}

pub fn process_rows() -> Vec<String> {
    let output = Command::new("ps")
        .args(["-axww", "-o", "pid=,ppid=,pgid=,stat=,args="])
        .output()
        .expect("DET_ERROR: host process observer");
    text(output).lines().map(str::to_string).collect()
}

pub fn marked_rows(probe: &Path, dir: &Path) -> Vec<String> {
    process_rows()
        .into_iter()
        .filter(|line| {
            line.contains(probe.to_str().unwrap())
                && line.contains(dir.to_str().unwrap())
                && line.contains(" descendant ")
        })
        .collect()
}

pub fn process_tree(probe: &Path, marked: &[String]) -> Vec<String> {
    let rows = process_rows();
    let mut tree = marked.to_vec();
    let mut parent_ids: Vec<_> = marked
        .iter()
        .filter_map(|s| s.split_whitespace().nth(1).map(str::to_string))
        .collect();
    while let Some(pid) = parent_ids.pop() {
        if let Some(row) = rows.iter().find(|row| {
            row.split_whitespace().next() == Some(pid.as_str())
                && (row.contains(probe.to_str().unwrap()) || row.contains("strands-box"))
        }) {
            if !tree.contains(row) {
                parent_ids.push(row.split_whitespace().nth(1).unwrap().to_string());
                tree.push(row.clone());
            }
        }
    }
    tree
}

pub fn require_exit_deadline(elapsed: Duration, deadline: Duration) {
    assert!(
        elapsed < deadline,
        "ordinary exit exceeded {deadline:?}: {elapsed:?}; a descendant's own expiry must not satisfy cleanup"
    );
}

pub fn require_cleanup(probe: &Path, dir: &Path, deadline: Duration, original: &[String]) {
    let end = Instant::now() + deadline;
    loop {
        let rows = marked_rows(probe, dir);
        if rows.is_empty() {
            return;
        }
        assert!(
            Instant::now() < end,
            "live descendant survived ordinary exit; before={original:?}; after={:?}",
            process_tree(probe, &rows)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
pub mod linux;
