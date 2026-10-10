#!/usr/bin/env python3
"""Capture macOS termination evidence for a finished deterministic run. Stdlib only.

Invoked by tools/mac-diagnostics.sh (which bootstrap.sh runs only in diagnostic mode, after the
verdict is written and uploaded, before teardown). Reads verdict.json and host records; never
changes a test outcome; always exits 0. Every external command runs in its OWN process group under
a watchdog that terminates and reaps the whole group (SIGTERM, then SIGKILL) at the earlier of its
per-command timeout and the global deadline, and whose output is capped in bytes while it runs.
Scans (report directories, copies, hashing) check the same global deadline as they go. When the
deadline passes, remaining steps are recorded as skipped and summary.json says `incomplete: true`.
A missing record is INCONCLUSIVE, a deleted alias path is UNAVAILABLE, and a missing tool is a
recorded diagnostic error — nothing is fabricated and no verdict is touched.

Usage: mac_diagnostics.py <results-dir> <output-dir> [run-start-epoch]
Env: DIAG_CMD_TIMEOUT (120), DIAG_OUTPUT_CAP (2 MiB), DIAG_REPORT_CAP (1 MiB per copied report),
     DIAG_MAX_REPORTS (20), DIAG_TOTAL_TIMEOUT (600), DIAG_ALIAS_IMAGE, DIAG_PLATFORM, DIAG_FORCE.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

KILLED_RE = re.compile(r"^(?:/bin/)?bash: line \d+:\s+(\d+) Killed: 9\s+(.*)$")
ALIAS_PATH_RE = re.compile(r"(/[^\s'\"]*?/state/bin/[A-Za-z0-9_.-]+)")
ALIAS_DIR_RE = re.compile(r"PATH=([^\s:]*?/state/bin)")
REPORT_SUFFIXES = (".ips", ".crash", ".diag")


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class Deadline:
    """One global deadline every step consults."""

    def __init__(self, seconds):
        self.start = time.monotonic()
        self.end = self.start + seconds
        self.tripped = False

    def remaining(self):
        return max(0.0, self.end - time.monotonic())

    def passed(self):
        if time.monotonic() >= self.end:
            self.tripped = True
        return self.tripped

    def elapsed(self):
        return int(time.monotonic() - self.start)


class Capture:
    def __init__(self, results, out, run_start):
        self.results = results
        self.out = out
        self.run_start = run_start
        self.cmd_timeout = env_int("DIAG_CMD_TIMEOUT", 120)
        self.output_cap = env_int("DIAG_OUTPUT_CAP", 2 * 1024 * 1024)
        self.report_cap = env_int("DIAG_REPORT_CAP", 1024 * 1024)
        self.max_reports = env_int("DIAG_MAX_REPORTS", 20)
        self.deadline = Deadline(env_int("DIAG_TOTAL_TIMEOUT", 600))
        self.alias_image = os.environ.get("DIAG_ALIAS_IMAGE") or os.path.join(
            os.environ.get("HOME", ""), "box/target/release/strands-box-sock-alias")
        self.platform = os.environ.get("DIAG_PLATFORM") or platform.system()
        self.errors = []
        self.skipped = []
        self.notes = []
        os.makedirs(os.path.join(out, "crash-reports"), exist_ok=True)
        os.makedirs(os.path.join(out, "image"), exist_ok=True)

    # ── bookkeeping ─────────────────────────────────────────────────────────────
    def note(self, text):
        self.notes.append(text)

    def error(self, text):
        self.errors.append(text)
        self.notes.append("ERROR: " + text)

    def skip(self, label):
        self.skipped.append(label)
        self.notes.append("SKIPPED (global deadline): " + label)

    def budget_ok(self, label):
        if self.deadline.passed():
            self.skip(label)
            return False
        return True

    # ── bounded external command in its own process group ──────────────────────
    def run(self, outfile, label, argv):
        """Run argv in a new session/process group; cap wall time to min(cmd_timeout, remaining)
        and stdout+stderr bytes to output_cap; on either bound, SIGTERM the group, then SIGKILL,
        and confirm the group is gone. Returns True when the command completed with status 0."""
        if not self.budget_ok(label):
            return False
        if shutil.which(argv[0]) is None:
            self.error(f"{label}: command not available: {argv[0]}")
            return False
        limit = min(float(self.cmd_timeout), self.deadline.remaining())
        path = os.path.join(self.out, outfile)
        started = time.monotonic()
        with open(path, "wb") as sink:
            try:
                proc = subprocess.Popen(argv, stdout=sink, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as exc:
                self.error(f"{label}: cannot start: {exc}")
                return False
            reason = None
            while True:
                status = proc.poll()
                if status is not None:
                    break
                sink.flush()
                if os.path.getsize(path) > self.output_cap:
                    reason = f"output exceeded {self.output_cap} bytes"
                    break
                if time.monotonic() - started >= limit:
                    reason = f"timed out after {limit:.0f}s"
                    break
                time.sleep(0.05)
        if reason is None and self.group_alive(proc.pid):
            reason = "command exited with live descendants"
        if reason is not None:
            self.terminate_group(proc, label)
            self.error(f"{label}: {reason} (partial output kept; process group terminated)")
        # The cap holds whether the command was cut or finished fast: a burst that completed between
        # polls is truncated too, and recorded.
        if os.path.getsize(path) > self.output_cap:
            with open(path, "r+b") as f:
                f.truncate(self.output_cap)
            if reason is None:
                self.error(f"{label}: output exceeded {self.output_cap} bytes (truncated to the cap)")
        if reason is not None:
            return False
        if status != 0:
            self.error(f"{label}: exit {status} (output kept)")
            return False
        return True

    def terminate_group(self, proc, label):
        """SIGTERM the command's whole process group, escalate to SIGKILL, reap, and verify."""
        pgid = proc.pid  # start_new_session=True makes the child its own group leader
        for sig, grace in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 2.0)):
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                break
            until = time.monotonic() + grace
            while time.monotonic() < until:
                try:
                    proc.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
                if not self.group_alive(pgid):
                    break
                time.sleep(0.05)
            if not self.group_alive(pgid):
                break
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        if self.group_alive(pgid):
            self.error(f"{label}: process group {pgid} still alive after SIGKILL (left to the runner's teardown)")

    @staticmethod
    def group_alive(pgid):
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    # ── 1. verdict ──────────────────────────────────────────────────────────────
    def read_cases(self):
        cases = {"verdict_present": False, "failed_cases": [], "killed": [], "alias_paths_named": []}
        path = os.path.join(self.results, "verdict.json")
        if not os.path.isfile(path):
            self.error(f"no verdict.json at {path}: nothing to correlate")
            return cases
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                verdict = json.load(f)
            if not isinstance(verdict, dict):
                raise ValueError("verdict.json is not a JSON object")
        except Exception as exc:  # noqa: BLE001 — every failure is a recorded diagnostic gap
            self.error(f"verdict.json unreadable or malformed: {type(exc).__name__}: {str(exc)[:200]}")
            cases["malformed"] = True
            return cases
        cases.update(verdict_present=True, platform=verdict.get("platform"), box_commit=verdict.get("box_commit"),
                     verdict=verdict.get("verdict"), counts=verdict.get("counts"))
        alias_paths = set()
        for row in verdict.get("results") or []:
            if not isinstance(row, dict):
                continue
            note = row.get("note") or ""
            if row.get("result") in ("FAIL", "ERROR"):
                cases["failed_cases"].append({"id": row.get("id"), "result": row.get("result"),
                                             "note_head": note[:200]})
            for line in note.split("\n"):
                m = KILLED_RE.match(line.strip())
                if m:
                    cmd = m.group(2).strip()
                    cases["killed"].append({"case": row.get("id"), "pid": int(m.group(1)),
                                            "argv0": cmd.split(" ", 1)[0] if cmd else "", "command": cmd[:300]})
                alias_paths.update(ALIAS_PATH_RE.findall(line))
                for d in ALIAS_DIR_RE.findall(line):
                    alias_paths.update(d + "/" + n for n in ("zsh", "bash", "sh", "python3", "python"))
        cases["alias_paths_named"] = sorted(alias_paths)
        return cases

    # ── 2. termination records ─────────────────────────────────────────────────
    def report_dirs(self):
        user = os.environ.get("USER") or ""
        try:
            import pwd
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:  # noqa: BLE001
            pass
        real_home = ""
        if self.run("image/dscacheutil.txt", "dscacheutil user lookup",
                    ["dscacheutil", "-q", "user", "-a", "name", user]):
            with open(os.path.join(self.out, "image/dscacheutil.txt"), errors="replace") as f:
                for line in f:
                    if line.startswith("dir: "):
                        real_home = line[5:].strip()
        if not real_home:
            try:
                import pwd
                real_home = pwd.getpwuid(os.getuid()).pw_dir
            except Exception:  # noqa: BLE001
                real_home = ""
        dirs = ["/Library/Logs/DiagnosticReports"]
        if real_home:
            dirs.append(os.path.join(real_home, "Library/Logs/DiagnosticReports"))
        home = os.environ.get("HOME", "")
        if home and home != real_home:
            dirs.append(os.path.join(home, "Library/Logs/DiagnosticReports"))
        self.note(f"uid={os.getuid()} user={user} real_home={real_home or 'unknown'} harness_home={home or 'unset'}")
        return dirs

    def collect_reports(self, killed):
        pids = {k["pid"] for k in killed}
        names = {k["argv0"] for k in killed if k.get("argv0")}
        found, candidates, searched = 0, 0, 0
        window = self.run_start if self.run_start else time.time() - 6 * 3600
        for d in self.report_dirs():
            if not self.budget_ok(f"scan {d}"):
                break
            if not os.path.isdir(d):
                self.note(f"  {d}: absent")
                continue
            searched += 1
            try:
                entries = sorted(os.listdir(d))
            except OSError as exc:
                self.error(f"{d}: unreadable ({exc})")
                continue
            for name in entries:
                if self.deadline.passed():
                    self.skip(f"scan {d} (stopped at {name})")
                    break
                if not name.endswith(REPORT_SUFFIXES):
                    continue
                path = os.path.join(d, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if not os.path.isfile(path) or st.st_mtime < window:
                    continue
                candidates += 1
                match = any(name.startswith(n + "-") or name.startswith(n + "_") for n in names)
                if not match and pids:
                    try:
                        with open(path, "rb") as f:
                            head = f.read(self.report_cap).decode("utf-8", "replace")
                        match = any(re.search(rf'"pid" *: *{p}\b|Process: +\S+ \[{p}\]', head) for p in pids)
                    except OSError as exc:
                        self.error(f"{path}: unreadable ({exc})")
                if match and found < self.max_reports:
                    self.copy_capped(path, os.path.join(self.out, "crash-reports", name))
                    found += 1
        self.note(f"crash reports: {candidates} candidates in {searched} directories, "
                  f"{found} matched killed pids/names")
        if found == 0:
            self.note("no termination record matched the killed pids/names: INCONCLUSIVE "
                      "(ReportCrash does not record every SIGKILL; absence is not evidence of a user-space sender)")
        return found, candidates

    def copy_capped(self, src, dst):
        try:
            with open(src, "rb") as f, open(dst, "wb") as g:
                data = f.read(self.report_cap)
                g.write(data)
                if f.read(1):
                    g.write(b"\n[truncated by mac_diagnostics at %d bytes]\n" % self.report_cap)
                    self.note(f"{os.path.basename(src)}: copied first {self.report_cap} bytes only")
        except OSError as exc:
            self.error(f"copy {src}: {exc}")

    def extract_reports(self):
        out = []
        d = os.path.join(self.out, "crash-reports")
        for name in sorted(os.listdir(d)):
            if not name.endswith(".ips"):
                continue
            try:
                text = open(os.path.join(d, name), errors="replace").read()
                first, _, rest = text.partition("\n")
                header = json.loads(first)
                body_text = rest.split("\n[truncated by mac_diagnostics")[0]
                body = json.loads(body_text) if body_text.strip().startswith("{") else {}
            except Exception as exc:  # noqa: BLE001
                out.append({"file": name, "parse_error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                continue
            term = body.get("termination") or {}
            out.append({"file": name, "app_name": header.get("app_name") or body.get("procName"),
                        "pid": body.get("pid"),
                        "proc_path": body.get("procPath"), "exception": body.get("exception"),
                        "termination": {k: term.get(k) for k in
                                        ("namespace", "code", "indicator", "byProc", "byPid", "reasons") if k in term},
                        "timestamp": header.get("timestamp") or body.get("captureTime")})
        if out:
            self.write_json("crash-reports/extracted.json", out)

    # ── 3. unified log ──────────────────────────────────────────────────────────
    def log_windows(self, killed):
        if self.run_start:
            window = ["--start", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.run_start))]
        else:
            window = ["--last", "2h"]
        self.note("log window: " + " ".join(window))
        base = ["log", "show"] + window + ["--style", "compact", "--info", "--predicate"]
        for pid in sorted({k["pid"] for k in killed}):
            self.run(f"log-pid-{pid}.txt", f"log show pid {pid}",
                     base + [f'processID == {pid} OR eventMessage CONTAINS "{pid}"'])
        self.run("log-kernel-security.txt", "log show kernel security", base + [
            'process == "kernel" AND (eventMessage CONTAINS[c] "sandbox" OR eventMessage CONTAINS[c] "code signing" '
            'OR eventMessage CONTAINS[c] "codesign" OR eventMessage CONTAINS "EXC_GUARD" '
            'OR eventMessage CONTAINS[c] "killed" '
            'OR eventMessage CONTAINS[c] "AMFI")'])
        self.run("log-security-daemons.txt", "log show amfid/taskgated/sandboxd", base + [
            'process == "amfid" OR process == "taskgated" OR process == "sandboxd" '
            'OR subsystem == "com.apple.sandbox.reporting" OR process == "ReportCrash"'])
        for name in sorted({k["argv0"] for k in killed if k.get("argv0")}):
            self.run(f"log-process-{name}.txt", f"log show process {name}", base + [f'process == "{name}"'])

    # ── 4. image identity ──────────────────────────────────────────────────────
    def image_identity(self, cases):
        self.run("image/sw_vers.txt", "sw_vers", ["sw_vers"])
        self.run("image/uname.txt", "uname", ["uname", "-a"])
        self.run("image/csrutil.txt", "csrutil status", ["csrutil", "status"])
        verify = "image-missing"
        img = self.alias_image
        if os.path.isfile(img):
            self.note(f"alias source image: {img}")
            self.write_text("image/source-stat.txt", self.stat_text(img))
            digest = self.sha256_bounded(img, "source image")
            if digest:
                self.write_text("image/source-sha256.txt", f"{digest}  {img}\n")
            self.run("image/source-file.txt", "file source image", ["file", img])
            self.run("image/source-codesign-display.txt", "codesign display", ["codesign", "-dv", "--verbose=4", img])
            verified = self.run("image/source-codesign-verify.txt", "codesign verify",
                                ["codesign", "--verify", "--verbose=2", img])
            verify = "ok" if verified else "failed-or-unavailable"
            self.note(f"codesign --verify: {verify}")
        else:
            self.error(f"alias source image not found at {img} (set DIAG_ALIAS_IMAGE); image identity unavailable")
        lines = []
        for p in cases.get("alias_paths_named", []):
            if self.deadline.passed():
                self.skip("alias path identity")
                break
            if os.path.exists(p):
                digest = self.sha256_bounded(p, p) or "unavailable"
                lines.append(f"== {p} (present)\n{self.stat_text(p)}sha256 {digest}\n")
            else:
                lines.append(f"== {p}: UNAVAILABLE (removed by fixture cleanup before capture; "
                             "identity cannot be shown for this path)\n")
        self.write_text("image/alias-paths.txt", "".join(lines) or "no alias paths named in the verdict notes\n")
        return verify

    @staticmethod
    def stat_text(path):
        try:
            st = os.stat(path)
            return (f"path={path} inode={st.st_ino} dev={st.st_dev} nlink={st.st_nlink} size={st.st_size} "
                    f"mode={oct(st.st_mode)} uid={st.st_uid} "
                    f"mtime={time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(st.st_mtime))}Z\n")
        except OSError as exc:
            return f"path={path} stat failed: {exc}\n"

    def sha256_bounded(self, path, label):
        """SHA-256 of a file, hashed in chunks that each check the global deadline."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    if self.deadline.passed():
                        self.skip(f"sha256 {label}")
                        return None
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError as exc:
            self.error(f"sha256 {label}: {exc}")
            return None
        return h.hexdigest()

    # ── output ─────────────────────────────────────────────────────────────────
    def write_text(self, rel, text):
        with open(os.path.join(self.out, rel), "w") as f:
            f.write(text)

    def write_json(self, rel, obj):
        with open(os.path.join(self.out, rel), "w") as f:
            json.dump(obj, f, indent=1)
            f.write("\n")

    def finish(self, cases, found, candidates, verify, applicable):
        self.write_text("errors.txt", "".join(e + "\n" for e in self.errors))
        summary = {
            "applicable": applicable,
            "platform": self.platform,
            "failed_cases": [c.get("id") for c in cases.get("failed_cases", [])],
            "killed": cases.get("killed", []),
            "crash_reports": {"candidates_in_window": candidates, "matched": found,
                              "conclusion": "see crash-reports/extracted.json" if found else
                              "INCONCLUSIVE: no termination record matched; absence does not identify a sender"},
            "alias_image_codesign_verify": verify,
            "diagnostic_errors": len(self.errors),
            "skipped_steps": self.skipped,
            "incomplete": bool(self.skipped) or self.deadline.tripped,
            "elapsed_seconds": self.deadline.elapsed(),
            "bounds": {"cmd_timeout_s": self.cmd_timeout, "output_cap_bytes": self.output_cap,
                       "report_cap_bytes": self.report_cap, "max_reports": self.max_reports,
                       "total_timeout_s": int(self.deadline.end - self.deadline.start)},
            "files": sorted(f for f in os.listdir(self.out) if os.path.isfile(os.path.join(self.out, f))),
        }
        self.write_json("summary.json", summary)
        self.notes.append(f"done in {self.deadline.elapsed()}s with {len(self.errors)} diagnostic error(s), "
                          f"{len(self.skipped)} skipped step(s); summary.json written")
        self.write_text("README.txt", "".join(n + "\n" for n in self.notes))


def main(argv):
    if len(argv) < 3:
        print("usage: mac_diagnostics.py <results-dir> <output-dir> [run-start-epoch]", file=sys.stderr)
        return 0
    results, out = argv[1], argv[2]
    run_start = None
    if len(argv) > 3 and argv[3]:
        try:
            run_start = float(argv[3])
        except ValueError:
            run_start = None
    os.makedirs(out, exist_ok=True)
    c = Capture(results, out, run_start)
    c.note(f"mac-diagnostics for {results} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} on {c.platform}")
    c.note(f"bounds: cmd {c.cmd_timeout}s, output {c.output_cap}B, report {c.report_cap}B, "
           f"reports {c.max_reports}, total {int(c.deadline.end - c.deadline.start)}s")
    if run_start is None:
        c.note("run start unknown: report window = last 6 h, log window = --last 2h")
    cases = c.read_cases()
    c.write_json("cases.json", cases)
    killed = cases.get("killed", [])
    c.note(f"killed pids: {' '.join(str(k['pid']) for k in killed) or 'none'}; process names: "
           f"{' '.join(sorted({k['argv0'] for k in killed if k.get('argv0')})) or 'none'}")
    applicable = c.platform == "Darwin" or os.environ.get("DIAG_FORCE") == "1"
    found = candidates = 0
    verify = "not-applicable"
    if applicable:
        found, candidates = c.collect_reports(killed)
        if found:
            c.extract_reports()
        c.log_windows(killed)
        verify = c.image_identity(cases)
    else:
        c.note(f"not macOS ({c.platform}): crash-report, unified-log and codesign steps not applicable")
    c.finish(cases, found, candidates, verify, applicable)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # noqa: BLE001 — the helper must never fail the run; say what broke
        try:
            out = sys.argv[2] if len(sys.argv) > 2 else "."
            os.makedirs(out, exist_ok=True)
            with open(os.path.join(out, "summary.json"), "w") as f:
                json.dump({"applicable": False, "helper_error": f"{type(exc).__name__}: {str(exc)[:300]}",
                           "diagnostic_errors": 1, "incomplete": True}, f, indent=1)
        finally:
            sys.exit(0)
