"""Check how ci.yml calls the CLI's reusable test workflow."""

import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"
CI = WORKFLOWS / "ci.yml"
CLI_TEST = WORKFLOWS / "cli-test.yml"


def job(path, name):
    text = path.read_text()
    return re.split(r"\n(?=  [^ ])", text.split(f"\n  {name}:\n", 1)[1], maxsplit=1)[0]


def step_command(path, name):
    lines = path.read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    start = lines.index("        run: |", start) + 1
    end = start
    while end < len(lines) and (not lines[end] or lines[end].startswith("          ")):
        end += 1
    return textwrap.dedent("\n".join(lines[start:end]))


class CliTestWorkflowTests(unittest.TestCase):
    def test_it_is_reusable_with_the_two_inputs(self):
        text = CLI_TEST.read_text()
        triggers = text.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", triggers), ["workflow_call"])
        self.assertEqual(re.findall(r"(?m)^      ([a-z_]+):", triggers),
                         ["suite", "macos"])

    def test_it_keeps_the_job_names(self):
        for name, title in [
            ("build-test-lint", "Build, test, lint"),
            ("macos", "macOS checks"),
        ]:
            with self.subTest(job=name):
                self.assertIn(f"    name: {title}\n", job(CLI_TEST, name))

    def test_each_suite_selects_its_jobs(self):
        self.assertIn("    if: inputs.suite == 'all'\n", job(CLI_TEST, "build-test-lint"))
        self.assertIn("    if: inputs.macos\n", job(CLI_TEST, "macos"))

    def test_an_unknown_suite_is_refused(self):
        command = step_command(CLI_TEST, "Refuse an unknown suite")
        for suite, success in [("all", True), ("engine", True), ("launch", False),
                               ("", False), ("ALL", False), ("corpus", False)]:
            with self.subTest(suite=suite):
                result = subprocess.run(["bash", "-c", command], env={**os.environ, "SUITE": suite},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stdout)

    def test_every_checkout_tests_the_callers_commit(self):
        # The caller's commit, not an input: CodeQL treats a checkout of an input ref in a job
        # that saves the Rust cache as cache poisoning.
        text = CLI_TEST.read_text()
        checkouts = text.count("uses: actions/checkout@")
        self.assertEqual(checkouts, 2)
        self.assertEqual(text.count("          ref: ${{ github.sha }}\n"), checkouts)
        self.assertNotIn("inputs.ref", text)


def step_run(path, job_name, step_name):
    """The run text of one step in one job, for a one-line or a block `run:`."""
    lines = job(path, job_name).splitlines()
    start = lines.index(f"      - name: {step_name}")
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("      - "):
            break
        if line == "        run: |":
            body = []
            for following in lines[index + 1:]:
                if following and not following.startswith("          "):
                    break
                body.append(following)
            return textwrap.dedent("\n".join(body))
        if line.startswith("        run: "):
            return line.removeprefix("        run: ")
    raise AssertionError(f"{job_name}: step {step_name!r} has no run")


class MovedCommandTests(unittest.TestCase):
    """The jobs moved from ci.yml keep their commands."""

    def test_the_linux_job_keeps_its_commands(self):
        for step, command in [
            ("Format", "cargo fmt --all --check"),
            ("Clippy", "cargo clippy --workspace --all-targets --all-features -- -D warnings"),
            ("Build", "cargo build --locked --all-features -p strands-box-cli -p strands-box "
                      "-p strands-box-containment --bin box --bin strands-box "
                      "--bin strands-box-sock-alias --bin strands-box-contain-trampoline"),
            ("Test", "cargo test -p strands-box-cli -p strands-box-cli-pack-tests -p strands-box-cli-profile -p strands-box-cli-telemetry --all-features"),
        ]:
            with self.subTest(step=step):
                self.assertEqual(step_run(CLI_TEST, "build-test-lint", step), command)

    def test_the_macos_job_keeps_its_commands(self):
        self.assertEqual(
            step_run(CLI_TEST, "macos", "Clippy"),
            "cargo clippy --workspace --all-targets --all-features -- -D warnings")
        test = step_run(CLI_TEST, "macos", "Test")
        self.assertIn('  *) echo "::error::full Xcode is not selected: $developer_dir"; exit 1 ;;\n',
                      test)
        self.assertIn("  cargo test -p strands-box-cli --all-features --test engine\n", test)
        self.assertIn("else\n  cargo test -p strands-box-cli -p strands-box-cli-pack-tests -p strands-box-cli-profile -p strands-box-cli-telemetry --all-features\nfi", test)


class SuiteStepTests(unittest.TestCase):
    """Each step of the macOS job runs only for the suites that need it."""

    ALL = "${{ !cancelled() && inputs.suite == 'all' }}"
    TESTS = "${{ !cancelled() }}"

    def step_if(self, name, occurrence=0):
        lines = job(CLI_TEST, "macos").splitlines()
        starts = [index for index, line in enumerate(lines) if line == f"      - name: {name}"]
        start = starts[occurrence]
        for line in lines[start + 1:]:
            if line.startswith("      - "):
                return None
            if line.startswith("        if: "):
                return line.removeprefix("        if: ")
        return None

    def test_lint_runs_only_for_all(self):
        self.assertEqual(self.step_if("Clippy"), self.ALL)

    def test_test_steps_run_for_all_and_engine(self):
        for name in ["Install launcher test prerequisites", "Test"]:
            with self.subTest(step=name):
                self.assertEqual(self.step_if(name), self.TESTS)

    LAUNCH = "${{ !cancelled() && steps.build.outcome == 'success' && env.LAUNCH == 'true' }}"

    def test_the_launch_checks_run_only_for_all(self):
        self.assertIn("      LAUNCH: ${{ inputs.suite == 'all' }}\n", job(CLI_TEST, "macos"))
        for name in ["Corpus launch check", "Install the agents", "Launch checks"]:
            with self.subTest(step=name):
                self.assertEqual(self.step_if(name), self.LAUNCH)
        self.assertEqual(self.step_if("Corpus runner unit tests"),
                         "${{ !cancelled() && env.LAUNCH == 'true' }}")

    def test_the_launch_checks_run_before_the_test_build(self):
        lines = job(CLI_TEST, "macos").splitlines()
        order = [lines.index(f"      - name: {name}") for name in
                 ["Build Box and helpers", "Corpus launch check", "Launch checks", "Test"]]
        self.assertEqual(order, sorted(order))


class LaunchCommandTests(unittest.TestCase):
    """The macOS job runs the corpus's launch checks and its runner's unit tests."""

    def test_the_probe_and_the_agents_launch(self):
        self.assertIn("python3 test-corpus/run_corpus.py --layer launch --ids probe --install-profiles",
                      step_run(CLI_TEST, "macos", "Corpus launch check"))
        self.assertIn("python3 test-corpus/run_corpus.py --layer launch --install-profiles --no-skip",
                      step_run(CLI_TEST, "macos", "Launch checks"))

    def test_the_runner_unit_tests_run(self):
        self.assertEqual(step_run(CLI_TEST, "macos", "Corpus runner unit tests"),
                         "python3 -m unittest discover -s test-corpus -p 'test_*.py'")

    def test_each_agent_download_is_checked(self):
        install = step_run(CLI_TEST, "macos", "Install the agents")
        self.assertIn('echo "$CLAUDE_CODE_SHA256  $claude" | shasum -a 256 -c -', install)
        self.assertIn('echo "$CODEX_SHA256  $RUNNER_TEMP/codex.tar.gz" | shasum -a 256 -c -', install)
        self.assertIn('--version "$KIRO_CLI_VERSION"', install)


class CiWorkflowTests(unittest.TestCase):
    def test_ci_calls_cli_test_with_the_change_classes(self):
        cli = job(CI, "cli")
        self.assertIn("    uses: ./.github/workflows/cli-test.yml\n", cli)
        self.assertIn("    if: needs.detect-changes.outputs.cli == 'true' || "
                      "needs.detect-changes.outputs.core == 'true'\n", cli)
        self.assertIn("      suite: ${{ needs.detect-changes.outputs.cli == 'true' && 'all' || 'engine' }}\n", cli)
        self.assertIn("      macos: ${{ github.event_name != 'pull_request' || "
                      "github.event.pull_request.draft == false }}\n", cli)

    def test_the_gate_needs_every_job_and_refuses_a_draft(self):
        gate = job(CI, "ci-gate")
        self.assertIn("    name: CI Gate\n", gate)
        self.assertIn("    needs: [detect-changes, prose, packaging, rust, cli, site-manifest, containment, "
                      "verdict]\n", gate)
        self.assertIn("          allowed-skips: rust, cli, site-manifest, containment, verdict\n", gate)
        self.assertIn("        if: ${{ github.event.pull_request.draft == true }}\n", gate)

    def test_a_change_to_cli_test_runs_the_cli_checks(self):
        cli = CI.read_text().split("            cli:\n", 1)[1].split("            shared:\n", 1)[0]
        self.assertIn("              - '.github/workflows/cli-test.yml'\n", cli)


if __name__ == "__main__":
    unittest.main()
