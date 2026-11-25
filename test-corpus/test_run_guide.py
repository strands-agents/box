"""Unit tests for run_guide.py, with a stub `box` and a stub agent. No model and no box."""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import run_guide

BOX = """#!/bin/sh
# A stub box: `help agent` prints the path of the shipped guide below one line and writes
# nothing, and `profile show --full <name>` prints the profile.
if [ "$1" = help ]; then
  [ "$#" = 2 ] && [ "$2" = agent ] || exit 2
  echo "Read this file and follow it to create or change a profile:"
  echo "  $(cat "$(dirname "$0")/resources-path")/editing-box-profile.md"
  echo
  echo "box home    $HOME/.strands/box"
  exit 0
fi
file="$HOME/.strands/box/profiles/$4/profile.toml"
[ -f "$file" ] || { echo "no profile $4" >&2; exit 1; }
cat "$file"
"""
AGENT = """#!/bin/sh
# A stub agent: it does what the file `behaviour` beside it says, in place of following the prompt.
profile="$HOME/.strands/box/profiles/test/profile.toml"
[ -z "$GITHUB_TOKEN$ACTIONS_ID_TOKEN_REQUEST_TOKEN$AWS_SECRET_ACCESS_KEY$AWS_PROFILE$ANTHROPIC_API_KEY$GITHUB_ENV" ] || exit 9
[ "$AWS_BEARER_TOKEN_BEDROCK" = a-key ] || exit 8
[ "$(cat "$(box help agent | sed -n '2s/^  //p')")" = "the guide" ] || exit 7
[ ! -e "$HOME/.strands/box/profiles/test/editing-box-profile.md" ] || exit 6
[ ! -e "$HOME/.strands/box/editing-box-profile.md" ] || exit 6
# The runner gives the agent the two folders that it needs: the cell's .strands/box and the resources.
[ "${10} ${11} ${12} ${13}" = "--add-dir $HOME/.strands/box --add-dir $BOX_RESOURCES" ] || exit 5
[ ! -e "$HOME/project/box-profile-guide.md" ] || exit 6
printf '%s' "$2" > "$(dirname "$0")/prompt"
case "$(cat "$(dirname "$0")/behaviour")" in
  good) printf '\\n[tool.truth]\\ncommand = ["/usr/bin/true"]\\n' >> "$profile" ;;
  stray) printf '\\n[tool.truth]\\ncommand = ["/usr/bin/true"]\\n' >> "$profile"; echo x > "$HOME/notes/stray" ;;
  shipped) printf '\\n[tool.truth]\\ncommand = ["/usr/bin/true"]\\n' >> "$profile"; echo x >> "$BOX_RESOURCES/packs/git/pack.toml" ;;
  pack) printf '\\n[tool.truth]\\ncommand = ["/usr/bin/true"]\\n' >> "$profile"; echo x >> "$HOME/.strands/box/packs/extra/pack.toml" ;;
  link) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; ln -s /tmp "$HOME/notes/link" ;;
  mode) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; chmod 777 "$HOME/settings.json" ;;
  planted) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; mkdir -p "$HOME/.local/bin"; echo x > "$HOME/.local/bin/box" ;;
  homeguide) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; echo "a copy" > "$HOME/.strands/box/editing-box-profile.md" ;;
  shippedguide) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; echo x >> "$BOX_RESOURCES/editing-box-profile.md" ;;
  leak) printf '\n[tool.truth]\ncommand = ["/usr/bin/true"]\n' >> "$profile"; echo "the key is $AWS_BEARER_TOKEN_BEDROCK" ;;
  nothing) ;;
  crash) exit 3 ;;
esac
"""


def script(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class GuideRunner(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="guide-test-", dir="/var/tmp")).resolve()
        self.addCleanup(lambda: subprocess.run(["rm", "-r", str(self.root)]))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        script(self.bin / "box", BOX)
        (self.bin / "resources-path").write_text(str(self.root / "resources"))
        self.agents = self.root / "agents"
        self.agents.mkdir()
        script(self.agents / "claude", AGENT)
        self.resources = self.root / "resources"
        (self.resources / "packs/git").mkdir(parents=True)
        (self.resources / "packs/git/pack.toml").write_text("[pack]\n")
        (self.resources / "editing-box-profile.md").write_text("the guide\n")

    def run_cell(self, behaviour, key="a-key", agent="claude", more=()):
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        (self.agents / "behaviour").write_text(behaviour)
        os.environ.update(GITHUB_TOKEN="t", ACTIONS_ID_TOKEN_REQUEST_TOKEN="t",
                          AWS_SECRET_ACCESS_KEY="t", AWS_PROFILE="p", ANTHROPIC_API_KEY="k",
                          GITHUB_ENV="/dev/null")
        # The stub box is not on this PATH: the runner must give it to the agent.
        os.environ.update(BOX_RESOURCES=str(self.resources),
                          PATH=f"{self.agents}:/usr/bin:/bin", AWS_BEARER_TOKEN_BEDROCK=key)
        os.environ.pop("BOX_BEDROCK_KEY_FILE", None)
        out = self.root / "out"
        code = run_guide.main(["--ids", "add-tool", "--out", str(out), "--box", str(self.bin),
                               "--agent", agent, *more])
        row = (out / "results.tsv").read_text().splitlines()[1].split("\t")
        return code, row[1], row[2]

    def test_a_correct_edit_inside_the_profile_passes(self):
        self.assertEqual(self.run_cell("good"), (0, "PASS", ""))

    def test_the_prompt_is_the_operators_sentence_and_the_task(self):
        self.run_cell("good")
        cell = next(c for c in run_guide.load_cells() if c["id"] == "add-tool")
        self.assertEqual((self.agents / "prompt").read_text(),
                         "Run box help agent and follow it to update profile test. "
                         + cell["task"])
        create = next(c for c in run_guide.load_cells() if "start" not in c)
        self.assertEqual(run_guide.prompt_for(create, Path("/home/x")),
                         "Run box help agent and follow it to create a profile. "
                         + create["task"].replace("{home}", "/home/x"))

    def test_prepare_writes_no_guide_and_needs_no_box(self):
        for cell in run_guide.load_cells():
            home = self.root / "prepared" / cell["id"]
            run_guide.prepare(cell, home)
            self.assertEqual([p for p in home.rglob("*.md") if "guide" in p.name
                              or p.name == "editing-box-profile.md"], [], cell["id"])
            self.assertEqual((home / ".strands/box/profiles").exists(), "start" in cell, cell["id"])

    def test_an_agent_that_changes_nothing_fails_the_show_check(self):
        code, verdict, reasons = self.run_cell("nothing")
        self.assertEqual((code, verdict), (1, "FAIL"))
        self.assertIn("show does not print '[tool.truth]'", reasons)

    def test_a_file_changed_outside_the_profile_fails(self):
        code, verdict, reasons = self.run_cell("stray")
        self.assertEqual((code, verdict), (1, "FAIL"))
        self.assertIn("changed outside the profile: notes/stray", reasons)

    def test_a_changed_operator_pack_fails(self):
        code, verdict, reasons = self.run_cell("pack")
        self.assertEqual((code, verdict), (1, "FAIL"))
        self.assertIn("changed outside the profile: .strands/box/packs/extra/pack.toml", reasons)

    def test_a_changed_shipped_pack_fails(self):
        code, verdict, reasons = self.run_cell("shipped")
        self.assertEqual((code, verdict), (1, "FAIL"))
        self.assertIn("changed a file that ships with box: packs/git/pack.toml", reasons)

    def test_the_uploaded_agent_log_holds_no_model_key(self):
        self.run_cell("leak", key="a-key")
        log = (self.root / "out" / "add-tool" / "agent.log").read_text()
        self.assertIn("the key is ***", log)
        self.assertNotIn("a-key", log)

    def test_a_changed_shipped_file_is_restored_for_the_next_cell(self):
        self.run_cell("shipped")
        self.assertEqual((self.resources / "packs/git/pack.toml").read_text(), "[pack]\n")
        self.run_cell("shippedguide")
        self.assertEqual((self.resources / "editing-box-profile.md").read_text(), "the guide\n")
        self.assertEqual(sorted(p.relative_to(self.resources).as_posix() for p in self.resources.rglob("*")),
                         ["editing-box-profile.md", "packs", "packs/git", "packs/git/pack.toml"])

    def test_a_new_link_a_changed_mode_and_a_planted_program_fail(self):
        for behaviour, path in (("link", "notes/link"), ("mode", "settings.json"),
                                ("planted", ".local/bin/box")):
            code, verdict, reasons = self.run_cell(behaviour)
            self.assertEqual((code, verdict), (1, "FAIL"), behaviour)
            self.assertIn(f"changed outside the profile: {path}", reasons)

    def test_a_guide_written_in_the_home_or_a_changed_shipped_guide_fails(self):
        for behaviour, reason in (
                ("homeguide", "changed outside the profile: .strands/box/editing-box-profile.md"),
                ("shippedguide", "changed a file that ships with box: editing-box-profile.md")):
            code, verdict, reasons = self.run_cell(behaviour)
            self.assertEqual((code, verdict), (1, "FAIL"), behaviour)
            self.assertIn(reason, reasons)

    def test_a_pattern_tells_a_right_rule_from_text_that_is_always_there(self):
        cell = {"shows": [], "matches": ['forbid[^;]*shell:spawn[^;]*"npm"[^;]*(arg2|arg_count)']}
        show = lambda text: subprocess.CompletedProcess([], 0, stdout=text, stderr="")
        generated = '@id("box_home_write") forbid (principal, action, resource);\n'
        wrong = generated + 'forbid (p, action == Box::Action::"shell:spawn", r) when { context.input.program == "npm" && context.input.arg1 == "install" };'
        exec_rule = generated + 'forbid (p, action == Box::Action::"shell:exec", r) when { context.input.program == "npm" && context.input has arg2 };'
        right = generated + 'forbid (p, action == Box::Action::"shell:spawn", r)\nwhen { context.input.program == "npm" &&\n context.input has arg2 };'
        self.assertEqual(run_guide.grade(cell, 0, show(right), [], [])[0], "PASS")
        self.assertEqual(run_guide.grade(cell, 0, show(exec_rule), [], [])[0], "FAIL")
        verdict, reasons = run_guide.grade(cell, 0, show(wrong), [], [])
        self.assertEqual(verdict, "FAIL")
        self.assertIn("show has no match for", reasons[0])

    def test_the_resources_folder_is_the_one_the_box_names(self):
        decoy = self.root / "decoy"
        decoy.mkdir()
        env = {"BOX_RESOURCES": str(decoy), "PATH": "/usr/bin:/bin"}
        self.assertEqual(run_guide.shipped_resources(str(self.bin / "box"), env),
                         self.resources.resolve())
        (self.bin / "resources-path").write_text(str(decoy))
        with self.assertRaises(ValueError):
            run_guide.shipped_resources(str(self.bin / "box"), env)

    def test_no_skip_fails_a_run_that_cannot_start(self):
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
        os.environ.pop("BOX_BEDROCK_KEY_FILE", None)
        self.assertEqual(run_guide.main(["--no-skip", "--out", str(self.root / "out")]), 1)

    def test_an_agent_that_exits_nonzero_fails(self):
        code, verdict, reasons = self.run_cell("crash")
        self.assertEqual((code, verdict), (1, "FAIL"))
        self.assertIn("the agent exited 3", reasons)

    def test_no_credential_or_no_agent_is_a_skip_that_names_its_reason(self):
        self.assertEqual(self.run_cell("good", key=""), (0, "SKIP", "no-model-credential"))
        self.assertEqual(self.run_cell("good", agent="absent-agent"), (0, "SKIP", "no-agent"))
        self.assertEqual(self.run_cell("good", key="", agent="absent-agent"),
                         (0, "SKIP", "no-model-credential,no-agent"))

    def test_the_agent_state_folders_are_not_changes(self):
        home = self.root / "home"
        (home / ".claude").mkdir(parents=True)
        before = run_guide.snapshot(home, run_guide.AGENT_STATE)
        (home / ".claude/history").write_text("x")
        (home / "folder").mkdir()
        (home / ".claude.json").write_text("{}")
        (home / "kept").write_text("x")
        after = run_guide.snapshot(home, run_guide.AGENT_STATE)
        self.assertEqual(run_guide.changed(before, after), ["folder", "kept"])

    def test_each_cell_names_what_it_checks_and_what_may_change(self):
        cells = run_guide.load_cells()
        self.assertEqual(len({c["id"] for c in cells}), len(cells))
        self.assertGreaterEqual(len(cells), 9)
        for cell in cells:
            self.assertTrue(cell["shows"] and cell["may_change"] and cell["task"], cell["id"])
            for pattern in cell["may_change"]:
                self.assertTrue(pattern.startswith(".strands/box/profiles/"), cell["id"])


if __name__ == "__main__":
    unittest.main()
