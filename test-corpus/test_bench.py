"""Unit tests for bench.py. They start no box: python3 -m unittest discover -s test-corpus"""
import json
import tempfile
import unittest
from pathlib import Path

import bench

GRID = [
    {"id": "A-1", "section": "Alpha", "script": "true", "needs": ["uv"]},
    {"id": "A-2", "section": "Alpha", "script": "true", "needs": ["git", "uv"]},
    {"id": "A-3", "section": "Alpha", "needs": ["poetry"]},
    {"id": "B-1", "section": "Beta"},
    {"id": "C-1", "section": "Gamma", "script": "true"},
]


class Plan(unittest.TestCase):
    def test_a_section_with_no_script_has_no_job(self):
        self.assertEqual([e["section"] for e in bench.plan(GRID)], ["Alpha", "Gamma"])

    def test_a_large_section_is_split_into_shards(self):
        self.assertEqual(bench.plan(GRID, chunk=1)[:2], [
            {"section": "Alpha", "shard": "1/2", "name": "Alpha-1-of-2", "needs": ["git", "poetry", "uv"]},
            {"section": "Alpha", "shard": "2/2", "name": "Alpha-2-of-2", "needs": ["git", "poetry", "uv"]},
        ])

    def test_the_filters_pick_the_sections(self):
        self.assertEqual(bench.plan(GRID, ids=["C-1", "B-1"]),
                         [{"section": "Gamma", "shard": "", "name": "Gamma", "needs": []}])
        self.assertEqual([e["name"] for e in bench.plan(GRID, section="alpha")], ["Alpha"])

    def test_a_job_installs_what_its_section_needs(self):
        self.assertEqual(bench.plan(GRID)[0]["needs"], ["git", "poetry", "uv"])
        self.assertEqual(bench.plan(GRID, ids=["A-1"])[0]["needs"], ["uv"])

    def test_an_unknown_id_stops_the_plan(self):
        with self.assertRaises(SystemExit) as stop:
            bench.main(["plan", "--ids", "TS-01,ts-02"])
        self.assertIn("ts-02", str(stop.exception.code))

    def test_ids_split_on_commas_and_spaces(self):
        self.assertEqual(bench.split_ids(" TS-01, RS-04 EV-07,"), ["TS-01", "RS-04", "EV-07"])

    def test_the_committed_grid_plans(self):
        for entry in bench.plan(bench.cells()):
            self.assertNotIn("/", entry["name"], "an artifact name cannot hold a slash")

    def test_a_quarantined_cell_counts_for_no_shard_and_adds_no_needs(self):
        grid = GRID + [{"id": "A-4", "section": "Alpha", "script": "true", "needs": ["pixi"],
                        "note": "Quarantined until a fix lands."},
                       {"id": "D-1", "section": "Delta", "script": "true", "note": "quarantine"}]
        self.assertEqual(bench.plan(grid, chunk=2), bench.plan(GRID, chunk=2))
        unquarantined = [dict(c, note="") for c in grid]
        self.assertIn("pixi", bench.plan(unquarantined)[0]["needs"])


class AgentPlan(unittest.TestCase):
    def test_every_cell_counts_even_with_no_script(self):
        ids = " ".join(e["ids"] for e in bench.plan(GRID, agent=True))
        self.assertEqual(ids.split(), ["A-1", "A-2", "A-3", "B-1", "C-1"])

    def test_cells_split_in_corpus_order_with_their_needs(self):
        self.assertEqual(bench.plan(GRID, chunk=2, agent=True), [
            {"name": "1-of-3", "ids": "A-1 A-2", "needs": ["git", "uv"]},
            {"name": "2-of-3", "ids": "A-3 B-1", "needs": ["poetry"]},
            {"name": "3-of-3", "ids": "C-1", "needs": []},
        ])

    def test_a_small_set_is_one_job(self):
        self.assertEqual(bench.plan(GRID, ids=["A-1", "C-1"], chunk=4, agent=True),
                         [{"name": "1-of-1", "ids": "A-1 C-1", "needs": ["uv"]}])

    def test_a_quarantined_cell_keeps_its_place_but_adds_no_needs(self):
        grid = [dict(GRID[0], needs=["pixi"], note="Quarantined until a fix lands."), GRID[1]]
        self.assertEqual(bench.plan(grid, chunk=4, agent=True),
                         [{"name": "1-of-1", "ids": "A-1 A-2", "needs": ["git", "uv"]}])

    def test_the_gate_filter_picks_cells(self):
        grid = [dict(GRID[0], gate="launch"), dict(GRID[1], gate="follows")]
        self.assertEqual(bench.plan(grid, gate="follows", agent=True)[0]["ids"], "A-2")

    def test_an_unknown_gate_stops_the_plan(self):
        with self.assertRaises(SystemExit) as stop:
            bench.main(["plan", "--agent", "--gate", "lunch"])
        self.assertIn("lunch", str(stop.exception.code))

    def test_the_committed_grid_plans_every_cell_once(self):
        entries = bench.plan(bench.cells(), chunk=4, agent=True)
        ids = [i for e in entries for i in e["ids"].split()]
        self.assertEqual(sorted(ids), sorted(c["id"] for c in bench.cells()))
        for entry in entries:
            self.assertNotIn("/", entry["name"], "an artifact name cannot hold a slash")


class WorkloadsReport(unittest.TestCase):
    ROWS = [{"id": "A-1", "verdict": "RED", "reason": "", "grade": "PASS", "grade_reason": ""},
            {"id": "B-1", "verdict": "SKIP", "reason": "needs-lived-in-image"}]

    def test_rows_follow_the_plan_and_a_missing_cell_is_named(self):
        text = bench.workloads_markdown(self.ROWS, ["A-1", "B-1", "C-1"])
        lines = [l for l in text.splitlines() if l.startswith("| ") and "Cell" not in l]
        self.assertEqual([l.split("|")[1].strip() for l in lines], ["A-1", "B-1", "C-1"])
        self.assertIn("| B-1 | SKIP | - | - | needs-lived-in-image |", text)
        self.assertIn("C-1 | - | - | - | no result", text)
        self.assertIn("RED 1", text)
        self.assertIn("PASS 1", text)
        self.assertIn("No result: 1.", text)

    def test_the_heading_names_the_agent(self):
        self.assertIn("## Workloads (Claude Code)", bench.workloads_markdown(self.ROWS, ["A-1"]))
        from io import StringIO
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "results.json").write_text(json.dumps(self.ROWS))
            buf = StringIO()
            with redirect_stdout(buf):
                bench.main(["workloads-report", root, "--agent", "kiro", "--matrix",
                            json.dumps([{"name": "1-of-1", "ids": "A-1"}])])
        self.assertIn("## Workloads (Kiro CLI)", buf.getvalue())
        self.assertNotIn("Claude Code", buf.getvalue())

    def test_the_command_reads_every_artifact_folder(self):
        with tempfile.TemporaryDirectory() as root:
            for name, rows in [("workloads-macos-1-1-of-2", self.ROWS[:1]),
                               ("workloads-macos-1-2-of-2", self.ROWS[1:])]:
                (Path(root) / name).mkdir()
                (Path(root) / name / "results.json").write_text(json.dumps(rows))
            matrix = json.dumps([{"name": "1-of-2", "ids": "A-1"}, {"name": "2-of-2", "ids": "B-1"}])
            from io import StringIO
            from contextlib import redirect_stdout
            buf = StringIO()
            with redirect_stdout(buf):
                bench.main(["workloads-report", root, "--matrix", matrix])
        self.assertIn("| A-1 | RED | PASS |", buf.getvalue())
        self.assertNotIn("no result", buf.getvalue())

    def test_one_artifact_unpacked_straight_into_the_folder_is_read(self):
        # download-artifact puts a lone matching artifact's files at the root, with no subfolder.
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "results.json").write_text(json.dumps(self.ROWS))
            from io import StringIO
            from contextlib import redirect_stdout
            buf = StringIO()
            with redirect_stdout(buf):
                bench.main(["workloads-report", root, "--matrix",
                            json.dumps([{"name": "1-of-1", "ids": "A-1 B-1"}])])
        self.assertIn("| A-1 | RED | PASS |", buf.getvalue())
        self.assertNotIn("no result", buf.getvalue())


class WorkloadsJudge(unittest.TestCase):
    ROWS = [
        {"id": "A-1", "verdict": "RED", "grade": "PASS", "grade_reason": "", "grade_by": "check",
         "judge": "PASS"},
        {"id": "B-1", "verdict": "GREEN", "grade": "FAIL", "grade_reason": "the check exited 1",
         "grade_by": "check", "judge": "PASS"},
        {"id": "C-1", "verdict": "RED", "grade": "PASS", "grade_by": "judge", "judge": "PASS",
         "grade_reason": "judge: cargo test ran and every test passed",
         "judge_evidence": "test result: ok. 12 passed | 0 failed"},
        {"id": "D-1", "verdict": "RED", "grade": "UNGRADED", "grade_by": "judge", "judge": "UNPROVEN",
         "grade_reason": "judge could not confirm it: only the agent says it worked"},
    ]

    def test_each_row_says_who_graded_it(self):
        text = bench.workloads_markdown(self.ROWS, ["A-1", "B-1", "C-1", "D-1"])
        self.assertIn("| A-1 | RED | PASS | check; judge agrees |", text)
        self.assertIn("| B-1 | GREEN | FAIL | check; judge says PASS |", text)
        self.assertIn("| C-1 | RED | PASS | judge |", text)
        self.assertIn("| D-1 | RED | UNGRADED | judge |", text)

    def test_a_judge_grade_shows_its_quote_with_the_pipe_escaped(self):
        text = bench.workloads_markdown(self.ROWS, ["C-1"])
        self.assertIn('(quote: "test result: ok. 12 passed \\| 0 failed")', text)

    def test_the_counts_say_how_often_the_judge_agrees_with_the_check(self):
        text = bench.workloads_markdown(self.ROWS, ["A-1", "B-1", "C-1", "D-1"])
        self.assertIn("Graded by a check: 2. Graded by the judge: 2.", text)
        self.assertIn("The judge agrees with the check on 1 of the 2 cells that have both.", text)

    def test_rows_without_a_judge_add_no_judge_lines(self):
        text = bench.workloads_markdown([{"id": "A-1", "verdict": "RED", "grade": "PASS",
                                          "grade_by": "check"}], ["A-1"])
        self.assertNotIn("judge", text)


class Report(unittest.TestCase):
    def test_rows_carry_their_platform_and_section(self):
        with tempfile.TemporaryDirectory() as d:
            mac = Path(d) / "cells-macos-Alpha"
            mac.mkdir()
            (mac / "results.json").write_text(json.dumps([
                {"id": "A-1", "verdict": "RED", "expect": "GREEN", "mismatch": "expected GREEN, got RED",
                 "denials": ["fs:write ~/.x|y"], "reason": "exit 1"},
                {"id": "A-3", "verdict": "SKIP", "reason": "no-scripted-commands", "mismatch": ""},
            ]))
            (Path(d) / "cells-linux-Gamma").mkdir()
            rows, missing = bench.load([mac, Path(d) / "cells-linux-Gamma"], GRID)
        self.assertEqual(missing, ["cells-linux-Gamma"])
        self.assertEqual({(r["platform"], r["section"]) for r in rows}, {("macos", "Alpha")})
        text = bench.markdown(rows, missing)
        self.assertIn("| macos | 0 | 1 | 0 | 1 | 1 |", text)
        self.assertIn("| A-1 | Alpha | macos | RED | GREEN | DIFFERS: expected GREEN, got RED | "
                      "fs:write ~/.x\\|y |", text)
        self.assertIn("1 SKIP rows", text)
        self.assertIn("No results from: cells-linux-Gamma", text)

    def test_a_job_that_left_no_artifact_is_named(self):
        with tempfile.TemporaryDirectory() as d:
            folders = bench.expected(d, bench.plan(GRID), ["macos", "linux"])
            rows, missing = bench.load(folders, GRID)
        self.assertEqual(rows, [])
        self.assertEqual(sorted(missing), ["cells-linux-Alpha", "cells-linux-Gamma",
                                           "cells-macos-Alpha", "cells-macos-Gamma"])

    def test_the_cells_with_no_script_are_listed(self):
        text = bench.markdown([], [], GRID)
        self.assertIn("2 of 5 cells have no script", text)
        self.assertIn("| A-3 | Alpha |", text)
        self.assertIn("| B-1 | Beta |", text)
        self.assertNotIn("| A-1 |", text)
        self.assertNotIn("have no script", bench.markdown([], [], [g for g in GRID if g.get("script")]))

    def test_a_named_platform_labels_a_job_folder(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "results.json").write_text(json.dumps([{"id": "C-1", "verdict": "GREEN"}]))
            rows, _ = bench.load([d], GRID, "linux")
        self.assertEqual(rows[0]["platform"], "linux")


if __name__ == "__main__":
    unittest.main()
