"""Hermetic tests for the judge (judge.py). No model is called: the transport is faked."""
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path

import judge


def stream(*events):
    return "\n".join(json.dumps(e) for e in events)


def bash(command, output, error=False, n=1):
    return (
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": f"t{n}", "name": "Bash", "input": {"command": command}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": f"t{n}", "content": output, "is_error": error}]}},
    )


def said(text):
    return {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.work = self.root / "work"
        self.work.mkdir()

    def test_new_changed_and_deleted_files_are_listed_with_a_diff(self):
        (self.work / "keep.js").write_text("a\nb\n")
        (self.work / "gone.txt").write_text("x\n")
        before = judge.snapshot(self.work)
        (self.work / "keep.js").write_text("a\nB\n")
        (self.work / "gone.txt").unlink()
        (self.work / "new.sql").write_text("select 1;\n")
        text = judge.changes(before, judge.snapshot(self.work))
        self.assertIn("New files (1): new.sql", text)
        self.assertIn("Deleted files (1): gone.txt", text)
        self.assertIn("Changed files (1): keep.js", text)
        self.assertIn("-b", text)
        self.assertIn("+B", text)
        self.assertIn("+select 1;", text)

    def test_no_change_says_so(self):
        (self.work / "a").write_text("1")
        snap = judge.snapshot(self.work)
        self.assertEqual(judge.changes(snap, judge.snapshot(self.work)),
                         "The agent changed no files in the workspace.")

    def test_a_link_out_of_the_workspace_is_never_read(self):
        # The agent can make a link to a file it cannot read; the host must not read it for it.
        secret = self.root / "secret.txt"
        secret.write_text("HOST-SECRET-VALUE\n")
        before = judge.snapshot(self.work)
        os.symlink(secret, self.work / "creds")
        os.symlink(self.root, self.work / "up")
        text = judge.changes(before, judge.snapshot(self.work))
        self.assertNotIn("HOST-SECRET-VALUE", text)
        self.assertIn(f"creds is a link to {secret}", text)
        self.assertIn(f"up is a link to {self.root}", text)

    def test_a_file_with_a_second_hard_link_is_never_read(self):
        outside = self.root / "outside.txt"
        outside.write_text("HARD-LINKED-VALUE\n")
        before = judge.snapshot(self.work)
        os.link(outside, self.work / "inside.txt")
        text = judge.changes(before, judge.snapshot(self.work))
        self.assertNotIn("HARD-LINKED-VALUE", text)
        self.assertIn("inside.txt: hardlink file, not shown", text)

    def test_package_folders_are_listed_not_read(self):
        before = judge.snapshot(self.work)
        (self.work / "node_modules" / "x").mkdir(parents=True)
        (self.work / "node_modules" / "x" / "index.js").write_text("module.exports = 1\n")
        text = judge.changes(before, judge.snapshot(self.work))
        self.assertIn("New folders, listed but not read (1): node_modules", text)
        self.assertNotIn("module.exports", text)

    def test_a_binary_file_is_named_not_shown(self):
        before = judge.snapshot(self.work)
        (self.work / "app.db").write_bytes(b"SQLite\0\1\2")
        text = judge.changes(before, judge.snapshot(self.work))
        self.assertIn("app.db: file file, not shown", text)

    def test_the_changes_are_cut_to_the_limit(self):
        before = judge.snapshot(self.work)
        (self.work / "big.txt").write_text("line\n" * 100)
        text = judge.changes(before, judge.snapshot(self.work), limit=200)
        self.assertLess(len(text), 300)
        self.assertIn("were cut to fit", text)

    def test_a_missing_workspace_is_an_empty_snapshot(self):
        snap = judge.snapshot(self.root / "nope")
        self.assertEqual(snap["files"], {})


class Steps(unittest.TestCase):
    def test_stream_json_becomes_tool_calls_outputs_and_words(self):
        log = "box: running profile claude (records: /x)\n" + stream(
            said("Let me run the tests."),
            *bash("pnpm test", "Tests  3 passed (3)"),
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t9",
                                                        "content": [{"type": "text", "text": "listed"}]}]}},
            {"type": "result", "subtype": "success", "result": "All fixed."})
        events, other = judge.parse_stream(log)
        self.assertEqual(other, ["box: running profile claude (records: /x)"])
        got = [(s["kind"], s["text"]) for s in judge.steps(events)]
        self.assertEqual(got, [("said", "Let me run the tests."), ("ran", "Bash: pnpm test"),
                               ("output", "Tests  3 passed (3)"), ("output", "listed"),
                               ("final", "All fixed.")])

    def test_an_edit_names_its_file(self):
        events = [{"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Edit", "input": {"file_path": "/w/a.js", "old_string": "x"}}]}}]
        self.assertTrue(judge.steps(events)[0]["text"].startswith("Edit: /w/a.js"))

    def test_plain_output_is_the_agents_words_without_the_box_lines(self):
        other = ["strands-box: [agent] runs /bin/bash with no policy decision over these paths:",
                 "  read        /usr/lib", "  write       /dev/null",
                 "box: running profile claude (records: /x)",
                 "The formatPrice test passes now."]
        self.assertEqual(judge.plain_steps(other),
                         [{"kind": "final", "text": "The formatPrice test passes now."}])

    def test_coded_box_lines_from_every_source_are_not_the_agents_words(self):
        other = ["strands-box: note[B0201]: [agent] runs /bin/bash with no policy decision over these paths:",
                 "  read        /usr/lib",
                 "strands-box-sock-alias: error[H0302]: ./build.sh: Permission denied",
                 "strands-box-contain-trampoline: error[H0401]: apply sandbox: Operation not permitted",
                 "policy: warning[P0201]: dogwood evaluation failed: x; denying",
                 "telemetry: warning[T0101]: the collector stopped",
                 "The build passes now."]
        self.assertEqual(judge.plain_steps(other),
                         [{"kind": "final", "text": "The build passes now."}])

    def test_kiro_stream_json_becomes_tool_calls_outputs_and_words(self):
        # The event shapes kiro-cli 3.4.0 prints with --output-format stream-json.
        def update(**u):
            return {"type": "sessionUpdate", "data": {"sessionId": "s", "update": u}}
        def text(t):
            return [{"type": "content", "content": {"type": "text", "text": t}}]
        events = [
            {"type": "runStarted", "data": {"payloadSchema": "acp", "engine": "v3"}},
            update(sessionUpdate="agent_message_chunk", content={"type": "text", "text": "Let me "}),
            update(sessionUpdate="agent_message_chunk", content={"type": "text", "text": "test."}),
            update(sessionUpdate="tool_call", toolCallId="c1", title="Run Command", kind="execute",
                   rawInput={"command": "pnpm test"}),
            update(sessionUpdate="tool_call_update", toolCallId="c1", status="in_progress",
                   rawInput={"command": "pnpm test"}),
            update(sessionUpdate="tool_call_update", toolCallId="c1", status="completed",
                   content=text("Output:\nTests  3 passed (3)\n\nExit Code: 0")),
            update(sessionUpdate="tool_call", toolCallId="c2", title="Write File", kind="edit",
                   rawInput={"path": "/w/a.js", "text": "x"}),
            update(sessionUpdate="tool_call_update", toolCallId="c2", status="completed",
                   content=[{"type": "diff", "path": "file:///w/a.js", "oldText": "", "newText": "x"}]),
            update(sessionUpdate="tool_call", toolCallId="c3", title="Run Command", kind="execute",
                   rawInput={"command": "false"}),
            update(sessionUpdate="tool_call_update", toolCallId="c3", status="failed",
                   content=text("Exit Code: 1")),
            update(sessionUpdate="tool_call", toolCallId="c4", title="Subagent", kind="other",
                   rawInput={"task": "check it"}),
            update(sessionUpdate="tool_call_update", toolCallId="c4", status="completed",
                   content=text("It works.")),
            update(sessionUpdate="agent_message_chunk", content={"type": "text", "text": "Done."}),
            {"type": "runFinished", "data": {"status": "success", "finalText": "Done."}}]
        got = [(s["kind"], s["text"], s.get("error")) for s in judge.steps(events)]
        self.assertEqual(got, [
            ("said", "Let me test.", None),
            ("ran", "Run Command: pnpm test", None),
            ("output", "Output:\nTests  3 passed (3)\n\nExit Code: 0", False),
            ("ran", "Write File: /w/a.js  (the file changes below show the result)", None),
            ("ran", "Run Command: false", None),
            ("output", "Exit Code: 1", True),
            ("ran", 'Subagent: {"task": "check it"}', None),
            ("report", "It works.", None),
            ("final", "Done.", None)])
        record, proof, claims = judge.build_record(
            "\n".join(json.dumps(e) for e in events), "")
        self.assertIn("Tests  3 passed (3)", proof)
        self.assertNotIn("It works.", proof)


class Record(unittest.TestCase):
    def test_tool_output_and_file_changes_are_proof_and_words_are_claims(self):
        log = stream(said("I will check."), *bash("pnpm test", "Tests  3 passed"),
                     {"type": "result", "result": "Done, it passes."})
        record, proof, claims = judge.build_record(log, "Changed files (1): a.js", ["policy denied: x"])
        self.assertIn("Tests  3 passed", proof)
        self.assertIn("Changed files (1): a.js", proof)
        self.assertIn("policy denied: x", proof)
        self.assertNotIn("Bash: pnpm test", proof)
        self.assertNotIn("Done, it passes.", proof)
        self.assertIn("Done, it passes.", claims)
        self.assertIn("I will check.", claims)
        for part in ("Tests  3 passed", "Done, it passes.", "a claim, not proof"):
            self.assertIn(part, record)

    def test_a_long_run_keeps_its_first_and_last_steps(self):
        events = [e for n in range(60) for e in bash(f"step {n}", "out " * 200, n=n)]
        record, _, _ = judge.build_record(stream(*events), "", limit=20_000)
        self.assertIn("Bash: step 0", record)
        self.assertIn("Bash: step 59", record)
        self.assertIn("steps in the middle are not shown", record)
        self.assertNotIn("Bash: step 30", record)

    def test_a_long_output_keeps_its_end(self):
        out = "noise\n" * 2000 + "Tests  9 passed"
        record, _, _ = judge.build_record(stream(*bash("pnpm test", out)), "")
        self.assertIn("Tests  9 passed", record)
        self.assertIn("characters not shown", record)

    def test_a_run_with_no_record_says_so(self):
        record, _, _ = judge.build_record("", "The agent changed no files in the workspace.")
        self.assertIn("left no record", record)


class Settle(unittest.TestCase):
    PROOF = "== Step 2: that tool's output ==\nTests  3 passed (3)\nDuration 1.2s"
    CLAIMS = "== The agent's final message ==\nAll tests pass now."

    def answer(self, verdict, evidence, reason="why"):
        return {"verdict": verdict, "evidence": evidence, "reason": reason}

    def test_a_pass_whose_quote_is_in_the_proof_stands(self):
        got = judge.settle(self.answer("PASS", "Tests  3 passed (3)"), self.PROOF, self.CLAIMS)
        self.assertEqual(got["verdict"], judge.PASS)

    def test_a_quote_with_different_spacing_still_matches(self):
        got = judge.settle(self.answer("PASS", "Tests 3 passed (3)\n Duration 1.2s"), self.PROOF, self.CLAIMS)
        self.assertEqual(got["verdict"], judge.PASS)

    def test_a_pass_that_quotes_only_the_agents_words_is_unproven(self):
        got = judge.settle(self.answer("PASS", "All tests pass now."), self.PROOF, self.CLAIMS)
        self.assertEqual(got["verdict"], judge.UNPROVEN)
        self.assertEqual(got["model_verdict"], judge.PASS)
        self.assertIn("only the agent's own words", got["reason"])

    def test_a_pass_whose_quote_is_not_in_the_record_is_unproven(self):
        got = judge.settle(self.answer("PASS", "Tests 4 passed"), self.PROOF, self.CLAIMS)
        self.assertEqual(got["verdict"], judge.UNPROVEN)
        self.assertIn("not whole lines", got["reason"])

    def test_a_fragment_lifted_from_a_failing_line_is_unproven(self):
        proof = "== Step 2: that tool's output ==\n1 failed, 3 passed in 0.2s"
        got = judge.settle(self.answer("PASS", "3 passed"), proof, "")
        self.assertEqual(got["verdict"], judge.UNPROVEN)

    def test_the_command_the_agent_typed_is_not_proof(self):
        log = stream(*bash("uv run pytest -q", "1 failed, 3 passed in 0.2s"),
                     {"type": "result", "result": "All tests pass now."})
        _, proof, claims = judge.build_record(log, "The agent changed no files in the workspace.")
        for quote in ("Bash: uv run pytest -q", "All tests pass now."):
            got = judge.settle(self.answer("PASS", quote), proof, claims)
            self.assertEqual(got["verdict"], judge.UNPROVEN, quote)

    def test_a_diff_line_counts_with_or_without_its_sign(self):
        proof = "== Files the agent changed ==\n+++ b/a.js\n+  return (cents / 100).toFixed(2);"
        for quote in ("+  return (cents / 100).toFixed(2);", "return (cents / 100).toFixed(2);"):
            self.assertEqual(judge.settle(self.answer("PASS", quote), proof, "")["verdict"], judge.PASS, quote)

    def test_a_section_header_is_not_proof(self):
        got = judge.settle(self.answer("PASS", "== Step 2: that tool's output =="), self.PROOF, "")
        self.assertEqual(got["verdict"], judge.UNPROVEN)

    def test_the_prompt_asks_for_every_part_of_the_condition(self):
        self.assertIn("every part of the success condition", judge.SYSTEM)
        self.assertIn("UNPROVEN", judge.SYSTEM)

    def test_a_subagents_report_is_a_claim_but_its_own_tool_output_is_proof(self):
        log = stream(
            {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "a1", "name": "Task",
                                                           "input": {"prompt": "Run pytest and report"}}]}},
            *bash("pytest", "12 passed in 0.4s", n=2),  # the subagent's own call, streamed as its own events
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "a1",
                                                      "content": "I ran the suite.\nAll 12 tests passed with no failures."}]}})
        record, proof, claims = judge.build_record(log, "")
        self.assertIn("a subagent's report (a claim, not proof)", record)
        self.assertEqual(judge.settle(self.answer("PASS", "All 12 tests passed with no failures."),
                                      proof, claims)["verdict"], judge.UNPROVEN)
        self.assertEqual(judge.settle(self.answer("PASS", "12 passed in 0.4s"), proof, claims)["verdict"],
                         judge.PASS)

    def test_a_cut_long_output_leaves_no_partial_line_to_quote(self):
        # Put the tail's start inside `===== 1 failed, 3 passed in 12.4s =====`, so an unsnapped cut
        # would leave the line ` 3 passed in 12.4s =====`.
        last = "===== 1 failed, 3 passed in 12.4s ====="
        partial = last[len("===== 1 failed,"):]
        out = "x" * 5000 + "\n" + last + "\n" + "y" * (judge.OUTPUT_TAIL - len(partial) - 1)
        self.assertEqual(out[-judge.OUTPUT_TAIL:].split("\n")[0], partial)
        _, proof, _ = judge.build_record(stream(*bash("pytest", out)), "")
        self.assertNotIn(judge._norm(partial), {judge._norm(l) for l in proof.splitlines()})
        self.assertEqual(judge.settle(self.answer("PASS", partial), proof, "")["verdict"], judge.UNPROVEN)

    def test_cut_snaps_to_whole_lines(self):
        text = "\n".join(f"line {n:04d}" for n in range(1000))
        cut = judge._cut(text, 100, 100)
        kept = [l for l in cut.splitlines() if "characters not shown" not in l]
        self.assertTrue(all(l.startswith("line ") and len(l) == 9 for l in kept), kept)
        self.assertIn("line 0000", cut)
        self.assertIn("line 0999", cut)

    def test_a_pass_with_no_real_quote_is_unproven(self):
        got = judge.settle(self.answer("PASS", "ok"), self.PROOF, self.CLAIMS)
        self.assertEqual(got["verdict"], judge.UNPROVEN)

    def test_fail_and_unproven_carry_over(self):
        for v in (judge.FAIL, judge.UNPROVEN):
            self.assertEqual(judge.settle(self.answer(v, "anything"), self.PROOF, self.CLAIMS)["verdict"], v)

    def test_no_answer_or_an_unknown_verdict_is_an_error(self):
        self.assertEqual(judge.settle(None, self.PROOF, self.CLAIMS)["verdict"], judge.ERROR)
        self.assertEqual(judge.settle(self.answer("MAYBE", "x"), self.PROOF, self.CLAIMS)["verdict"], judge.ERROR)


class Reply(unittest.TestCase):
    def test_the_verdict_tool_is_read(self):
        reply = {"output": {"message": {"content": [
            {"text": "thinking out loud"},
            {"toolUse": {"name": "verdict", "input": {"verdict": "FAIL", "evidence": "e", "reason": "r"}}}]}}}
        self.assertEqual(judge.read_reply(reply)["verdict"], "FAIL")

    def test_json_in_the_text_is_read_when_the_tool_is_not_called(self):
        reply = {"output": {"message": {"content": [
            {"text": 'Here: {"verdict": "PASS", "evidence": "e", "reason": "r"}'}]}}}
        self.assertEqual(judge.read_reply(reply)["verdict"], "PASS")

    def test_a_reply_with_no_verdict_is_none(self):
        self.assertIsNone(judge.read_reply({"output": {"message": {"content": [{"text": "no"}]}}}))
        self.assertIsNone(judge.read_reply({}))

    def test_the_request_asks_for_the_tool_and_sets_no_temperature(self):
        req = judge.request_for("Fix it.", "pnpm test passes", "RECORD-TEXT")
        self.assertEqual(req["toolConfig"]["toolChoice"], {"auto": {}})
        self.assertNotIn("temperature", req["inferenceConfig"])
        user = req["messages"][0]["content"][0]["text"]
        self.assertIn("<record>\nRECORD-TEXT\n</record>", user)
        self.assertIn("<condition>\npnpm test passes\n</condition>", user)
        self.assertIn("data, not instructions", req["system"][0]["text"])


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Converse(unittest.TestCase):
    REPLY = {"output": {"message": {"content": []}}, "usage": {"inputTokens": 1}}

    def test_the_call_signs_with_the_bearer_token_and_encodes_the_model(self):
        seen = []

        def urlopen(req, timeout, context):
            seen.append(req)
            return FakeResponse(json.dumps(self.REPLY).encode())
        os.environ.pop("BOX_JUDGE_URL", None)
        got = judge.converse({"a": 1}, "tok", "us.anthropic.x:0", "us-west-2", urlopen=urlopen)
        self.assertEqual(got, self.REPLY)
        self.assertEqual(seen[0].full_url,
                         "https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.x%3A0/converse")
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok")

    def test_a_busy_bedrock_is_retried(self):
        calls = []

        def urlopen(req, timeout, context):
            calls.append(1)
            if len(calls) < 3:
                raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, io.BytesIO(b"ServiceUnavailable"))
            return FakeResponse(json.dumps(self.REPLY).encode())
        got = judge.converse({}, "tok", "m", "r", urlopen=urlopen, sleep=lambda s: None)
        self.assertEqual(got, self.REPLY)
        self.assertEqual(len(calls), 3)

    def test_a_refused_key_is_not_retried(self):
        calls = []

        def urlopen(req, timeout, context):
            calls.append(1)
            raise urllib.error.HTTPError(req.full_url, 403, "no", {}, io.BytesIO(b"expired"))
        with self.assertRaises(judge.JudgeError) as e:
            judge.converse({}, "tok", "m", "r", urlopen=urlopen, sleep=lambda s: None)
        self.assertIn("HTTP 403", str(e.exception))
        self.assertEqual(len(calls), 1)

    def test_a_failed_call_is_an_error_verdict_not_a_crash(self):
        def call(*a):
            raise judge.JudgeError("HTTP 403: expired")
        got = judge.judge("t", "c", "r", "p", "c", "tok", call=call)
        self.assertEqual(got["verdict"], judge.ERROR)
        self.assertIn("HTTP 403", got["reason"])

    def test_judge_settles_the_reply_and_keeps_the_usage(self):
        reply = {"output": {"message": {"content": [{"toolUse": {"name": "verdict", "input": {
            "verdict": "PASS", "evidence": "Tests  3 passed", "reason": "tests ran"}}}]}},
            "usage": {"inputTokens": 42}}
        got = judge.judge("t", "c", "r", "Tests  3 passed", "", "tok", call=lambda *a: reply)
        self.assertEqual(got["verdict"], judge.PASS)
        self.assertEqual(got["usage"], {"inputTokens": 42})


if __name__ == "__main__":
    unittest.main()
