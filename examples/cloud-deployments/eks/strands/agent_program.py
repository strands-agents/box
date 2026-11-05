"""Run one Strands agent inside its own Box."""
import argparse
import errno
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit
import uuid

MAX_BYTES = 65536
PARENT_PROMPT = "Ask the release reviewer for the project release note, then report its release window."
PROMPTS = {
    "parent": "Call review_release exactly once. Use its child_result to answer. ",
    "child": "Call read_release_note exactly once. Summarize the returned project release note. ",
}
FINAL_INSTRUCTION = (
    'Return only JSON {"project":"...","release_window":"...","summary":"..."}. '
    'Copy project and release_window exactly from the tool result. '
    'If the tool fails, return {"status":"error","error":"..."} instead of guessing.'
)


def json_object(text):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def parse_final(text):
    text = text.strip()
    try:
        value = json_object(text)
    except json.JSONDecodeError:
        match = re.fullmatch(r"(.*?)```(?:json)?[ \t]*\r?\n(.*?)\r?\n```", text, re.DOTALL)
        if text.count("```") != 2 or match is None:
            raise ValueError("Expected plain JSON or one final JSON fence")
        prefix, body = match.groups()
        if prefix and not prefix.endswith("\n"):
            raise ValueError("The JSON fence must start on its own line")
        decoder = json.JSONDecoder()
        for index, character in enumerate(prefix):
            if character in "{[":
                try:
                    previous, _ = decoder.raw_decode(prefix[index:])
                except json.JSONDecodeError:
                    continue
                if isinstance(previous, (dict, list)):
                    raise ValueError("Competing JSON answers")
        value = json_object(body)
    if set(value) != {"project", "release_window", "summary"} or any(
        not isinstance(item, str) or not item.strip() for item in value.values()
    ):
        raise ValueError("The agent did not return the success schema")
    return value


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds the size limit")
    return json_object(data)


def boundary_probes(probes):
    results = []
    for item in probes:
        success, error = False, None
        try:
            if item["kind"] == "read":
                with open(item["path"], "rb") as stream:
                    stream.read(1)
            elif item["kind"] == "write":
                with open(item["path"], "ab") as stream:
                    stream.write(b"Synthetic permitted write.\n")
            elif item["kind"] == "execute":
                subprocess.run([item["path"], "--version"], timeout=5, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                raise ValueError("Unknown probe kind")
            success = True
        except subprocess.TimeoutExpired:
            error = errno.ETIMEDOUT
        except OSError as exc:
            error = exc.errno
        results.append({**item, "success": success, "errno": error})
    return results


class Tools:
    def __init__(self, root, job):
        self.root, self.job, self.records = root, job, []

    def call(self, name, operation):
        row = {"name": name, "arguments": {}, "started_at": time.time()}
        self.records.append(row)
        try:
            if len(self.records) != 1:
                raise ValueError("The example permits one tool call per agent")
            value = operation()
        except Exception as error:
            value = {"status": "error", "error": {"type": type(error).__name__,
                                                     "message": "The tool did not complete"}}
        row.update(ended_at=time.time(), result=value)
        return json.dumps(value, separators=(",", ":"))

    def read_release_note(self) -> str:
        """Read the release note from this agent's fixed input file."""
        return self.call("read_release_note", lambda: {
            "status": "ok", "note": read_json(self.root / "in/release-note.json")})

    def review_release(self) -> str:
        """Ask a separate, fixed child agent to review the release note."""
        return self.call("review_release", self.delegate)

    def delegate(self):
        broker = urlsplit(self.job["broker_url"])
        proxy = urlsplit(os.environ.get("HTTP_PROXY", ""))
        if (broker.scheme != "http" or broker.hostname != "127.0.0.1" or not broker.port
                or broker.path or broker.query or broker.fragment or broker.username
                or proxy.scheme != "http" or not proxy.hostname or not proxy.port):
            raise ValueError("Expected the trusted broker and Box HTTP proxy")
        delegation_id = uuid.uuid4().hex
        self.records[-1]["delegation_id"] = delegation_id
        connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=180)
        try:
            connection.request("POST", self.job["broker_url"] + "/delegate/review", "{}", headers={
                "Host": broker.netloc, "Content-Type": "application/json",
                "X-Delegation-Id": delegation_id, "Connection": "close"})
            response = connection.getresponse()
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES or not 200 <= response.status < 300:
                raise ValueError("The delegation response failed")
            declared = response.getheader("Content-Length")
            if declared is not None and int(declared) != len(body):
                raise ValueError("Incomplete delegation response")
            envelope = json_object(body)
            if (envelope.get("delegation_id") != delegation_id or envelope.get("child_role") != "child"
                    or envelope.get("status") not in ("ok", "error")):
                raise ValueError("The delegation response does not match")
            return envelope
        finally:
            connection.close()


class ModelBudget:
    def __init__(self):
        self.calls, self.responses = 0, 0

    def register_hooks(self, registry):
        from strands.hooks import BeforeModelCallEvent, AfterModelCallEvent
        registry.add_callback(BeforeModelCallEvent, self.before)
        registry.add_callback(AfterModelCallEvent, self.after)

    def before(self, event):
        if self.calls >= 4:
            raise RuntimeError("The example model-call budget is exhausted")
        self.calls += 1

    def after(self, event):
        if event.exception is None and event.stop_response is not None:
            self.responses += 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.job.is_absolute() or args.job.name != "job.json" or args.job.parent.name != "in":
        parser.error("Use an absolute path ending in in/job.json")
    job = read_json(args.job)
    role = job["role"]
    if role not in PROMPTS:
        parser.error("Unknown agent role")
    root = args.job.parent.parent
    tools, budget, agent = Tools(root, job), ModelBudget(), None
    result = {"run_id": job["run_id"], "role": role, "model_id": job["model_id"],
              "region": job["region"], "status": "error", "messages": [], "tools": tools.records,
              "usage": {}, "probes": [], "final": None}
    try:
        result["probes"] = boundary_probes(job["probes"])
        from strands import Agent, tool
        from strands.models import BedrockModel
        from strands.tools.executors import SequentialToolExecutor
        from botocore.config import Config
        model = BedrockModel(model_id=job["model_id"], region_name=job["region"], temperature=0,
                             max_tokens=800, boto_client_config=Config(connect_timeout=10,
                                 read_timeout=45, retries={"total_max_attempts": 1}))
        selected = tools.review_release if role == "parent" else tools.read_release_note
        agent = Agent(model=model, system_prompt=PROMPTS[role] + FINAL_INSTRUCTION,
                      tools=[tool(selected)], tool_executor=SequentialToolExecutor(),
                      hooks=[budget], callback_handler=None, retry_strategy=None, context_manager=False)
        answer = agent(PARENT_PROMPT if role == "parent" else "Review your release note.")
        result.update(final_text=str(answer), final=parse_final(str(answer)),
                      usage=dict(answer.metrics.accumulated_usage))
        if len(tools.records) != 1 or tools.records[0]["result"].get("status") != "ok":
            raise ValueError("The required tool did not succeed")
        result["status"] = "complete"
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": "The contained agent did not complete"}
    finally:
        if agent is not None:
            result["messages"] = agent.messages
        result.update(model_calls=budget.calls, model_responses=budget.responses)
        (root / "out/result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
