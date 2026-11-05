"""Check trusted receipts for two complete agents and a correlated delegation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote

from agent_program import PARENT_PROMPT, parse_final

APP = Path(__file__).resolve().parent


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def tool_content(content):
    require(isinstance(content, list) and len(content) == 1, "Expected one SDK tool-result block")
    block = content[0]
    if set(block) == {"json"}:
        value = block["json"]
    elif set(block) == {"text"}:
        value = json.loads(block["text"])
    else:
        raise ValidationError("Unexpected SDK tool-result encoding")
    require(isinstance(value, dict), "The SDK tool result must be an object")
    return value


def transcript(result, tool_name):
    messages = result["messages"]
    require(isinstance(messages, list) and messages[0]["role"] == "user", "Missing initial user message")
    uses, replies, assistants = [], [], []
    for index, message in enumerate(messages):
        if message["role"] == "assistant":
            assistants.append(index)
        for block in message["content"]:
            if "toolUse" in block:
                require(message["role"] == "assistant", "A tool use must come from the assistant")
                uses.append((index, block["toolUse"]))
            if "toolResult" in block:
                require(message["role"] == "user", "A tool result must return to the assistant")
                replies.append((index, block["toolResult"]))
    require(len(uses) == len(replies) == 1, "Expected exactly one SDK tool call and result")
    use_index, use = uses[0]
    reply_index, reply = replies[0]
    require(use["name"] == tool_name and use["input"] == {}, "Unexpected model-selected tool or arguments")
    require(isinstance(use["toolUseId"], str) and bool(use["toolUseId"])
            and use["toolUseId"] == reply["toolUseId"] and reply["status"] == "success",
            "SDK tool identifiers or status differ")
    require(use_index < reply_index < assistants[-1] == len(messages) - 1,
            "The agent did not resume after the tool result")
    final_text = "".join(block["text"] for block in messages[-1]["content"] if "text" in block)
    require(parse_final(final_text) == result["final"] == parse_final(result["final_text"]),
            "The final answer differs from the transcript")
    require(len(result["tools"]) == 1, "Expected one recorded tool operation")
    operation = result["tools"][0]
    require(operation["name"] == tool_name and operation["arguments"] == {}
            and operation["result"] == tool_content(reply["content"]), "SDK and recorded tool results differ")
    return operation, len(assistants), use["toolUseId"]


def validate(receipt, *, expected_program=None):
    try:
        return validate_receipt(receipt, expected_program)
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise ValidationError("Malformed or incomplete receipt: " + type(error).__name__) from error


def validate_receipt(receipt, expected_program):
    require(receipt["mode"] in ("baseline", "alternate"), "Unknown fixture mode")
    require(set(receipt["roles"]) == {"parent", "child"}, "Both full agents are required")
    require(receipt.get("protected_unchanged") is True and not receipt.get("error"), "The run failed its protected-file checks")
    root, program = Path(receipt["run_root"]), receipt["program"]
    require(root.is_absolute() and Path(program).is_absolute(), "Expected absolute trusted paths")
    if expected_program is not None:
        require(program == str(expected_program), "Unexpected contained agent program")
    require(receipt["program_sha256"] == hashlib.sha256((APP / "agent_program.py").read_bytes()).hexdigest(),
            "The contained program differs from this verifier's source")
    note = json.loads((APP / "fixtures/release-note.json").read_text())
    if receipt["mode"] == "alternate":
        note["release_window"] = "Thursday at 10:00 UTC"
    require(receipt["note_sha256"] == digest(note), "The fixture differs from the selected mode")
    checks, operations, tool_ids, model_counts = {}, {}, [], {}
    box_ids, run_ids, states, configs = [], [], [], []
    for role in ("parent", "child"):
        entry, work = receipt["roles"][role], root / role
        result = entry["result"]
        require(entry["returncode"] == 0 and entry.get("timed_out") is False
                and result["status"] == "complete" and not result.get("error"), role + " did not complete")
        require(result["role"] == role and result["run_id"] == receipt["run_id"], "Agent run identity differs")
        require(entry["started_at"] < entry["ended_at"], "Invalid agent interval")
        require(entry["config"] == str(root / "trusted" / role / "box.toml"), "Unexpected child configuration path")
        require(entry["command"][1:] == ["-I", "-B", program, "--job", str(work / "in/job.json")]
                and Path(entry["command"][0]).is_absolute(), "Unexpected contained command")
        state = Path(entry["state"])
        require(state.is_absolute() and state.name == "state" and state.parent.name == role
                and root not in state.parents, "Box state must be separate from agent files")
        box_ids.append(entry["box_id"])
        run_ids.append(entry["box_run_id"])
        states.append(str(state))
        configs.append(entry["config"])
        require(re.fullmatch(r"box-[0-9a-f]{16}", entry["box_id"]) is not None
                and isinstance(entry["box_run_id"], str) and bool(entry["box_run_id"]), "Invalid native Box identity")
        tool_name = "review_release" if role == "parent" else "read_release_note"
        operation, count, tool_id = transcript(result, tool_name)
        operations[role], model_counts[role] = operation, count
        tool_ids.append(tool_id)
        require(2 <= count <= 4 and result["model_calls"] == result["model_responses"] == count,
                "Model calls, responses, and transcript differ")
        require(result["usage"].get("inputTokens", 0) > 0 and result["usage"].get("outputTokens", 0) > 0,
                "Missing model token usage")
        require(entry["started_at"] <= operation["started_at"] < operation["ended_at"] <= entry["ended_at"],
                "Tool interval is outside its agent")
        host = "bedrock-runtime." + result["region"] + ".amazonaws.com"
        events = [event for event in entry["decisions"]
                  if event.get("strands.box.policy.action") == "http:request" and event.get("server.address") == host]
        require(len(events) == count, "Native model request count differs from model loops")
        resource = host + ":443/model/" + quote(result["model_id"], safe="") + "/converse-stream"
        request_ids, times = [], []
        for event in events:
            require(all(event.get(key) == value for key, value in {
                "box_id": entry["box_id"], "box_run_id": entry["box_run_id"],
                "strands.box.policy.principal": "agent:self", "strands.box.policy.verdict": "permit",
                "server.port": 443, "http.request.method": "POST", "strands.box.policy.resource": resource,
            }.items()), "Native model decision differs from this agent's request")
            timestamp = event["timestamp_ns"] / 1e9
            require(entry["started_at"] <= timestamp <= entry["ended_at"], "Native decision is outside the agent interval")
            times.append(timestamp)
            request_ids.append(event["strands.box.request.id"])
        require(all(request_ids) and len(set(request_ids)) == count, "Model request identifiers are missing or repeated")
        require(min(times) < operation["started_at"] and max(times) > operation["ended_at"],
                "No native model request after the tool result")
        other = "child" if role == "parent" else "parent"
        other_input = "release-note.json" if other == "child" else "parent-only.txt"
        expected_probes = {
            "own_input": ("read", str(work / "in/job.json"), True),
            "own_output": ("write", str(work / "out/control.txt"), True),
            "other_input": ("read", str(root / other / "in" / other_input), False),
            "other_output": ("write", str(root / other / "out/private.txt"), False),
            "trusted_input": ("read", str(root / "trusted/private.txt"), False),
            "box_execute": ("execute", receipt["box_binary"], False),
        }
        probes = {item["name"]: item for item in result["probes"]}
        require(len(result["probes"]) == len(probes) and set(probes) == set(expected_probes), "Missing or repeated native probe")
        for name, (kind, path, allowed) in expected_probes.items():
            probe = probes[name]
            require((probe["kind"], probe["path"], probe["allowed"], probe["success"]) == (kind, path, allowed, allowed),
                    "Native boundary probe differs from its expected result")
            if not allowed:
                require(probe["errno"] in (1, 2, 13), "The refused probe failed for an unrelated reason")
                target = entry["probe_targets"][name]
                require(target == {"path": path, "kind": kind, "existed": True, "control": True},
                        "Refused native target lacks its trusted positive control")
        checks[role + "_full_model_loop"] = True
        checks[role + "_native_file_boundaries"] = True
    require(all(len(set(values)) == 2 for values in (box_ids, run_ids, states, configs, tool_ids)),
            "The agents do not have distinct identities")
    parent, child = receipt["roles"]["parent"], receipt["roles"]["child"]
    require(parent["started_at"] < child["started_at"] < child["ended_at"] < parent["ended_at"], "Child lifetime is outside the parent")
    require(parent["result"]["messages"][0]["content"] == [{"text": PARENT_PROMPT}], "Parent prompt differs across fixture modes")
    require(operations["child"]["result"] == {"status": "ok", "note": note}, "The child did not read the selected note")
    child_final = child["result"]["final"]
    require(all(child_final[key] == note[key] for key in ("project", "release_window")), "Child answer differs from its input")
    require(len(receipt["delegations"]) == 1, "Expected one trusted delegation")
    delegation = receipt["delegations"][0]
    identifier = delegation["delegation_id"]
    require(isinstance(identifier, str) and re.fullmatch(r"[a-f0-9]{32}", identifier) is not None, "Invalid delegation identifier")
    envelope = {"status": "ok", "delegation_id": identifier, "child_role": "child",
                "child_result": child_final, "child_result_sha256": digest(child_final)}
    operation = operations["parent"]
    require(delegation["envelope"] == operation["result"] == envelope
            and operation["delegation_id"] == identifier, "Parent result differs from the completed child")
    require(operation["started_at"] <= delegation["started_at"] <= delegation["child_started_at"]
            <= child["started_at"] < child["ended_at"] <= delegation["child_ended_at"]
            <= delegation["ended_at"] <= operation["ended_at"], "Delegation timestamps do not nest")
    broker_events = [event for event in parent["decisions"]
                     if event.get("strands.box.policy.action") == "http:request"
                     and event.get("server.address") == "127.0.0.1"]
    require(len(broker_events) == 1, "Expected one native delegation request")
    event = broker_events[0]
    require(all(event.get(key) == value for key, value in {
        "box_id": parent["box_id"], "box_run_id": parent["box_run_id"],
        "strands.box.policy.principal": "agent:self", "strands.box.policy.verdict": "permit",
        "server.port": receipt["broker_port"], "http.request.method": "POST",
        "strands.box.policy.resource": "127.0.0.1:" + str(receipt["broker_port"]) + "/delegate/review",
    }.items()) and bool(event.get("strands.box.request.id")), "Native delegation decision differs")
    require(operation["started_at"] <= event["timestamp_ns"] / 1e9 <= operation["ended_at"],
            "Native delegation request is outside the parent tool call")
    require(receipt["parent_final"] == parent["result"]["final"] and all(
        receipt["parent_final"][key] == child_final[key] for key in ("project", "release_window")),
        "Parent answer does not preserve the child's release fact")
    checks.update(independent_boxes=True, exact_child_result=True, parent_continued=True,
                  selected_fixture=True, protected_files_unchanged=True)
    return {"verified": True, "checks": checks, "run_id": receipt["run_id"],
            "mode": receipt["mode"], "model_responses": model_counts,
            "scope": "Trusted receipt consistency; not attestation or isolation qualification"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--expected-program")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(json.loads(args.receipt.read_text()), expected_program=args.expected_program)))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
