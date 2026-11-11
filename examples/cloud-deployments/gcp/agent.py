"""Run a fixed deployment exercise through Strands and Google Gemini under Box."""
import asyncio
import json
import os
from pathlib import Path
import ssl
import sys

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"
if VENDOR.is_dir():
    sys.path.insert(0, str(VENDOR))
sys.path.insert(0, str(HERE.parent / "eks" / "claude"))

import httpx
from google import genai
from google.genai import types
from google.oauth2.credentials import Credentials
from strands import Agent, tool
from strands.models.gemini import GeminiModel
from strands.tools.executors import SequentialToolExecutor

from deployment_tools import endpoint, request

PHASES = (
    ("deployment_status", "Read the synthetic service status before deployment."),
    ("deploy_checkout", "Make the first synthetic deployment attempt."),
    ("deploy_checkout", "Make the second synthetic deployment attempt."),
    ("deploy_checkout", "Make the third synthetic deployment attempt."),
    ("deploy_checkout", "Try once more to test the deployment retry restriction."),
    ("deployment_status", "Read diagnostics while the deployment cooldown is active."),
    ("deploy_checkout", "Test the retry restriction once more, then stop deploying."),
)
SYSTEM_PROMPT = (
    "You are checking a failed checkout-service release in a synthetic environment. "
    "Follow each requested phase and call its named tool exactly once. "
    "These deliberate retries test an operator policy enforced outside this agent. "
    "The policy pauses deployments for ten minutes after three failures within five minutes. "
    "Do not change the policy, seek another route, or wait for the cooldown to expire. "
    "Report only observed tool results."
)


def make_client(environment):
    """Use the Box proxy, certificate, and credential placeholder for Google requests."""
    proxy = environment["HTTPS_PROXY"]
    endpoint(proxy, {"127.0.0.1", "localhost"})
    placeholder = environment["GOOGLE_TOKEN"]
    if not placeholder.startswith("strands_box_"):
        raise ValueError("GOOGLE_TOKEN must contain a Box credential placeholder")
    context = ssl.create_default_context(cafile=environment["SSL_CERT_FILE"])
    options = {"proxy": proxy, "verify": context, "trust_env": False, "timeout": 45}
    return genai.Client(
        vertexai=True,
        project=environment["GOOGLE_CLOUD_PROJECT"],
        location=environment["GOOGLE_CLOUD_LOCATION"],
        credentials=Credentials(token=placeholder, expiry=None),
        http_options=types.HttpOptions(
            api_version="v1", timeout=45000,
            retry_options=types.HttpRetryOptions(attempts=1),
            httpx_client=httpx.Client(**options),
            httpx_async_client=httpx.AsyncClient(**options),
        ),
    )


def deployment_tools(service_url, receipts):
    """Return two model tools that use the shared Box HTTP request implementation."""
    endpoint(service_url, {"127.0.0.1"})

    def perform(name, method, path):
        result = request(service_url, method, path)
        receipts.append({"name": name, **result})
        return json.dumps(result)

    @tool
    def deploy_checkout() -> str:
        """Request a synthetic checkout deployment."""
        return perform("deploy_checkout", "POST", "/deployments/checkout")

    @tool
    def deployment_status() -> str:
        """Read synthetic checkout deployment diagnostics."""
        return perform("deployment_status", "GET", "/deployments/checkout/status")

    return [deploy_checkout, deployment_status]


async def exercise(client, service_url, model_id, location):
    """Request each test operation from one live agent and preserve its tool results."""
    calls, phases = [], []
    model = GeminiModel(client=client, model_id=model_id, params={"max_output_tokens": 2048})
    agent = Agent(model=model, tools=deployment_tools(service_url, calls),
                  system_prompt=SYSTEM_PROMPT, callback_handler=None,
                  tool_executor=SequentialToolExecutor(), retry_strategy=None,
                  context_manager=False)
    for name, prompt in PHASES:
        model.update_config(params={"max_output_tokens": 2048, "tool_config": {
            "function_calling_config": {"mode": "ANY", "allowed_function_names": [name]}}})
        start = len(calls)
        result = await agent.invoke_async(prompt + " Call " + name + " exactly once.", limits={"turns": 1})
        phase_calls = calls[start:]
        phases.append({"tool": name, "stop_reason": result.stop_reason,
                       "tool_calls": len(phase_calls)})
        if len(phase_calls) != 1 or phase_calls[0]["name"] != name:
            raise RuntimeError("The model did not execute exactly the requested phase tool")
    model.update_config(params={"max_output_tokens": 2048, "tool_config": {
        "function_calling_config": {"mode": "NONE"}}})
    result = await agent.invoke_async(
        "Report the three failures, two refused retries, and diagnostics. "
        "State that cooldown expiry was not tested. Use only the recorded results.", limits={"turns": 1})
    usage = {key: result.metrics.accumulated_usage.get(key, 0)
             for key in ("inputTokens", "outputTokens", "totalTokens")}
    deployments = [row for row in calls if row["name"] == "deploy_checkout"]
    diagnostics = [row for row in calls if row["name"] == "deployment_status"]
    model_responses = sum(message["role"] == "assistant" for message in agent.messages)
    checks = {
        "seven_model_selected_tools": len(calls) == 7 and [row["name"] for row in calls] == [x[0] for x in PHASES],
        "three_service_failures": len(deployments) == 5 and all(
            row["status"] == 503 and not row["box_refused"] for row in deployments[:3]),
        "two_box_refusals": len(deployments) == 5 and all(
            row["status"] >= 400 and row["box_refused"] for row in deployments[3:]),
        "diagnostics_available": len(diagnostics) == 2 and all(
            row["status"] == 200 and not row["box_refused"] for row in diagnostics),
        "model_responses": model_responses == 8,
        "model_usage": usage["inputTokens"] > 0 and usage["outputTokens"] > 0,
    }
    return {"passed": all(checks.values()), "checks": checks, "provider": "google_vertex_ai",
            "model": model_id, "location": location, "pid": os.getpid(),
            "executor": "SequentialToolExecutor", "model_responses": model_responses,
            "tool_calls": calls, "phases": phases, "usage": usage, "response": str(result),
            "expiry_checked": False}


async def main():
    if len(sys.argv) != 2:
        raise ValueError("Provide the synthetic deployment service URL")
    client = make_client(os.environ)
    try:
        result = await exercise(client, sys.argv[1], os.environ["GOOGLE_MODEL_ID"],
                                os.environ["GOOGLE_CLOUD_LOCATION"])
        result["credential_is_placeholder"] = os.environ["GOOGLE_TOKEN"].startswith("strands_box_")
    finally:
        await client.aio.aclose()
        client.close()
    print("GCP_AGENT_RESULT " + json.dumps(result), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as error:
        print("GCP_AGENT_RESULT " + json.dumps({"passed": False, "error_type": type(error).__name__}), flush=True)
        sys.exit(1)
