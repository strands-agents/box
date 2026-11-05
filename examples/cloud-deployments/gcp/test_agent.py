"""Check the pinned model adapter without Google credentials or a cloud request."""
import asyncio
import json
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent
import certifi
import httpx
from google import genai
from google.genai import types
from google.oauth2.credentials import Credentials


class AgentTests(unittest.IsolatedAsyncioTestCase):
    async def run_exercise(self, *, missing_tool=False, refusal_marker=True):
        requests, tool_requests = [], []

        def model_request(request):
            index = len(requests)
            requests.append(request)
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.host, "aiplatform.googleapis.com")
            self.assertEqual(request.url.path,
                "/v1/projects/example-project/locations/global/publishers/google/models/gemini-3.8-flash:streamGenerateContent")
            self.assertEqual(request.url.params["alt"], "sse")
            self.assertEqual(request.headers["Authorization"], "Bearer strands_box_test_placeholder")
            payload = json.loads(request.content)
            config = payload["toolConfig"]["functionCallingConfig"]
            if index < len(agent.PHASES) and not missing_tool:
                name = agent.PHASES[index][0]
                self.assertEqual(config["mode"], "ANY")
                self.assertEqual(config["allowed_function_names"], [name])
                part = {"functionCall": {"name": name, "args": {}}, "thoughtSignature": "dGVzdA=="}
            else:
                if not missing_tool:
                    self.assertEqual(config["mode"], "NONE")
                part = {"text": "Three failures, two refused retries, diagnostics available. Expiry was not tested."}
            chunk = {"candidates": [{"index": 0, "content": {"role": "model", "parts": [part]},
                                      "finishReason": "STOP"}],
                     "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2, "totalTokenCount": 7}}
            return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                  content="data: " + json.dumps(chunk) + "\n\n")

        def deployment_request(url, method, path):
            self.assertEqual(url, "http://127.0.0.1:12345")
            tool_requests.append((method, path))
            deployments = sum(row[0] == "POST" for row in tool_requests)
            refused = method == "POST" and deployments > 3
            return {"status": 403 if refused else 503 if method == "POST" else 200,
                    "box_refused": refused and refusal_marker, "body": {"synthetic": True}}

        transport = httpx.MockTransport(model_request)
        client = genai.Client(vertexai=True, project="example-project", location="global",
            credentials=Credentials(token="strands_box_test_placeholder", expiry=None),
            http_options=types.HttpOptions(api_version="v1", retry_options=types.HttpRetryOptions(attempts=1),
                httpx_client=httpx.Client(transport=transport),
                httpx_async_client=httpx.AsyncClient(transport=transport)))
        try:
            with patch.object(agent, "request", side_effect=deployment_request), \
                 patch("google.auth.default", side_effect=AssertionError("Unexpected default credential lookup")), \
                 patch.object(Credentials, "refresh", side_effect=AssertionError("Unexpected credential refresh")):
                result = await agent.exercise(client, "http://127.0.0.1:12345", "gemini-3.8-flash", "global")
        finally:
            await client.aio.aclose()
            client.close()
        return result, requests, tool_requests

    async def test_pinned_sdk_runs_all_phases_and_uses_placeholder(self):
        result, requests, tools = await self.run_exercise()
        self.assertTrue(result["passed"], result)
        self.assertEqual(len(requests), 8)
        self.assertEqual(len(tools), 7)
        self.assertEqual(result["usage"], {"inputTokens": 40, "outputTokens": 16, "totalTokens": 56})
        self.assertTrue(all(row["stop_reason"] == "limit_turns" for row in result["phases"]))
        self.assertEqual(result["executor"], "SequentialToolExecutor")
        self.assertNotIn("strands_box_test_placeholder", json.dumps(result))

    async def test_missing_model_tool_call_fails_the_exercise(self):
        with self.assertRaisesRegex(RuntimeError, "exactly the requested"):
            await self.run_exercise(missing_tool=True)

    async def test_refusal_text_without_box_marker_does_not_pass(self):
        result, _, _ = await self.run_exercise(refusal_marker=False)
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["two_box_refusals"])


class ClientTests(unittest.TestCase):
    def environment(self):
        return {"HTTPS_PROXY": "http://127.0.0.1:12345", "SSL_CERT_FILE": certifi.where(),
                "GOOGLE_TOKEN": "strands_box_test_placeholder", "GOOGLE_CLOUD_PROJECT": "example-project",
                "GOOGLE_CLOUD_LOCATION": "global"}

    def test_client_uses_explicit_proxy_and_verified_tls_for_both_transports(self):
        with patch.object(agent.httpx, "Client", wraps=httpx.Client) as sync_client, \
             patch.object(agent.httpx, "AsyncClient", wraps=httpx.AsyncClient) as async_client, \
             patch("google.auth.default", side_effect=AssertionError("Unexpected default credential lookup")):
            client = agent.make_client(self.environment())
        try:
            for constructor in (sync_client, async_client):
                options = constructor.call_args.kwargs
                self.assertEqual(options["proxy"], "http://127.0.0.1:12345")
                self.assertFalse(options["trust_env"])
                self.assertEqual(options["verify"].verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(options["verify"].check_hostname)
        finally:
            asyncio.run(client.aio.aclose())
            client.close()

    def test_raw_credential_is_rejected(self):
        environment = self.environment()
        environment["GOOGLE_TOKEN"] = "synthetic-value-not-a-box-placeholder"
        with self.assertRaisesRegex(ValueError, "placeholder"):
            agent.make_client(environment)

    def test_non_loopback_proxy_is_rejected(self):
        environment = self.environment()
        environment["HTTPS_PROXY"] = "http://example.com:12345"
        with self.assertRaisesRegex(ValueError, "loopback"):
            agent.make_client(environment)

    def test_missing_proxy_is_rejected(self):
        environment = self.environment()
        del environment["HTTPS_PROXY"]
        with self.assertRaises(KeyError):
            agent.make_client(environment)


if __name__ == "__main__":
    unittest.main()
