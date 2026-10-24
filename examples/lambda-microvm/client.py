"""Connect to the exact Lambda instance recorded by the example."""
import json
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError("The Lambda application must not redirect authenticated requests")


class Client:
    def __init__(self, session, target):
        if session.client("sts").get_caller_identity()["Account"] != target["account"]:
            raise ValueError("The selected profile does not own the recorded account")
        self.client = session.client("lambda-microvms", region_name=target["region"])
        self.target = target
        self.instance = self.client.get_microvm(microvmIdentifier=target["microvm_id"])
        if (self.instance["imageArn"], self.instance["imageVersion"]) != (target["image"], target["version"]):
            raise ValueError("The retained instance image changed")
        if self.instance["state"] == "TERMINATED":
            raise RuntimeError("The instance expired. Deploy a new instance.")
        if self.instance["state"] == "SUSPENDED":
            self.client.resume_microvm(microvmIdentifier=target["microvm_id"])
        self.headers = {}
        self.expires = 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        if data is not None and len(data) > 16384:
            raise ValueError("The request exceeds 16384 bytes")
        if time.monotonic() >= self.expires:
            self.headers = self.client.create_microvm_auth_token(
                microvmIdentifier=self.target["microvm_id"], expirationInMinutes=15,
                allowedPorts=[{"port": 8080}],
            )["authToken"]
            self.headers.update({"X-aws-proxy-port": "8080", "Content-Type": "application/json"})
            self.expires = time.monotonic() + 780
        endpoint = self.instance["endpoint"]
        if not endpoint.startswith("https://"):
            endpoint = "https://" + endpoint
        request = urllib.request.Request(endpoint + path, data=data, headers=self.headers)
        with self.opener.open(request, timeout=45) as response:
            return json.load(response)

    def ready(self):
        deadline = time.monotonic() + 180
        while True:
            try:
                info = self.request("/info")
                break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("The retained application did not become ready") from None
                time.sleep(2)
        if (info["manifest"]["fingerprint"] != self.target["fingerprint"]
                or info["package"] != self.target["package"]
                or info["box_sha256"] != self.target["package"]["binary_sha256"]
                or info["architecture"] != "aarch64" or info["uid"] != 0):
            raise ValueError("The application does not match the recorded source and execution profile")
        return info
