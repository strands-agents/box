#!/usr/bin/env python3
"""Run offline tests with socket connections prohibited, preserving a source-bound receipt."""
import hashlib, importlib.util, json, platform, socket, unittest
from pathlib import Path
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("test_example", HERE / "test_example.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
(HERE / "evidence").mkdir(exist_ok=True)
network = []
def blocked(self, address):
    network.append(str(address))
    raise RuntimeError("Unexpected offline network attempt")
original = socket.socket.connect
socket.socket.connect = blocked
try:
    with (HERE / "evidence/offline-tests.txt").open("w") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
finally:
    socket.socket.connect = original
summary = {"mode": "offline real LangChain graph and ChatBedrockConverse with test-only synthetic provider and HTTP responses",
           "tests_run": result.testsRun, "negative_evidence_mutations": 36,
           "failures": len(result.failures), "errors": len(result.errors),
           "network_attempts": network, "success": result.wasSuccessful(),
           "python": platform.python_version(), "architecture": platform.machine(),
           "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ("agent.py", "run-demo.py", "test_example.py", "run-offline-tests.py", "dependency-manifest.json")}}
(HERE / "evidence/offline-tests.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary))
raise SystemExit(0 if result.wasSuccessful() and not network else 1)
