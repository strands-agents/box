"""Install the packaged operator workload before the Runtime accepts requests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tomllib

from claude_runtime import ClaudeRuntime

HERE = Path(__file__).resolve().parent
DIRECTORY = Path("/var/tmp/box-manual")


def prepare(box):
    if os.getuid() == 0:
        raise RuntimeError("The manual workload requires a non-root operator")
    config = (HERE / "box.toml").read_bytes()
    policy = (HERE / "policy.dw").read_bytes()
    identity = hashlib.sha256(config + policy).hexdigest()
    marker = DIRECTORY / "installed.json"
    if marker.exists():
        if json.loads(marker.read_text())["package_config_sha256"] != identity:
            raise RuntimeError("The manual directory belongs to another configuration")
        return DIRECTORY
    if DIRECTORY.exists():
        raise RuntimeError(
            "The manual directory exists without an install marker. "
            "Remove /var/tmp/box-manual and restart the Runtime."
        )
    runtime = ClaudeRuntime(box)
    claude, _ = runtime.install()
    root = runtime.configure(DIRECTORY / "bin/claude", "", True, exercise=True,
                             directory=DIRECTORY)
    # Refuse a platform mismatch instead of broadening packaged filesystem grants.
    if tomllib.loads(config.decode()) != tomllib.loads((root / "box.toml").read_text()):
        raise RuntimeError("The packaged manual configuration does not match this platform")
    if policy != (root / "policy.dw").read_bytes():
        raise RuntimeError("The packaged manual policy differs from the exercise policy")
    (root / "bin").mkdir()
    (root / "bin/box").symlink_to(box)
    (root / "bin/claude").symlink_to(claude)
    shutil.copyfile(HERE / "box.toml", root / "box.toml")
    shutil.copyfile(HERE / "policy.dw", root / "policy.dw")
    launcher = root / "box"
    launcher.write_text(f"""#!{sys.executable}
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
binary = root / "bin/box"
env = {{
    "HOME": str(Path.home()),
    "PATH": str(root) + ":/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "TERM": os.environ.get("TERM", "xterm-256color"),
    "COLORTERM": "truecolor",
}}
if sys.argv[1:2] == ["run"] and not any(x in sys.argv[2:] for x in ("--help", "-h")):
    from aws_bedrock_token_generator import provide_token
    env["AWS_BEARER_TOKEN_BEDROCK"] = provide_token(region="us-west-2")
os.execve(binary, [str(binary), *sys.argv[1:]], env)
""")
    launcher.chmod(0o700)
    (root / "README.txt").write_text(
        "Run inside this Runtime session:\n"
        "  cd /var/tmp/box-manual\n"
        "  ./box run --config box.toml\n\n"
        "The local launcher supplies model authentication and starts the packaged Box binary.\n"
        "The manual workload has its own project, Claude history, and Box audit directory.\n"
        "It does not attach to the Claude process in the desktop demo tabs.\n"
    )
    marker.write_text(json.dumps({"package_config_sha256": identity,
                                  "config": str(root / "box.toml"),
                                  "binary": str(box), "claude": str(claude)}) + "\n")
    return root
