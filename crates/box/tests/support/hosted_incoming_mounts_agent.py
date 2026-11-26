# A contained agent drives real Shell and Python aliases for hosted mount tests.
import json
import pathlib
import shlex
import subprocess
import sys

status = pathlib.Path("/proc/self/status").read_text().splitlines()
assert all(int(line.split()[1], 16) == 0 for line in status
           if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")))
print(json.dumps({"ready": True}), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    path = request["path"]
    if request["interpreter"] == "shell":
        if request["operation"] == "read":
            source = "cat " + shlex.quote(path)
        else:
            source = "printf %s " + shlex.quote(request["text"]) + " > " + shlex.quote(path)
        argv = ["zsh", "-c", source]
    else:
        expression = "Path(" + repr(path) + ")"
        if request["operation"] == "read":
            source = "from pathlib import Path; print(" + expression + ".read_text(), end='')"
        else:
            source = "from pathlib import Path; " + expression + ".write_text(" + repr(request["text"]) + ")"
        argv = ["python3", "-c", source]
    completed = subprocess.run(argv, text=True, capture_output=True, timeout=40)
    print(json.dumps({"status": completed.returncode, "stdout": completed.stdout,
                      "stderr": completed.stderr}), flush=True)
