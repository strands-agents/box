# /// script
# dependencies = ["pyte"]
# ///
"""Run a command in a pseudo-terminal, send it keys, and print the screens it draws.

usage: uv run scripts/drive_tui.py STEPS -- COMMAND...
STEPS is a JSON list: ["wait", text, seconds], ["send", keys], ["sleep", seconds], ["screen"].
See docs/dev/interactive-testing.md.
"""

import json
import os
import pty
import select
import signal
import struct
import sys
import time

import fcntl
import pyte
import termios

COLS, ROWS = 120, 40


def main():
    split = sys.argv.index("--")
    steps = json.loads(sys.argv[1])
    command = sys.argv[split + 1 :]
    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.ByteStream(screen)
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp(command[0], command)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    alive = [True]
    missed = False

    def pump(seconds):
        end = time.time() + seconds
        while alive[0] and time.time() < end:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    alive[0] = False
                    return
                if not data:
                    alive[0] = False
                    return
                stream.feed(data)

    def text():
        return "\n".join(line.rstrip() for line in screen.display).rstrip()

    def show(label):
        print(f"===== {label} =====\n{text()}\n", flush=True)

    for step in steps:
        kind = step[0]
        if kind == "wait":
            needle, timeout = step[1], step[2]
            end = time.time() + timeout
            while alive[0] and needle not in text() and time.time() < end:
                pump(0.2)
            found = needle in text()
            show(f"wait {needle!r}: {'found' if found else 'NOT FOUND'}")
            if not found:
                missed = True
                break
        elif kind == "send":
            os.write(fd, step[1].encode().decode("unicode_escape").encode())
            pump(0.3)
        elif kind == "sleep":
            pump(step[1])
        elif kind == "screen":
            show("screen")
        if not alive[0]:
            show("process exited")
            break

    if alive[0]:
        os.kill(pid, signal.SIGTERM)
        pump(1)
    _, status = os.waitpid(pid, 0)
    print(f"exit status: {os.waitstatus_to_exitcode(status)}")
    sys.exit(1 if missed else 0)


if __name__ == "__main__":
    main()
