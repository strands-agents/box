#!/usr/bin/env python3
"""Render verdict.json into the GitHub Actions job summary.

The suite's own exit status already decides pass/fail; this exists so a reader
does not have to download an artifact to learn WHICH case failed. Writes to
$GITHUB_STEP_SUMMARY when set, otherwise stdout, so it is useful locally too.

Never fails the job on its own: a missing or malformed verdict is reported as
such and exits 0. The suite step is the signal; this is the explanation.
"""

import json
import os
import sys


def emit(out, line=""):
    out.write(line + "\n")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "det-results/verdict.json"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    out = open(summary, "a", encoding="utf-8") if summary else sys.stdout

    try:
        with open(path, encoding="utf-8") as fh:
            v = json.load(fh)
    except FileNotFoundError:
        emit(out, "### Deterministic suite: no verdict produced")
        emit(out)
        emit(out, f"`{path}` does not exist. The harness did not get far enough "
                  "to write one -- check the suite step's log for a build error.")
        return 0
    except (json.JSONDecodeError, OSError) as err:
        emit(out, "### Deterministic suite: verdict unreadable")
        emit(out)
        emit(out, f"`{path}`: {err}")
        return 0

    counts = v.get("counts", {}) or {}
    integrity = v.get("integrity", {}) or {}
    verdict = v.get("verdict", "UNKNOWN")
    icon = {"GREEN": "PASS", "RED": "FAIL"}.get(verdict, verdict)

    emit(out, f"### Deterministic suite: {icon} ({verdict})")
    emit(out)
    emit(out, f"platform `{v.get('platform', '?')}` · box `{str(v.get('box_commit', '?'))[:12]}`")
    emit(out)
    emit(out, "| total | pass | fail | error | skip |")
    emit(out, "|---|---|---|---|---|")
    emit(out, "| {} | {} | {} | {} | {} |".format(
        counts.get("total", "?"), counts.get("pass", "?"),
        counts.get("fail", "?"), counts.get("error", "?"),
        counts.get("skip", "?")))
    emit(out)

    problems = integrity.get("problems") or []
    if problems:
        emit(out, "**Integrity problems**")
        for p in problems:
            emit(out, f"- {p}")
        emit(out)

    # Only the rows that are not a plain pass. A skip carries its reason (a
    # platform declaration or a named quarantine), which is worth showing:
    # a case silently not running is how coverage rots.
    notable = [r for r in v.get("results", [])
               if str(r.get("result", "")).upper() != "PASS"]
    if notable:
        emit(out, f"**{len(notable)} non-pass cases**")
        emit(out)
        for r in notable:
            rid = r.get("id", "?")
            res = str(r.get("result", "?")).upper()
            note = " ".join(str(r.get("note", "")).split())
            if len(note) > 400:
                note = note[:400] + " […]"
            emit(out, f"- **{rid}** — `{res}`" + (f": {note}" if note else ""))
        emit(out)

    if out is not sys.stdout:
        out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
