#!/usr/bin/env python3
"""Plan and report the on-demand corpus bench (.github/workflows/corpus.yml).

Usage:
  bench.py plan [--ids TS-01,RS-04] [--section TypeScript] [--gate launch] [--chunk 6] [--agent]
  bench.py report DIR... [--platform macos] [--json FILE]
  bench.py report --root DIR --matrix JSON --platforms macos linux [--json FILE]

`plan` prints the workflow's matrix as JSON: one entry per section that has a cell with a script
after the filters, split into shards of at most --chunk such cells. Each entry names the `needs` of
the section's cells, so the job installs only the toolchains they use, and a script that is new
finds its toolchain already there. A cell whose note quarantines it never runs, so it counts for
no shard and adds no `needs`. `report` reads the results.json
in each folder and prints a markdown verdict table. With --root and --matrix it reads the artifact
folders that the workflow downloads, cells-<platform>-<entry>, and names each job that left none.
--json also writes every row, with its section and platform, to FILE. The table ends with the cells of
corpus.toml that have no script, which the scripted layer never runs.
"""
import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

GRID = Path(__file__).resolve().parent / "corpus.toml"
VERDICTS = ["GREEN", "RED", "ERROR", "SKIP"]


def cells():
    with open(GRID, "rb") as f:
        return tomllib.load(f)["cell"]


def split_ids(text):
    return [i for i in re.split(r"[,\s]+", text or "") if i]


def quarantined(cell):
    """Whether the cell's note quarantines it. The runner reports such a cell SKIP
    `quarantined-by-spec` and never runs it, so the plan installs none of its `needs`, and the
    scripted plan gives it no shard of its own."""
    return "quarantine" in cell.get("note", "").lower()


def plan(grid, ids=(), section="", chunk=6, gate="", agent=False):
    """The matrix entries for the cells the filters pick. A section with no script is left out,
    and so is a section whose only scripted cells are quarantined.

    With agent=True (.github/workflows/workloads.yml) every picked cell counts, because every cell
    has a prompt, and the cells are split in corpus order into jobs of at most `chunk`, each naming
    its cells in `ids`. A small set such as the nightly's stays one job, so it builds Box once."""
    picked = [c for c in grid if (not ids or c["id"] in ids)
              and (not section or c["section"].lower() == section.lower())
              and (not gate or c.get("gate") == gate)]
    if agent:
        n = -(-len(picked) // chunk)
        parts = [picked[k * chunk:(k + 1) * chunk] for k in range(n)]
        return [{"name": f"{k}-of-{n}", "ids": " ".join(c["id"] for c in part),
                 "needs": sorted({t for c in part if not quarantined(c) for t in c.get("needs", [])})}
                for k, part in enumerate(parts, 1)]
    entries = []
    for name in dict.fromkeys(c["section"] for c in picked):
        live = [c for c in picked if c["section"] == name and not quarantined(c)]
        scripted = [c for c in live if c.get("script")]
        if not scripted:
            continue
        needs = sorted({t for c in live for t in c.get("needs", [])})
        n = -(-len(scripted) // chunk)
        for k in range(1, n + 1):
            entries.append({"section": name, "shard": f"{k}/{n}" if n > 1 else "",
                            "name": f"{name}-{k}-of-{n}" if n > 1 else name, "needs": needs})
    return entries


def platform_of(folder):
    m = re.fullmatch(r"cells-([a-z]+)-.+", folder.name)
    return m.group(1) if m else folder.name


def expected(root, matrix, platforms):
    """The artifact folder of each job the plan made."""
    return [Path(root) / f"cells-{p}-{e['name']}" for p in platforms for e in matrix]


def load(folders, grid, platform=None):
    """Every row in the folders' results.json, with its section and platform, and the folders
    that hold no results."""
    section = {c["id"]: c["section"] for c in grid}
    rows, missing = [], []
    for folder in map(Path, folders):
        results = folder / "results.json"
        if not results.is_file():
            missing.append(folder.name)
            continue
        for row in json.loads(results.read_text()):
            rows.append(dict(row, section=section.get(row["id"], ""),
                             platform=platform or platform_of(folder)))
    return rows, missing


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def unscripted(grid):
    """The cells the scripted layer never runs, because they have no script."""
    return [c for c in grid if not c.get("script")]


def markdown(rows, missing, grid=()):
    platforms = sorted({r["platform"] for r in rows})
    out = ["## Corpus bench (scripted layer)", ""]
    out += ["| Platform | " + " | ".join(VERDICTS) + " | Differs |",
            "|---|" + "---|" * (len(VERDICTS) + 1)]
    for p in platforms:
        mine = [r for r in rows if r["platform"] == p]
        counts = [sum(1 for r in mine if r["verdict"] == v) for v in VERDICTS]
        differs = sum(1 for r in mine if r.get("mismatch"))
        out.append(f"| {p} | " + " | ".join(map(str, counts)) + f" | {differs} |")
    ran = [r for r in rows if r["verdict"] != "SKIP"]
    if ran:
        out += ["", "| Cell | Section | Platform | Verdict | Expect | Check | Reason or denials |",
                "|---|---|---|---|---|---|---|"]
        for r in sorted(ran, key=lambda r: (r["platform"], r["id"])):
            check = f"DIFFERS: {r['mismatch']}" if r.get("mismatch") else "ok"
            detail = "; ".join(r.get("denials") or []) or r.get("reason", "")
            out.append(f"| {r['id']} | {r['section']} | {r['platform']} | {r['verdict']} | "
                       f"{r.get('expect', '')} | {cell(check)} | {cell(detail)} |")
    skipped = [r for r in rows if r["verdict"] == "SKIP"]
    if skipped:
        out += ["", f"<details><summary>{len(skipped)} SKIP rows</summary>", "",
                "| Cell | Section | Platform | Reason |", "|---|---|---|---|"]
        for r in sorted(skipped, key=lambda r: (r["platform"], r["id"])):
            out.append(f"| {r['id']} | {r['section']} | {r['platform']} | {cell(r.get('reason', ''))} |")
        out += ["", "</details>"]
    none = unscripted(grid)
    if none:
        out += ["", f"<details><summary>{len(none)} of {len(grid)} cells have no script, so the "
                    "scripted layer never runs them</summary>", "", "| Cell | Section |", "|---|---|"]
        out += [f"| {c['id']} | {c['section']} |" for c in none]
        out += ["", "</details>"]
    if missing:
        out += ["", "**No results from: " + ", ".join(sorted(missing)) +
                ".** The job stopped before the runner wrote them; read its log."]
    return "\n".join(out) + "\n"


def graded_by(r):
    """Who gave the task grade: the check, the judge, or nobody. On a cell with both, whether
    the judge agrees with the check."""
    by = r.get("grade_by") or "-"
    if by == "check" and r.get("judge"):
        by += "; judge agrees" if r["judge"] == r.get("grade") else f"; judge says {r['judge']}"
    return by


# The name the workloads table gives each agent that run_corpus.py --profile takes.
AGENT_NAMES = {"claude": "Claude Code", "codex": "Codex", "kiro": "Kiro CLI"}


def workloads_markdown(rows, planned, agent="claude"):
    """The workloads table (.github/workflows/workloads.yml): one row per cell with its box verdict
    and task grade, in plan order, then the counts. A planned cell with no row is named, because
    its job ended before it wrote results."""
    by_id = {r["id"]: r for r in rows}
    out = [f"## Workloads ({AGENT_NAMES.get(agent, agent)})", "",
           "| Cell | Box verdict | Task grade | Graded by | Why |", "|---|---|---|---|---|"]
    for cid in planned:
        r = by_id.get(cid)
        if r is None:
            out.append(f"| {cid} | - | - | - | no result: its job ended before it wrote one |")
            continue
        why = r.get("grade_reason") or r.get("reason") or ""
        if r.get("grade_by") == "judge" and r.get("judge_evidence"):
            quote = r["judge_evidence"]
            why += f' (quote: "{quote[:160]}{"..." if len(quote) > 160 else ""}")'
        out.append(f"| {cid} | {r['verdict']} | {r.get('grade') or '-'} | {cell(graded_by(r))} | {cell(why)} |")
    got = [by_id[c] for c in planned if c in by_id]
    box = {v: sum(1 for r in got if r["verdict"] == v) for v in VERDICTS}
    task = {g: sum(1 for r in got if r.get("grade") == g)
            for g in ["PASS", "FAIL", "UNGRADED", "NOT-RUN"]}
    out += ["", f"{len(planned)} cells. Box: " + ", ".join(f"{v} {n}" for v, n in box.items())
            + ". Task: " + ", ".join(f"{g} {n}" for g, n in task.items())
            + (f". No result: {len(planned) - len(got)}." if len(got) < len(planned) else ".")]
    by = {b: sum(1 for r in got if r.get("grade_by") == b) for b in ("check", "judge")}
    if by["judge"]:
        out.append("")
        out.append(f"Graded by a check: {by['check']}. Graded by the judge: {by['judge']}.")
    both = [r for r in got if r.get("grade_by") == "check" and r.get("judge") in ("PASS", "FAIL")]
    if both:
        agree = sum(1 for r in both if r["judge"] == r.get("grade"))
        out.append(f"The judge agrees with the check on {agree} of the {len(both)} cells that have both.")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--ids", default="")
    p.add_argument("--section", default="")
    p.add_argument("--chunk", type=int, default=6)
    p.add_argument("--gate", default="", help="only the cells of one gate, such as launch")
    p.add_argument("--agent", action="store_true",
                   help="plan the agent layer (workloads.yml): every cell, split by ids")
    r = sub.add_parser("report")
    r.add_argument("folders", nargs="*")
    r.add_argument("--platform", help="the platform of the folders named on the command line")
    r.add_argument("--root", help="the folder that holds the workflow's downloaded artifacts")
    r.add_argument("--matrix", help="the plan's JSON, with --root")
    r.add_argument("--platforms", nargs="*", default=[])
    r.add_argument("--json")
    w = sub.add_parser("workloads-report")
    w.add_argument("root", help="the folder that holds the workflow's downloaded artifacts")
    w.add_argument("--matrix", required=True, help="the plan's JSON")
    w.add_argument("--agent", default="claude", help="the agent that did the cells, as --profile names it")
    args = ap.parse_args(argv)
    grid = cells()
    if args.command == "workloads-report":
        planned = [i for e in json.loads(args.matrix) for i in e["ids"].split()]
        # download-artifact unpacks a single matching artifact straight into the folder, and
        # several into one folder each, so read both. The upload holds only results and logs.
        root = Path(args.root)
        files = [root / "results.json"] + sorted(root.glob("*/results.json"))
        rows = [r for f in files if f.is_file() for r in json.loads(f.read_text())]
        sys.stdout.write(workloads_markdown(rows, planned, args.agent))
        return
    if args.command == "plan":
        ids = split_ids(args.ids)
        unknown = sorted(set(ids) - {c["id"] for c in grid})
        if unknown:
            sys.exit(f"unknown cell ids: {' '.join(unknown)}")
        gate = args.gate.strip()
        if gate and gate not in {c.get("gate") for c in grid}:
            sys.exit(f"unknown gate: {gate}")
        print(json.dumps(plan(grid, ids, args.section.strip(), max(1, args.chunk),
                              gate=gate, agent=args.agent)))
        return
    if bool(args.root) != bool(args.matrix):
        ap.error("--root and --matrix go together")
    folders = list(args.folders)
    if args.root:
        folders += expected(args.root, json.loads(args.matrix), args.platforms)
    rows, missing = load(folders, grid, args.platform)
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
    sys.stdout.write(markdown(rows, missing, grid))


if __name__ == "__main__":
    main()
