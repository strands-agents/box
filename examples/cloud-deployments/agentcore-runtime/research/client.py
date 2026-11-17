#!/usr/bin/env python3
"""Complete a scripted launch brief after the fourth enrichment request."""

import argparse
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--assignment", type=Path, required=True)
    args = parser.parse_args()
    assignment = json.loads(args.assignment.read_text())
    proxy = urlsplit(os.environ["HTTP_PROXY"])
    service = urlsplit(args.service)
    steps, sources = [], []
    for query in assignment["queries"]:
        connection = http.client.HTTPConnection(proxy.hostname, proxy.port, timeout=15)
        body = json.dumps({"topic": query["topic"]})
        connection.request("POST", args.service + "/research/enrich", body=body, headers={
            "Host": service.netloc,
            "Content-Type": "application/json",
            "Connection": "close",
        })
        response = connection.getresponse()
        raw = response.read().decode()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw
        step = {
            "topic": query["topic"], "status": response.status,
            "box_refused": response.getheader("x-strands-box-egress") == "refused",
            "body": data,
        }
        steps.append(step)
        connection.close()
        if step["status"] == 200:
            sources.append(data)
    lines = ["# TrailNotes Demo: launch brief", "", assignment["audience"], ""]
    lines += [source["finding"] + " [" + source["source_id"] + "]" for source in sources]
    lines += ["", "## Remaining question", ""]
    missing = [query["question"] for query, step in zip(assignment["queries"], steps) if step["status"] != 200]
    if missing:
        lines += ["Unverified: " + question for question in missing]
        lines += ["Box refused these enrichment attempts. The brief uses the sources already collected."]
    else:
        lines += ["All four fixture questions have a retrieved source."]
    lines += ["", "## Sources", ""]
    lines += ["- [" + source["source_id"] + "] " + source["title"] + " (synthetic fixture)." for source in sources]
    lines += ["", "This brief describes fictional fixture data. It makes no claims about a released product.", ""]
    print(json.dumps({
        "mode": "deterministic scripted research; no language model",
        "steps": steps, "sources": sources, "brief": "\n".join(lines),
        "completion": {"kind": "brief_completed", "after_call_count": len(steps)},
        "unanswered_questions": missing,
    }))


if __name__ == "__main__":
    main()
