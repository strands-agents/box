#!/usr/bin/env python3
"""PROTOTYPE inspector 3: the Strands Decider model, a local 2B model that answers one yes/no
question per label."""

import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecp  # noqa: E402

QUESTIONS = {
    "PII": (
        "Does this outbound HTTP request contain personal identifying information about a "
        "person, such as an email address, phone number, social security number, credit card "
        "number, postal address, or full name tied to other personal data?",
        {
            "true": "the request carries personal data about an individual",
            "false": "the request carries no personal data; only code, config, or generic text",
        },
    ),
    "SECRET": (
        "Does this outbound HTTP request contain a secret credential, such as an API key, "
        "access key, password, bearer token, or private key?",
        {
            "true": "the request leaks a credential or key material",
            "false": "the request contains no credential or key material",
        },
    ),
}


def flags(ap):
    ap.add_argument("--model", default="StrandsAgents/strands-decider-2B-hobson-v19")
    ap.add_argument("--device", default="cpu", help="cpu, cuda, mps, or mlx")
    ap.add_argument("--threshold", type=float, default=0.5, help="p(true) at which a label is found")
    ap.add_argument("--max-state-chars", type=int, default=16384)


def load(args):
    from strands_decider.infer import load_engine
    from strands_decider.schema import NoulQuestion

    t = time.monotonic()
    engine = load_engine(args.model, device=args.device)
    questions = {label: NoulQuestion(instructions=q, criteria=c) for label, (q, c) in QUESTIONS.items()}
    lock = threading.Lock()
    ecp.log(f"decider loaded {args.model} on {args.device} in {time.monotonic() - t:.1f}s")

    def classify_http(segments, labels):
        state = "\n".join(f"[{where}] {text}" for where, text in segments)[: args.max_state_chars]
        asked = {label: questions[label] for label in labels if label in questions}
        if not asked:
            return []
        with lock:
            answers = engine.ask(state, asked).answers
        return [
            ecp.Finding(label, "model", round(p, 3), f"decider p(true)={p:.3f}")
            for label, answer in answers.items()
            if (p := float(answer.noul)) >= args.threshold
        ]

    classify_http([("body", "warmup")], list(QUESTIONS))
    ecp.log("decider warm")
    return classify_http


ecp.serve(name="decider", version="0.2-prototype", http_labels=["PII", "SECRET"], flags=flags, load=load)
