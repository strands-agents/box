#!/usr/bin/env python3
"""PROTOTYPE inspector 2: Microsoft Presidio with spaCy `en_core_web_sm`. PII only, because SECRET
is not a Presidio concept."""

import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecp  # noqa: E402

MIN_SCORE = 0.5
ENTITY_KIND = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "us_ssn",
    "CREDIT_CARD": "credit_card",
    "IBAN_CODE": "iban",
    "IP_ADDRESS": "ip_address",
    "PERSON": "person",
    "US_PASSPORT": "us_passport",
    "US_DRIVER_LICENSE": "us_driver_license",
}


def load(args):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    nlp = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    ).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    lock = threading.Lock()
    analyzer.analyze(text="warmup", language="en")
    ecp.log("presidio warm")

    def classify_http(segments, labels):
        out = []
        for _, text in segments:
            with lock:
                results = analyzer.analyze(text=text, language="en", entities=list(ENTITY_KIND))
            for r in results:
                if r.score < MIN_SCORE:
                    continue
                value, kind = text[r.start : r.end], ENTITY_KIND[r.entity_type]
                evidence = ecp.mask_email(value) if kind == "email" else ecp.mask_tail(value, 2)
                out.append(ecp.Finding("PII", kind, round(r.score, 3), evidence))
        return out

    return classify_http


ecp.serve(name="presidio", version="0.2-prototype", http_labels=["PII"], load=load)
