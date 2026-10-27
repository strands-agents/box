#!/usr/bin/env python3
"""PROTOTYPE inspector 1: regular expressions for PII and SECRET. Standard library only."""

import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ecp  # noqa: E402

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
PHONE = re.compile(r"(?<![\d-])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?![\d-])")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
AWS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")
PRIVATE_KEY = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----")
GENERIC_KEY = re.compile(
    r"(?i)\b([a-z0-9_.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|access[_-]?key)[a-z0-9_.-]*)"
    r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-/+=.]{16,})"
)


def luhn(digits):
    total, alt = 0, False
    for c in reversed(digits):
        d = int(c)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def pii(text):
    for m in EMAIL.finditer(text):
        yield ecp.Finding("PII", "email", 0.95, ecp.mask_email(m.group()))
    for m in SSN.finditer(text):
        yield ecp.Finding("PII", "us_ssn", 0.9, "***-**-" + m.group()[-4:])
    for m in CARD.finditer(text):
        d = re.sub(r"\D", "", m.group())
        if 13 <= len(d) <= 19 and luhn(d):
            yield ecp.Finding("PII", "credit_card", 0.9, ecp.mask_tail(d))
    for m in PHONE.finditer(text):
        yield ecp.Finding("PII", "phone", 0.6, ecp.mask_tail(re.sub(r"\D", "", m.group())))


def secret(text):
    for m in AWS_KEY.finditer(text):
        yield ecp.Finding("SECRET", "aws_access_key_id", 0.99, ecp.mask_head(m.group()))
    for m in GITHUB_TOKEN.finditer(text):
        yield ecp.Finding("SECRET", "github_token", 0.99, ecp.mask_head(m.group()))
    for m in PRIVATE_KEY.finditer(text):
        yield ecp.Finding("SECRET", "private_key", 0.99, f"-----BEGIN {m.group(1)}-----")
    for m in GENERIC_KEY.finditer(text):
        if ecp.entropy(m.group(2)) >= 3.5:
            yield ecp.Finding("SECRET", "generic_api_key", 0.7, f"{m.group(1)}=***")


def classify_http(segments, labels):
    out = []
    for _, text in segments:
        if "PII" in labels:
            out += pii(text)
        if "SECRET" in labels:
            out += secret(text)
    return out


ecp.serve(name="regex", version="0.2-prototype", http_labels=["PII", "SECRET"], classify_http=classify_http)
