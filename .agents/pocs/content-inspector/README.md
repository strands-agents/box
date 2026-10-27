# PROTOTYPE — throwaway: three content inspectors, one protocol

Three separate inspectors speak the same protocol, the Egress Classification Protocol
(`../egress-classification-protocol/SPEC.md`, draft 0.2). Box can use any of them without a
change, because it talks only the protocol. No tests. Do not build on it.

| Inspector | What it is | Needs | `http` labels |
|---|---|---|---|
| `regex-rules.py` | Regular expressions with a Luhn and an entropy check | Python 3 only | `PII`, `SECRET` |
| `presidio.py` | Microsoft Presidio with spaCy `en_core_web_sm` | `presidio-analyzer`, the spaCy model | `PII` |
| `strands-decider.py` | Strands Decider, a local 2B model, asked one yes/no question per label | `torch`, `strands-decider`, about 4.4 GB of weights | `PII`, `SECRET` |

`ecp.py` is the shared protocol library, the part a vendor would get as an SDK. It holds the
message envelope, `capabilities` and `classify`, the error codes, the stdio, unix, and https
transports, and the transport flags. It also holds the `dns` and `connect` rules, so every
inspector answers `TUNNELING`, `MALICIOUS_DOMAIN`, and `MALICIOUS_IP` the same way. Each inspector
file holds only its own detection logic, and ends in one `ecp.serve(...)` call.

## Install

```sh
cd .agents/pocs/content-inspector
python3 -m venv .venv
.venv/bin/pip install presidio-analyzer && .venv/bin/python -m spacy download en_core_web_sm
.venv/bin/pip install torch strands-decider    # Linux CPU: add --index-url https://download.pytorch.org/whl/cpu to torch
```

The first Decider run downloads its weights from Hugging Face. It needs no token and no AWS
credentials.

## Run

Every inspector takes one transport: `--stdio`, `--socket PATH`, or `--https 127.0.0.1:PORT`.

```sh
python3 -I regex-rules.py --https 127.0.0.1:8443 --cert leaf.pem --key leaf.key --token T
.venv/bin/python -I presidio.py --socket /tmp/inspector.sock
.venv/bin/python -I strands-decider.py --stdio --device mps
```

- All three take `--domain-blocklist FILE` and `--ip-blocklist FILE`, one entry per line, re-read
  when the file changes.
- `strands-decider.py` also takes `--device cpu|cuda|mps|mlx`, `--threshold 0.5`, `--model`, and
  `--max-state-chars 16384`.
- `--https` binds 127.0.0.1 only. The bearer token comes from `--token` or `$INSPECTOR_TOKEN`.

Send it requests with `client.py`:

```sh
.venv/bin/python -I client.py --socket /tmp/inspector.sock                 # capabilities, clean, pii, secret
.venv/bin/python -I client.py --socket /tmp/inspector.sock --body 'my ssn is 123-45-6789'
.venv/bin/python -I client.py --socket /tmp/inspector.sock --dns evil.example --connect x=10.0.0.1
.venv/bin/python -I client.py --https https://127.0.0.1:8443/v1/classify --cafile ca.pem --token T
```

## Notes

- Responses can arrive out of order, because requests on one connection run concurrently.
- Presidio and Decider load once and warm up before they serve, and then serialize behind a lock.
  Decider on this aarch64 CPU is about 1.5 s per question. A GPU brings it to about 150 ms.
- Decider gives no span. Its finding has `kind: "model"`, and the evidence is the probability,
  never the content.
- `TUNNELING` is a heuristic: a name over 100 characters, a label of 30 or more characters with
  Shannon entropy of 3.5 or more, or two hex- or base32-looking labels.
