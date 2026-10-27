# PROTOTYPE — throwaway: content inspection at the egress gateway

Strands Box can deny an outbound HTTP request because of what it carries. A policy asks for a
classification, Box sends the decrypted request to an inspector you choose, and Dogwood decides on
the labels the inspector returns.

```cedar
forbid (principal, action == Box::Action::"http:request", resource)
when { Inspection::Content(["PII", "SECRET"]).labels.containsAny(["PII", "SECRET"]) };
```

This is a prototype on branch `feature/prototype-content-inspection`. It is not a shipped feature,
and nothing here is a stable interface.

## How it works

```text
agent (curl) ──HTTPS──▶ egress gateway (MITM, body buffered)
                              │ policy uses Inspection::Content?  no ─▶ decide as usual
                              │ yes
                              ▼
                        inspector  ◀── protocol 0.2 `classify`: http subject (auth redacted), labels
                              │      ──▶ {"result":{"labels":["PII"], "findings":[...]}}
                              ▼
                        Dogwood decides with the labels ─▶ 200 or 403
```

- The inspector is any program that speaks the protocol in
  `../egress-classification-protocol/SPEC.md` (draft 0.2). `../content-inspector/` holds three
  separate inspectors: `regex-rules.py`, `presidio.py`, and `strands-decider.py` (Strands Decider,
  a local 2B model).
- Box reaches the inspector in one of three ways:
  - **unix**: the inspector runs outside the box, started by you, on a socket you own that is not
    group- or other-writable. Box keeps one connection and reconnects after it drops.
  - **https**: the inspector runs outside the box. Box sends one POST per message, with a bearer
    token that Box resolves through its credential vault.
  - **command** (stdio): Box starts the inspector once, in a contained leaf, and talks to it on
    stdio. `gpu = true` lets that leaf use Metal on macOS.
- At startup Box sends `capabilities`. Box refuses to start if the inspector is unreachable, has no
  `0.x` version, or does not list the subject a provider in the policy needs (`http` for
  `Inspection::Content`, `dns` for `Inspection::Domain`, `connect` for `Inspection::Address`). Box
  prints the inspector's name and its labels per subject, and warns about each policy label the
  inspector does not list for that subject.
- `Inspection::Domain([...])` on `net:resolve` sends a `dns` subject before any DNS query leaves.
  `Inspection::Address([...])` on `net:connect` sends a `connect` subject per resolved address.
  Box reuses a `dns` or `connect` answer for its `cache_ttl_s` (in memory, at most 4096 entries),
  so a cached answer makes no new `classify` line in the inspector's log. `policy-dns.dw` is the example.
- If the inspector fails, times out, or the body is over the inspector's `max_body_bytes`, the
  request is denied.
- If the policy never calls `Inspection::Content`, the inspector is not called at all.
- `authorization`, `proxy-authorization`, and `cookie` values are redacted before the inspector sees
  them.

## Configuration

Set exactly one of `endpoint` and `command`.

```toml
[egress.inspector]
timeout_ms = 2000                  # end to end, per call; use 120000 for Decider on CPU

# unix: connect to an inspector that is already running.
endpoint = "unix:///abs/path/inspector.sock"

# https: POST to an inspector that is already running. `http://` is refused.
# endpoint = "https://127.0.0.1:8443/v1/classify"
# secret.ref = "env://INSPECTOR_TOKEN"   # a Box credential locator for the bearer token
# ca_file = "/abs/path/ca.pem"           # optional extra trust root (prototype knob)

# stdio: Box starts it in a leaf.
# command = ["/path/to/python3", "/path/to/regex-rules.py", "--stdio"]
# env = { HOME = "/Users/you" }
# gpu = true                       # macOS only: Metal for the leaf, and only this leaf
# [egress.inspector.filesystem]
# read = ["/path/to/python/prefix", "/path/to/content-inspector"]
```

## Set up (macOS, Apple Silicon)

From the repository root:

```sh
cargo build -p strands-box -p strands-box-containment --all-features

cd .agents/pocs/content-inspector
python3 -m venv .venv
.venv/bin/pip install torch strands-decider
.venv/bin/python -c "import torch; print('mps:', torch.backends.mps.is_available())"
cd -
```

The first Decider run downloads about 4.4 GB of weights from Hugging Face. No token or AWS
credentials are needed.

## Demo 1: a shared inspector on the GPU (unix)

**Terminal 1** — start the inspector. Decider takes about 20 s to load; wait for the
`decider loaded ... on mps` line.

```sh
cd .agents/pocs/content-inspector
.venv/bin/python -I strands-decider.py --socket /tmp/inspector.sock --device mps
```

Use `regex-rules.py` instead for an instant start and ~1 ms answers.

**Terminal 2** — write a box. Run this from the repository root.

```sh
export DEMO="$(cd /tmp && pwd -P)/inspection-demo"
mkdir -p "$DEMO/ws" "$DEMO/home"
cp .agents/pocs/content-inspection-e2e/policy.dw "$DEMO/policy.dw"
cat > "$DEMO/box.toml" <<EOF
name = "inspection-demo"
box_dir = "$DEMO/state"
policy = "$DEMO/policy.dw"

[agent]
command = ["/usr/bin/curl"]
workspace = "$DEMO/ws"
env = { PATH = "/usr/bin:/bin", HOME = "$DEMO/home" }
[agent.filesystem]
read_file = ["/private/etc/ssl/openssl.cnf"]

[egress.inspector]
endpoint = "unix:///private/tmp/inspector.sock"
timeout_ms = 10000
EOF
cat "$DEMO/policy.dw"
```

On Linux, leave out the `[agent.filesystem]` table, use `/tmp/inspector.sock` as the socket, and
`export EXPERIMENTAL_LINUX_SUPPORT=TRUE`.

The policy permits HTTPS to `httpbin.org` and forbids any request labelled `PII` or `SECRET`.

Each command below runs `curl` inside a new box. The arguments after `--` go to `curl`.

```sh
BOX=./target/debug/strands-box
post() { $BOX run --config "$DEMO/box.toml" -- -sS -w '\nstatus=%{http_code}\n' \
           -X POST -H 'content-type: application/json' --data "$1" https://httpbin.org/post; }

post '{"msg":"hello world"}'                               # 200, labels=[]
post '{"name":"Jane Doe","ssn":"123-45-6789"}'             # 403, labels=["PII"]
post '{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}'        # 403, labels=["SECRET"]
```

What to point at on screen:

- the clean request returns httpbin's echo and `status=200`;
- the box prints nothing per request; the inspector's log (Terminal 1) has one `classify` line per
  inspected request, for example `box-2 classify POST https://httpbin.org/post ... -> ['PII'] 1400ms`;
- the PII and secret requests get `status=403` from the gateway, and the request never leaves
  the machine;

**Redaction.** Credentials in headers are not sent to the inspector:

```sh
$BOX run --config "$DEMO/box.toml" -- -sS -o /dev/null -w 'status=%{http_code}\n' \
  -H 'authorization: Bearer ghp_notarealtoken' https://httpbin.org/get     # 200
```

**No rule, no inspection.** Switch to the control policy, and the same SSN request passes. Terminal 1
logs no `classify` line.

```sh
cp .agents/pocs/content-inspection-e2e/policy-noinspect.dw "$DEMO/policy.dw"
post '{"ssn":"123-45-6789"}'                               # 200
cp .agents/pocs/content-inspection-e2e/policy.dw "$DEMO/policy.dw"
```

**Fail closed.** Stop the inspector in Terminal 1 (Ctrl-C), and send the clean request again.
It gets 403 if the box is already running; a new box refuses to start, because `capabilities`
fails. The 403 body says `content inspection failed: ...`.

## Demo 2: Box starts the inspector in a contained leaf, on the GPU

The leaf needs read grants for the Python interpreter, the venv, and the model cache, so the e2e
script writes this config for you. It runs a clean POST (200), an SSN POST (403), and an SSN POST
under the control policy (200, inspector not called). Then, under `policy-dns.dw`: (d) a GET to
httpbin.org (200, inspector `classify dns` and `classify connect` lines with `-> []`), (e) a GET to a
40-hex-character subdomain (denied at resolve with `TUNNELING`, no `classify connect` line, curl
exit 7, CONNECT 403), (f) a
GET to a name in `--domain-blocklist` (denied with `MALICIOUS_DOMAIN`), (g) a GET with httpbin's
address ranges in `--ip-blocklist` (denied at connect with `MALICIOUS_IP`), and (h) two GETs in one
box (one `classify dns` line, because Box caches the second resolve). The `fake` backend runs only a to c.

```sh
cd .agents/pocs/content-inspection-e2e
DEVICE=mps ./run-e2e.sh stdio decider
cat box-stdio-b-pii.toml          # the generated config: command, filesystem grants, gpu = true
```

On screen, the startup disclosure lists the leaf's grants, including
`gpu  Metal (AGX, IOSurface, MTLCompilerService)`, and then
`inspection: inspector leaf started (pid ...)` and the capabilities line.

To show that the GPU grant is what makes this work, run it without the grant. Case a fails with
403, and the inspector's stderr shows `The MPS backend is supported on macOS 14.0+`:

```sh
GPU=0 DEVICE=mps ./run-e2e.sh stdio decider
```

`gpu = true` adds three Seatbelt rules to this leaf only, never to the agent or another tool:

```scheme
(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient" "IOSurfaceRootUserClient"))
(allow sysctl-read (sysctl-name "hw.memsize"))
(allow mach-lookup (xpc-service-name "com.apple.MTLCompilerService"))
```

## All runs

```sh
cd .agents/pocs/content-inspection-e2e
./run-e2e.sh stdio regex
./run-e2e.sh unix  regex
./run-e2e.sh https regex     # makes a throwaway CA and a 127.0.0.1 cert with openssl
DEVICE=mps ./run-e2e.sh unix  decider
DEVICE=mps ./run-e2e.sh stdio decider
```

On Linux, set nothing extra: the script exports `EXPERIMENTAL_LINUX_SUPPORT=TRUE`. `gpu = true`
is accepted there and does nothing.

## Measured latency per request

| Backend | Where | Latency |
|---|---|---|
| regex | any | 0–4 ms |
| Decider | M1 GPU, socket | 1.2–1.4 s |
| Decider | M1 GPU, leaf | 2.0–2.2 s |
| Decider | M1 CPU | 1.7–2.3 s |
| Decider | Linux aarch64 CPU | ~3.2 s |

## Known gaps

- A denial from inspection is not written to the policy history.
- The leaf is not restarted if it exits; every request after that is denied.
- `NEWLY_REGISTERED` is not implemented by the inspectors in `../content-inspector/`, so it is not advertised.
- A provider used on another action than its own (for example `Inspection::Domain` in an
  `http:request` rule) sees no labels.
- The inspector only sees request bodies. Responses, MCP tool arguments, and file writes are not
  inspected.
- Decider's accuracy is not measured. In one smoke test it missed a GitHub token that the regex
  inspector caught.
