"""PROTOTYPE Egress Classification Protocol 0.2: the shared plumbing every inspector imports.

An inspector supplies its name, its http labels, and one function that classifies http segments.
`serve` does the rest: the envelope, `capabilities` and `classify`, the stdio, unix, and https
bindings, and the `dns` and `connect` subjects.
"""

import argparse
import asyncio
import base64
import collections
import ipaddress
import json
import math
import os
import re
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit

PROTOCOL_V = "0.2"
BODY_CAP = 1 << 20  # advertised as subjects.http.max_body_bytes
LINE_LIMIT = 16 << 20
HTTP_STATUS = {
    "invalid_request": 400,
    "unsupported_version": 400,
    "unsupported_subject": 400,
    "unauthorized": 401,
    "too_large": 413,
    "rate_limited": 429,
    "internal": 500,
}

Finding = collections.namedtuple("Finding", "label kind confidence evidence")


def log(*a):
    print("[inspector]", *a, file=sys.stderr, flush=True)


class ProtocolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- helpers for inspectors


def mask_tail(s, keep=4):
    return "*" * max(len(s) - keep, 0) + s[-keep:]


def mask_head(s, keep=4):
    return s[:keep] + "*" * max(len(s) - keep, 0)


def mask_email(s):
    user, _, dom = s.partition("@")
    return f"{user[:1]}***@{dom}"


def entropy(s):
    n = len(s)
    return -sum(s.count(c) / n * math.log2(s.count(c) / n) for c in set(s))


def segments(subject, raw=None):
    """(where, text) pairs of an http subject: URL query values, header values, body."""
    out = []
    url = subject.get("url") or ""
    try:
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            out.append(("query", f"{k}={v}"))
    except ValueError:
        out.append(("url", url))
    for h in subject.get("headers") or []:
        if isinstance(h, (list, tuple)) and len(h) == 2:
            out.append(("header", f"{h[0]}: {h[1]}"))
    if raw:
        out.append(("body", raw.decode("utf-8", errors="replace")))
    return out


# ---------------------------------------------------------------- dns and connect subjects

DNS_LABELS = ("MALICIOUS_DOMAIN", "TUNNELING")
CONNECT_LABELS = ("MALICIOUS_IP",)
NAME_CACHE_TTL_S = 300
BUILTIN_DOMAINS = {"malware.testing.google.test", "evil.example", "phishing.example", "c2.example"}
RE_HEXISH = re.compile(r"^(?:[0-9a-f]{16,}|[a-z2-7]{24,})$")


class Blocklist:
    """One entry per line; `#` starts a comment. Re-read when the file changes."""

    def __init__(self, path, parse):
        self.path, self.parse, self.stamp, self.entries = path, parse, None, []
        self.lock = threading.Lock()

    def get(self):
        if not self.path:
            return []
        with self.lock:
            try:
                st = os.stat(self.path)
                stamp = (st.st_mtime_ns, st.st_size)
            except OSError:
                stamp = None
            if stamp != self.stamp:
                self.stamp, self.entries = stamp, []
                if stamp is not None:
                    with open(self.path) as f:
                        for line in f:
                            line = line.split("#", 1)[0].strip()
                            if line:
                                self.entries.append(self.parse(line))
                log(f"loaded {len(self.entries)} entries from {self.path}")
            return self.entries


DOMAINS = Blocklist(None, lambda l: l.lower().rstrip("."))
NETWORKS = Blocklist(None, lambda l: ipaddress.ip_network(l, strict=False))


def tunneling(name):
    labels = name.split(".")
    if len(name) > 100:
        return ("long_name", 0.8, f"{len(name)} characters")
    for lab in labels:
        if len(lab) >= 30 and entropy(lab) >= 3.5:
            return ("high_entropy_label", 0.9, f"{len(lab)}-char label, entropy {entropy(lab):.2f}")
    encoded = [lab for lab in labels[:-2] if RE_HEXISH.match(lab)]
    if len(encoded) >= 2:
        return ("encoded_labels", 0.7, f"{len(encoded)} hex/base32 labels")
    return None


def malicious_domain(name):
    parts = name.split(".")
    listed = BUILTIN_DOMAINS | set(DOMAINS.get())
    for i in range(len(parts)):
        if ".".join(parts[i:]) in listed:
            return ("blocklist", 1.0, ".".join(parts[i:]))
    return None


def malicious_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ProtocolError("invalid_request", f"subject.ip {ip!r} is not an address")
    for net in NETWORKS.get():
        if addr.version == net.version and addr in net:
            return ("blocklist", 1.0, str(net))
    return None


def classify_name(subject, labels):
    name = subject.get("name")
    if not isinstance(name, str) or not name:
        raise ProtocolError("invalid_request", "subject.name is required")
    out = []
    if subject["kind"] == "dns":
        if "TUNNELING" in labels and (f := tunneling(name)):
            out.append(("TUNNELING", *f))
        if "MALICIOUS_DOMAIN" in labels and (f := malicious_domain(name)):
            out.append(("MALICIOUS_DOMAIN", *f))
    else:
        if "MALICIOUS_IP" in labels and (f := malicious_ip(subject.get("ip") or "")):
            out.append(("MALICIOUS_IP", *f))
    return out


# ---------------------------------------------------------------- protocol


class Inspector:
    def __init__(self, name, version, http_labels, classify_http):
        self.name, self.version = name, version
        self.http_labels = tuple(http_labels)
        self.classify_http = classify_http


def dedupe(findings):
    seen, out = set(), []
    for label, kind, conf, ev in findings:
        k = (label, kind, ev)
        if k not in seen:
            seen.add(k)
            out.append({"label": label, "kind": kind, "confidence": conf, "evidence": ev})
    return out


def capabilities(insp):
    return {
        "versions": [PROTOCOL_V],
        "inspector": {"name": insp.name, "version": insp.version},
        "subjects": {
            "http": {"labels": list(insp.http_labels), "max_body_bytes": BODY_CAP},
            "dns": {"labels": list(DNS_LABELS)},
            "connect": {"labels": list(CONNECT_LABELS)},
        },
    }


def classify(insp, params, rid):
    subject = params.get("subject")
    if not isinstance(subject, dict):
        raise ProtocolError("invalid_request", "params.subject is required")
    kind = subject.get("kind")
    if kind not in ("http", "dns", "connect"):
        raise ProtocolError("unsupported_subject", f"this inspector does not classify {kind!r}")
    asked = params.get("labels")
    if not isinstance(asked, list) or not asked or not all(isinstance(l, str) for l in asked):
        raise ProtocolError("invalid_request", "params.labels must be a non-empty list of strings")
    if kind != "http":
        supported = DNS_LABELS if kind == "dns" else CONNECT_LABELS
        labels = [l for l in dict.fromkeys(asked) if l in supported]
        findings = dedupe(classify_name(subject, labels))
        found = [l for l in dict.fromkeys(f["label"] for f in findings) if l in labels]
        where = subject.get("name") if kind == "dns" else f"{subject.get('name')} {subject.get('ip')}"
        log(f"{rid} classify {kind} {where}:{subject.get('port')} asked={asked} -> {found}")
        return {"labels": found, "findings": findings, "cache_ttl_s": NAME_CACHE_TTL_S}
    raw = b""
    if subject.get("body_b64"):
        try:
            raw = base64.b64decode(subject["body_b64"], validate=True)
        except ValueError:
            raise ProtocolError("invalid_request", "body_b64 is not standard base64")
    if len(raw) > BODY_CAP:
        raise ProtocolError("too_large", f"body is {len(raw)} bytes, limit is {BODY_CAP}")
    labels = [l for l in dict.fromkeys(asked) if l in insp.http_labels]
    segs = segments(subject, raw)
    t = time.monotonic()
    findings = dedupe(insp.classify_http(segs, labels)) if labels and segs else []
    ms = round((time.monotonic() - t) * 1000)
    found = [l for l in dict.fromkeys(f["label"] for f in findings) if l in labels]
    log(
        f"{rid} classify {subject.get('method')} {subject.get('url')} "
        f"headers={subject.get('headers')} asked={asked} -> {found} {ms}ms"
    )
    return {"labels": found, "findings": [f for f in findings if f["label"] in found]}


def respond(insp, line):
    """One request line (bytes or str) -> one response dict. Never raises."""
    rid = None
    try:
        try:
            msg = json.loads(line)
        except ValueError:
            raise ProtocolError("invalid_request", "the message is not JSON")
        if not isinstance(msg, dict):
            raise ProtocolError("invalid_request", "the message is not an object")
        rid = msg.get("id") if isinstance(msg.get("id"), str) else None
        if rid is None:
            raise ProtocolError("invalid_request", "missing string id")
        v = msg.get("v")
        if not isinstance(v, str) or v.split(".")[0] != PROTOCOL_V.split(".")[0]:
            raise ProtocolError("unsupported_version", f"unsupported protocol version {v!r}")
        op, params = msg.get("op"), msg.get("params")
        if not isinstance(params, dict):
            raise ProtocolError("invalid_request", "params must be an object")
        if op == "capabilities":
            result = capabilities(insp)
            log(f"{rid} capabilities")
        elif op == "classify":
            result = classify(insp, params, rid)
        else:
            raise ProtocolError("invalid_request", f"unknown op {op!r}")
        return {"v": PROTOCOL_V, "id": rid, "result": result}
    except ProtocolError as e:
        log(f"{rid} error {e.code}: {e}")
        return {"v": PROTOCOL_V, "id": rid, "error": {"code": e.code, "message": str(e)}}
    except Exception as e:  # noqa: BLE001 - prototype: every failure becomes a typed error
        log(f"{rid} error internal: {type(e).__name__}: {e}")
        return {"v": PROTOCOL_V, "id": rid, "error": {"code": "internal", "message": f"{type(e).__name__}: {e}"}}


# ---------------------------------------------------------------- line bindings (stdio, unix)


async def pump(insp, reader, emit):
    """Read one message per line, answer each concurrently; `emit(bytes)` is an async writer."""
    lock = asyncio.Lock()
    loop = asyncio.get_running_loop()

    async def one(line):
        resp = await loop.run_in_executor(None, respond, insp, line)
        async with lock:
            await emit((json.dumps(resp) + "\n").encode())

    tasks = set()
    while True:
        try:
            line = await reader.readline()
        except (ValueError, asyncio.LimitOverrunError):
            err = {"v": PROTOCOL_V, "id": None, "error": {"code": "invalid_request", "message": "line over 16 MiB"}}
            async with lock:
                await emit((json.dumps(err) + "\n").encode())
            break
        if not line:
            break
        if line.strip():
            t = asyncio.create_task(one(line))
            tasks.add(t)
            t.add_done_callback(tasks.discard)
    if tasks:
        await asyncio.gather(*tasks)


async def serve_conn(insp, reader, writer):
    async def emit(b):
        writer.write(b)
        await writer.drain()

    try:
        await pump(insp, reader, emit)
    except ConnectionError:
        pass
    finally:
        writer.close()


async def serve_stdio(insp, out):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=LINE_LIMIT)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    async def emit(b):
        out.write(b)
        out.flush()

    log(f"serving stdio backend={insp.name}")
    await pump(insp, reader, emit)


async def serve_unix(insp, path):
    if os.path.exists(path):
        os.unlink(path)
    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(
            lambda r, w: serve_conn(insp, r, w), path=path, limit=LINE_LIMIT
        )
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    log(f"listening on unix {path} backend={insp.name}")
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------- https binding


def serve_https(insp, addr, cert, key, token):
    import http.server
    import ssl

    host, _, port = addr.rpartition(":")
    if host not in ("127.0.0.1", "localhost"):
        raise SystemExit("--https binds 127.0.0.1 only")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log("https", fmt % args)

        def reply(self, resp):
            body = json.dumps(resp).encode()
            err = resp.get("error")
            status = HTTP_STATUS.get(err["code"], 500) if err else 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > LINE_LIMIT:
                self.close_connection = True
                return self.reply({"v": PROTOCOL_V, "id": None, "error": {"code": "invalid_request", "message": "message over 16 MiB"}})
            raw = self.rfile.read(length)
            if token is not None and self.headers.get("Authorization") != f"Bearer {token}":
                try:
                    rid = json.loads(raw).get("id")
                except Exception:  # noqa: BLE001
                    rid = None
                rid = rid if isinstance(rid, str) else None
                log(f"{rid} error unauthorized: bad or missing bearer token")
                return self.reply({"v": PROTOCOL_V, "id": rid, "error": {"code": "unauthorized", "message": "bad or missing bearer token"}})
            self.reply(respond(insp, raw))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", int(port)), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    log(f"listening on https://127.0.0.1:{port} backend={insp.name} token={'set' if token else 'none'}")
    server.serve_forever()


# ---------------------------------------------------------------- entry point


def serve(*, name, version, http_labels, classify_http=None, load=None, flags=None):
    """Parse the transport flags, then serve until stdin closes or the process is stopped.

    Pass `classify_http(segments, labels) -> [Finding]` directly, or `load(args)` that returns one
    after the flags are parsed (for an inspector that loads a model). `flags(parser)` adds the
    inspector's own flags.
    """
    ap = argparse.ArgumentParser(description=f"{name}: an Egress Classification Protocol {PROTOCOL_V} inspector")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--stdio", action="store_true", help="one message per line on stdin/stdout")
    mode.add_argument("--socket", default=os.environ.get("INSPECTOR_SOCKET"), help="unix socket path")
    mode.add_argument("--https", metavar="HOST:PORT", help="https on 127.0.0.1 only")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--token", default=os.environ.get("INSPECTOR_TOKEN"))
    ap.add_argument("--domain-blocklist", help="MALICIOUS_DOMAIN names, one per line; re-read on change")
    ap.add_argument("--ip-blocklist", help="MALICIOUS_IP addresses or CIDRs, one per line; re-read on change")
    if flags:
        flags(ap)
    args = ap.parse_args()
    if not (args.stdio or args.https or args.socket):
        ap.error("one of --stdio, --socket PATH, or --https HOST:PORT is required")
    if args.https and not (args.cert and args.key):
        ap.error("--https needs --cert and --key")
    DOMAINS.path, NETWORKS.path = args.domain_blocklist, args.ip_blocklist

    out = None
    if args.stdio:
        # Keep the real stdout for protocol lines only; anything else printing to fd 1
        # (libraries, C extensions) lands on stderr.
        out = os.fdopen(os.dup(1), "wb", buffering=0)
        os.dup2(2, 1)
        sys.stdout = sys.stderr
    insp = Inspector(name, version, http_labels, classify_http or load(args))

    async def run():
        if args.stdio:
            await serve_stdio(insp, out)
        elif args.https:
            await asyncio.get_running_loop().run_in_executor(
                None, serve_https, insp, args.https, args.cert, args.key, args.token
            )
        else:
            await serve_unix(insp, args.socket)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
