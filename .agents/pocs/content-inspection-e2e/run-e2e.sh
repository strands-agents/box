#!/usr/bin/env bash
# PROTOTYPE(content-inspection): end-to-end check of outbound content inspection.
#
#   ./run-e2e.sh stdio [regex|presidio|decider|fake]   Box launches the inspector in a leaf
#   ./run-e2e.sh unix  [regex|presidio|decider|fake]   Box connects to a running inspector's socket
#   ./run-e2e.sh https [regex|presidio|decider]        Box POSTs to a running inspector on 127.0.0.1
#
# Protocol: .agents/pocs/egress-classification-protocol/SPEC.md (draft 0.2).
# Cases: (a) clean POST -> 200, (b) POST with an SSN -> 403, (c) SSN POST under a policy with no
# inspection rule -> 200, and the inspector is not called. Under policy-dns.dw (not with `fake`):
# (d) GET httpbin.org -> 200 with a clean resolve and connect, (e) a tunneling-shaped name -> denied
# at resolve, no connect, (f) a blocklisted name -> denied at resolve, (g) httpbin's addresses in the
# IP blocklist -> denied at connect, (h) two GETs in one box -> the second resolve is cached.
set -uo pipefail

MODE="${1:-stdio}"
case "$MODE" in stdio|unix|https) ;; *) echo "usage: $0 <stdio|unix|https> [regex|presidio|decider|fake]"; exit 2 ;; esac
BACKEND="${2:-regex}"
TIMEOUT_MS="${TIMEOUT_MS:-$([ "$BACKEND" = decider ] && echo 120000 || echo 2000)}"
HERE="$(cd "$(dirname "$0")" && pwd -P)"
REPO="$(cd "$HERE/../../.." && pwd -P)"
BOX="$REPO/target/debug/strands-box"
INSPECTOR_DIR="$REPO/.agents/pocs/content-inspector"
# PROTOTYPE(content-inspection): canonical, because macOS reaches /var through a /private symlink.
WORK="$(cd "$(mktemp -d /var/tmp/ci-e2e.XXXXXX)" && pwd -P)"
SOCK="$WORK/inspector.sock"
# PROTOTYPE(content-inspection): blocklists the inspector re-reads when they change.
LISTS="$WORK/lists"
mkdir -p "$LISTS"
echo "blocked.httpbin.org" > "$LISTS/domains"
: > "$LISTS/ips"
URL="https://httpbin.org/post"
export EXPERIMENTAL_LINUX_SUPPORT=TRUE
# The https bearer token: Box resolves it through its credential vault (`env://INSPECTOR_TOKEN`), and
# the inspector reads the same variable.
export INSPECTOR_TOKEN="${INSPECTOR_TOKEN:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

if [ "$BACKEND" = fake ]; then
  # A copy of /tmp/fake_inspector.py: the Linux leaf mounts a fresh /tmp.
  PY=/usr/bin/python3
  LEAF_PY=/usr/bin/python3
  LEAF_PY_FLAGS=(-I)
  SCRIPT="$HERE/fake_inspector.py"
  INSPECTOR_ARGS=()
  PY_READS=(/usr/lib64/python3.9 /usr/lib/python3.9)
  LEAF_ENV=""
else
  PY="$INSPECTOR_DIR/.venv/bin/python"
  case "$BACKEND" in
  regex) SCRIPT="$INSPECTOR_DIR/regex-rules.py" ;;
  presidio) SCRIPT="$INSPECTOR_DIR/presidio.py" ;;
  decider) SCRIPT="$INSPECTOR_DIR/strands-decider.py" ;;
  *) echo "usage: $0 <stdio|unix|https> <regex|presidio|decider|fake>"; exit 2 ;;
  esac
  INSPECTOR_ARGS=(--domain-blocklist "$LISTS/domains" --ip-blocklist "$LISTS/ips")
  # DEVICE=mps on an Apple Silicon Mac, DEVICE=cuda on an NVIDIA host.
  [ "$BACKEND" = decider ] && INSPECTOR_ARGS+=(--device "${DEVICE:-cpu}")
  # The venv python links to the system (mise) interpreter, so the leaf reads both trees.
  PY_REAL="$(readlink -f "$PY")"
  PY_PREFIX="$(cd "$(dirname "$PY_REAL")/.." && pwd -P)"
  PY_READS=("$PY_PREFIX")  # the script directory below also covers .venv
  # The venv's python links through /home/fdingler, a symlink the Linux leaf view does not carry,
  # so the leaf runs the real interpreter and adds the venv's site-packages itself (Box reserves
  # every PYTHON* variable, so PYTHONPATH is not an option).
  LEAF_PY="$PY_REAL"
  SITE="$(ls -d "$INSPECTOR_DIR"/.venv/lib/python3*/site-packages)"
  LEAF_PY_FLAGS=(-I -c "import sys, runpy, site; site.addsitedir('$SITE'); sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')")
  LEAF_ENV=""
  [ "$BACKEND" = decider ] && PY_READS+=("$(readlink -f "$HOME/.cache/huggingface")")
  # PROTOTYPE(content-inspection): on macOS the leaf starts in the agent workspace, where getcwd()
  # needs a read (torch calls os.path.abspath at import), and Homebrew python loads its dylibs
  # (openssl, xz, zstd, mpdecimal) through /opt/homebrew/opt symlinks outside the interpreter prefix.
  if [ "$(uname)" = Darwin ]; then
    case "$PY_PREFIX" in /opt/homebrew/*) PY_READS=(/opt/homebrew/Cellar /opt/homebrew/opt "${PY_READS[@]:1}") ;; esac
    PY_READS+=("$WORK/ws")
    # The Linux leaf gets a fresh /tmp; a Seatbelt leaf needs its own writable TMPDIR (torch cache).
    LEAF_TMP="$WORK/leaf-tmp"
    LEAF_ENV=", TMPDIR = \"$LEAF_TMP\""
    PY_READS+=("$LEAF_TMP")
  fi
fi

(cd "$REPO" && cargo build -q -p strands-box -p strands-box-containment --all-features >/dev/null 2>&1) || { echo "cargo build failed"; exit 1; }

toml_list() { local out="" x; for x in "$@"; do out+="\"$x\", "; done; echo "[${out%, }]"; }

write_config() { # $1 = policy file, $2 = config path, $3 = state dir
  {
    echo "name = \"inspection-e2e\""
    echo "box_dir = \"$3\""
    echo "policy = \"$1\""
    echo
    echo "[agent]"
    echo "command = [\"/usr/bin/curl\"]"
    echo "workspace = \"$WORK/ws\""
    echo "env = { PATH = \"/usr/bin:/bin\", HOME = \"$WORK/home\" }"
    # PROTOTYPE(content-inspection): macOS curl (LibreSSL) opens openssl.cnf at startup.
    [ "$(uname)" = Darwin ] && { echo "[agent.filesystem]"; echo "read_file = [\"/private/etc/ssl/openssl.cnf\"]"; }
    echo
    echo "[egress.inspector]"
    echo "timeout_ms = $TIMEOUT_MS"
    case "$MODE" in
    unix)
      echo "endpoint = \"unix://$SOCK\""
      ;;
    https)
      echo "endpoint = \"https://127.0.0.1:$PORT/v1/classify\""
      echo "secret.ref = \"env://INSPECTOR_TOKEN\""
      echo "ca_file = \"$WORK/tls/ca.pem\""
      ;;
    stdio)
      echo "command = $(toml_list "$LEAF_PY" "${LEAF_PY_FLAGS[@]}" "$SCRIPT" --stdio "${INSPECTOR_ARGS[@]}")"
      echo "env = { PATH = \"/usr/bin:/bin\", HF_HUB_OFFLINE = \"1\", HOME = \"$(readlink -f "$HOME")\"$LEAF_ENV }"
      # PROTOTYPE(content-inspection): MPS needs the leaf's GPU grant; GPU=0 leaves it out.
      [ "${DEVICE:-cpu}" = mps ] && [ "${GPU:-1}" = 1 ] && echo "gpu = true"
      echo "[egress.inspector.filesystem]"
      echo "read = $(toml_list "${PY_READS[@]}" "$(dirname "$SCRIPT")" "$LISTS")"
      [ -n "${LEAF_TMP:-}" ] && echo "write = $(toml_list "$LEAF_TMP")"
      ;;
    esac
  } > "$2"
}

INSPECTOR_PID=""
INSPECTOR_LOG="$WORK/inspector.log"
if [ "$MODE" = https ]; then
  [ "$BACKEND" = fake ] && { echo "the fake backend has no https binding"; exit 2; }
  # A throwaway CA and a leaf for 127.0.0.1; rustls refuses a CA certificate used as the leaf.
  mkdir -p "$WORK/tls"
  (cd "$WORK/tls" &&
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj /CN=inspection-e2e-ca &&
    openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=localhost &&
    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > leaf.ext &&
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 1 -extfile leaf.ext
  ) > "$WORK/tls/openssl.log" 2>&1 || { echo "openssl failed"; cat "$WORK/tls/openssl.log"; exit 1; }
  PORT="${PORT:-$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
  "$PY" -I "$SCRIPT" --https "127.0.0.1:$PORT" --cert "$WORK/tls/leaf.pem" --key "$WORK/tls/leaf.key" \
    "${INSPECTOR_ARGS[@]}" 2> "$INSPECTOR_LOG" &
  INSPECTOR_PID=$!
  for _ in $(seq 1 3000); do grep -q '^\[inspector\] listening' "$INSPECTOR_LOG" 2>/dev/null && break; sleep 0.1; done
  grep -q '^\[inspector\] listening' "$INSPECTOR_LOG" || { echo "inspector never listened"; cat "$INSPECTOR_LOG"; exit 1; }
elif [ "$MODE" = unix ]; then
  "$PY" -I "$SCRIPT" --socket "$SOCK" "${INSPECTOR_ARGS[@]}" 2> "$INSPECTOR_LOG" &
  INSPECTOR_PID=$!
  for _ in $(seq 1 3000); do [ -S "$SOCK" ] && break; sleep 0.1; done
  [ -S "$SOCK" ] || { echo "inspector socket never appeared"; cat "$INSPECTOR_LOG"; exit 1; }
fi
trap '[ -n "$INSPECTOR_PID" ] && kill "$INSPECTOR_PID" 2>/dev/null' EXIT

mkdir -p "$WORK/home" "$WORK/ws" ${LEAF_TMP:+"$LEAF_TMP"}
# PROTOTYPE(content-inspection): Box prints nothing per request, so the checks read the inspector's
# own log, scoped to one case: the shared log's new lines (unix, https) or the box's stderr, where
# the leaf's stderr passes through (stdio).
CLASSIFY=' classify |^fake_inspector: '
log_mark() { if [ "$MODE" = stdio ]; then echo 0; else wc -l < "$INSPECTOR_LOG" 2>/dev/null || echo 0; fi; }
log_slice() { # $1 = case name, $2 = mark before the case
  if [ "$MODE" = stdio ]; then
    grep -E "$CLASSIFY" "$WORK/$1.stderr" > "$WORK/$1.inspector" || true
  else
    tail -n +"$(($2 + 1))" "$INSPECTOR_LOG" | grep -E "$CLASSIFY" > "$WORK/$1.inspector" || true
  fi
}
run_case() { # $1 = name, $2 = policy, $3 = body, $4 = expected status
  local name="$1" state="$WORK/state-$1" config="$WORK/box-$1.toml" out mark
  write_config "$HERE/$2" "$config" "$state"
  mark="$(log_mark)"
  cp "$config" "$HERE/box-$MODE-$name.toml"
  out="$("$BOX" run --config "$config" -- -sS -o /dev/null -w 'status=%{http_code}\n' \
        -X POST -H 'content-type: application/json' -H 'authorization: Bearer hunter2' \
        --data "$3" "$URL" 2> "$WORK/$name.stderr")"
  log_slice "$name" "$mark"
  local status; status="$(sed -n 's/^status=//p' <<<"$out")"
  echo "--- case $name: expect $4, got ${status:-none}"
  { grep -E 'http:request gate' "$WORK/$name.stderr"; cat "$WORK/$name.inspector"; } | sed 's/^/    /'
  [ "$status" = "$4" ] && echo "    PASS" || { echo "    FAIL"; sed 's/^/    | /' "$WORK/$name.stderr" | tail -25; }
}

run_case a-clean policy.dw '{"msg":"hello"}' 200
run_case b-pii policy.dw '{"ssn":"123-45-6789"}' 403
run_case c-no-rule policy-noinspect.dw '{"ssn":"123-45-6789"}' 200
if [ -s "$WORK/c-no-rule.inspector" ]; then
  echo "    FAIL: the inspector was called under a policy with no inspection rule"
else
  echo "    PASS: the inspector logged no classify line under the no-rule policy"
fi

# PROTOTYPE(content-inspection): dns and connect subjects. $1 = name, $2 = expect (200 or deny),
# then curl URLs. The status is curl's %{http_code}, the CONNECT reply, and curl's exit code.
run_get() {
  local name="$1" expect="$2" state="$WORK/state-$1" config="$WORK/box-$1.toml" out args=() u rc mark
  shift 2
  for u in "$@"; do args+=(-o /dev/null "$u"); done
  write_config "$HERE/policy-dns.dw" "$config" "$state"
  mark="$(log_mark)"
  cp "$config" "$HERE/box-$MODE-$name.toml"
  out="$("$BOX" run --config "$config" -- -sS -w 'status=%{http_code} connect=%{http_connect}\n' \
        "${args[@]}" 2> "$WORK/$name.stderr")"
  rc=$?
  log_slice "$name" "$mark"
  local statuses; statuses="$(sed -n 's/^status=\([0-9]*\).*/\1/p' <<<"$out" | tr '\n' ' ')"
  echo "--- case $name: expect $expect, got: $(tr '\n' ';' <<<"$out") curl exit=$rc"
  { grep -E 'gate|forbid|denied' "$WORK/$name.stderr"; cat "$WORK/$name.inspector"; } | sed 's/^/    /'
  local ok=1
  if [ "$expect" = 200 ]; then
    for u in "$@"; do :; done
    [ "$(tr -d ' ' <<<"$statuses")" = "$(printf '200%.0s' "$@")" ] || ok=0
  else
    grep -q ' 200' <<<" $statuses" && ok=0
    [ "$rc" = 0 ] && ok=0
  fi
  CASE_OK=$ok
}
check() { # $1 = description, then a command that must succeed
  local what="$1"; shift
  if "$@"; then echo "    PASS: $what"; else echo "    FAIL: $what"; fi
}
has() { grep -qE "$2" "$WORK/$1.inspector"; }
hasnt() { ! grep -qE "$2" "$WORK/$1.inspector"; }
count() { [ "$(grep -cE "$2" "$WORK/$1.inspector")" = "$3" ]; }
DNS=' classify dns '
CONNECT=' classify connect '

if [ "$BACKEND" != fake ]; then
  run_get d-dns-clean 200 https://httpbin.org/get
  check "status 200" [ "$CASE_OK" = 1 ]
  check "resolve inspected with labels=[]" has d-dns-clean "${DNS}httpbin.org:443 asked=.* -> \[\]$"
  check "connect inspected with labels=[]" has d-dns-clean "${CONNECT}httpbin.org [0-9a-f.:]+:443 asked=.* -> \[\]$"

  TUNNEL="$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n').httpbin.org"
  run_get e-dns-tunnel deny "https://$TUNNEL/get"
  check "denied" [ "$CASE_OK" = 1 ]
  check "resolve labelled TUNNELING" has e-dns-tunnel "${DNS}$TUNNEL:443 asked=.* -> \['TUNNELING'\]$"
  check "never reached connect (no DNS query)" hasnt e-dns-tunnel "$CONNECT"

  run_get f-dns-blocked deny https://blocked.httpbin.org/get
  check "denied" [ "$CASE_OK" = 1 ]
  check "resolve labelled MALICIOUS_DOMAIN" has f-dns-blocked "${DNS}blocked.httpbin.org:443 asked=.* -> \['MALICIOUS_DOMAIN'\]$"
  check "never reached connect" hasnt f-dns-blocked "$CONNECT"

  # Every /16 that httpbin.org resolves to here, so a rotated address is still listed.
  python3 -c 'import ipaddress, socket
for a in sorted({i[4][0] for i in socket.getaddrinfo("httpbin.org", 443)}):
    ip = ipaddress.ip_address(a)
    print(ipaddress.ip_network(f"{a}/{16 if ip.version == 4 else 48}", strict=False))' > "$LISTS/ips"
  echo "--- ip blocklist for case g: $(tr '\n' ' ' < "$LISTS/ips")"
  run_get g-connect-blocked deny https://httpbin.org/get
  : > "$LISTS/ips"
  check "denied" [ "$CASE_OK" = 1 ]
  check "resolve passed with labels=[]" has g-connect-blocked "${DNS}httpbin.org:443 asked=.* -> \[\]$"
  check "connect labelled MALICIOUS_IP" has g-connect-blocked "${CONNECT}httpbin.org [0-9a-f.:]+:443 asked=.* -> \['MALICIOUS_IP'\]$"

  run_get h-dns-cached 200 https://httpbin.org/get https://httpbin.org/anything
  check "both 200" [ "$CASE_OK" = 1 ]
  check "resolve classified with labels=[]" has h-dns-cached "${DNS}httpbin.org:443 asked=.* -> \[\]$"
  check "second resolve cached (one dns classify for two GETs)" count h-dns-cached "${DNS}httpbin.org:443 " 1
fi
echo "work dir: $WORK"
