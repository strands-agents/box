#!/bin/bash
# PROBE ONLY (issue 54): run a box against an upstream signed by a private "corporate" root,
# under each upstream trust mode, before and after the root is trusted in the macOS keychain.
set -u
T=${TARGET_DIR:-$PWD/target}/debug
W=$RUNNER_TEMP/h54
mkdir -p "$W/pki" "$W/area/corp" "$W/policydir" "$W/bin"
cd "$W/pki"
OPENSSL=$(brew --prefix openssl@3 2>/dev/null)/bin/openssl
[ -x "$OPENSSL" ] || OPENSSL=openssl
"$OPENSSL" version
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 \
  -subj "/CN=Corp Intercept Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
"$OPENSSL" req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=corp-intercept.test" 2>/dev/null
printf "subjectAltName=DNS:corp-intercept.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" > leaf.ext
"$OPENSSL" x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 30 -extfile leaf.ext 2>/dev/null
cp ca.pem "$W/area/corp/ca.pem"

cat > "$W/server.py" <<'PY'
import http.server, ssl, sys
log = open(sys.argv[2], "a", buffering=1)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log.write("authorization_seen_by_upstream=%s\n" % self.headers.get("Authorization"))
        body = b"hello"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1] + "/leaf.pem", sys.argv[1] + "/leaf.key")
s = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
python3 "$W/server.py" "$W/pki" "$W/upstream.log" &
echo "127.0.0.1 corp-intercept.test" | sudo tee -a /etc/hosts >/dev/null
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder || true
sleep 2
curl -sS --cacert "$W/pki/ca.pem" https://corp-intercept.test:8443/ && echo " <- host curl with --cacert"

cat > "$W/policydir/policy.dw" <<'EOF'
@id("corp_connect")
permit (principal, action == Box::Action::"net:connect", resource)
when { (context.input.host == "corp-intercept.test" && context.input.port == 8443) || (context.input.host == "api.github.com" && context.input.port == 443) };

@id("corp_request")
permit (principal, action == Box::Action::"http:request", resource)
when { context.input.host == "corp-intercept.test" || context.input.host == "api.github.com" };
EOF

cp "$T/strands-box" "$W/bin/box"
cp "$T/strands-box-sock-alias" "$T/strands-box-contain-trampoline" "$T/box-egress-probe" "$W/bin/"

# case <name> <mode: none|host|platform> <url> [extra top-level toml]
case_run() {
  local name=$1 mode=$2 url=$3 extra=${4:-}
  local C=$W/cases/$name
  mkdir -p "$C/config" "$C/workspace"
  cat > "$C/config/box.toml" <<TOML
name = "issue54-$name"
box_dir = "$C/config/state"
policy = "$W/policydir/policy.dw"
$extra

[agent]
command = ["$W/bin/box-egress-probe", "$url", "CORP_TOKEN"]
workspace = "$C/workspace"

[agent.filesystem]
exec = ["$W/bin/box-egress-probe"]

[egress.corp]
destinations = ["corp-intercept.test:8443"]
secret.ref = "env://CORP_TOKEN"
TOML
  : > "$W/upstream.log"
  local start end
  start=$(python3 -c 'import time; print(time.time())')
  if [ "$mode" = none ]; then
    (cd "$W" && CORP_TOKEN=real-secret-123 "$W/bin/box" run --config "$C/config/box.toml" >"$C/out.txt" 2>"$C/err.txt")
  else
    (cd "$W" && BOX54_UPSTREAM_TRUST=$mode CORP_TOKEN=real-secret-123 "$W/bin/box" run --config "$C/config/box.toml" >"$C/out.txt" 2>"$C/err.txt")
  fi
  local rc=$?
  end=$(python3 -c 'import time; print(time.time())')
  echo "### $name mode=$mode extra=[$extra] box_exit=$rc seconds=$(python3 -c "print(round($end-$start,2))")"
  sed 's/^/    out: /' "$C/out.txt"
  grep -E "trusts|verifies|PROBE|warning|error" "$C/err.txt" | sed 's/^/    err: /'
  sed 's/^/    upstream: /' "$W/upstream.log"
}

CORP=https://corp-intercept.test:8443/
GH=https://api.github.com/zen
echo "===== before the root is in the keychain"
case_run m0-baseline none "$CORP"
case_run ma-file none "$CORP" "upstream-ca-file = \"$W/area/corp/ca.pem\""
case_run mb0-host host "$CORP"
case_run mc0-platform platform "$CORP"
case_run gh-none none "$GH"
case_run gh-host host "$GH"
case_run gh-platform platform "$GH"

echo "===== trust the root in the System keychain (admin trust domain, as MDM installs a TLS-inspection root)"
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$W/pki/ca.pem"; echo "add-trusted-cert exit=$?"
curl -sS https://corp-intercept.test:8443/ && echo " <- host curl, no --cacert"
case_run m0-baseline-k none "$CORP"
case_run ma-file-k none "$CORP" "upstream-ca-file = \"$W/area/corp/ca.pem\""
case_run mb1-host-k host "$CORP"
case_run mc1-platform-k platform "$CORP"
echo "===== operator SSL_CERT_FILE set to Apple's shipped bundle"
export SSL_CERT_FILE=/private/etc/ssl/cert.pem
case_run mb2-host-k-sslcertfile host "$CORP"
case_run mc2-platform-k-sslcertfile platform "$CORP"
unset SSL_CERT_FILE

echo "===== the root marked as distrusted (deny) for SSL in the admin domain"
sudo security remove-trusted-cert -d "$W/pki/ca.pem"; echo "remove-trusted-cert exit=$?"
sudo security add-trusted-cert -d -r deny -k /Library/Keychains/System.keychain "$W/pki/ca.pem"; echo "add deny exit=$?"
curl -sS https://corp-intercept.test:8443/ >/dev/null 2>&1; echo "host curl after deny exit=$?"
case_run mb3-host-deny host "$CORP"
case_run mc3-platform-deny platform "$CORP"
exit 0
