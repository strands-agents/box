#!/usr/bin/env bash
# Build the pinned Box source and run the example as an ordinary Linux user.
set -euo pipefail
exec > >(tee -a /var/log/box-gcp-setup.log /dev/console) 2>&1
trap 'code=$?; printf "BOX_GCP_SETUP_EXIT=%s\n" "$code"' EXIT

metadata() {
    curl --fail --silent --show-error --retry 5 --max-time 30 \
        -H 'Metadata-Flavor: Google' \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

printf 'BOX_GCP_PHASE=installing\n'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends git build-essential pkg-config libssl-dev \
    python3-venv curl ca-certificates cmake perl util-linux
id boxdemo >/dev/null 2>&1 || useradd --create-home --shell /bin/bash boxdemo
install -d -m 0755 /var/lib/box-gcp
metadata box-config > /var/lib/box-gcp/config.json
metadata box-payload > /var/lib/box-gcp/payload.b64

runuser --user boxdemo -- env HOME=/home/boxdemo \
    PATH=/home/boxdemo/.cargo/bin:/usr/local/bin:/usr/bin:/bin bash <<'BUILD'
set -euo pipefail
python3 - <<'PREFLIGHT'
import json
import re
from pathlib import Path
config = json.loads(Path('/var/lib/box-gcp/config.json').read_text())
if not re.fullmatch('[0-9a-f]{40}', config['source_revision']):
    raise SystemExit('Invalid pinned Box revision')
PREFLIGHT
test "$(uname -m)" = aarch64
unshare --user --map-root-user --mount --pid --fork --net --ipc --uts true
printf 'BOX_GCP_PHASE=building\n'
revision=$(python3 -c 'import json; print(json.load(open("/var/lib/box-gcp/config.json"))["source_revision"])')
if [ ! -d /home/boxdemo/box-src/.git ]; then
    git init /home/boxdemo/box-src
    git -C /home/boxdemo/box-src remote add origin https://github.com/strands-agents/box.git
    git -C /home/boxdemo/box-src fetch --depth 1 origin "$revision"
    git -C /home/boxdemo/box-src checkout --detach FETCH_HEAD
fi
test "$(git -C /home/boxdemo/box-src rev-parse HEAD)" = "$revision"
cd /home/boxdemo/box-src
if [ ! -x /home/boxdemo/.cargo/bin/rustup ]; then
    curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o /home/boxdemo/rustup-init.sh
    sh /home/boxdemo/rustup-init.sh -y --profile minimal --default-toolchain none
fi
cargo build --locked --release --all-features -p strands-box -p strands-box-containment
ln -sf strands-box target/release/box

python3 - <<'UNPACK'
import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path
config = json.loads(Path('/var/lib/box-gcp/config.json').read_text())
data = base64.b64decode(Path('/var/lib/box-gcp/payload.b64').read_bytes(), validate=True)
if hashlib.sha256(data).hexdigest() != config['payload_sha256']:
    raise SystemExit('Example payload checksum mismatch')
destination = Path('/home/boxdemo/box-src/examples/cloud-deployments/gcp')
destination.mkdir(parents=True, exist_ok=True)
allowed = {'run-demo.py', 'agent.py', 'requirements.txt', 'dependency-lock.txt'}
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    for member in archive.getmembers():
        if member.name not in allowed or not member.isfile() or member.size > 1_000_000:
            raise SystemExit('Unexpected file in example payload')
        target = destination / member.name
        if target.is_symlink():
            raise SystemExit('Refusing a symlink in the example directory')
        target.write_bytes(archive.extractfile(member).read())
UNPACK
python3 -m venv /home/boxdemo/venv
/home/boxdemo/venv/bin/python -m pip install --disable-pip-version-check \
    --target examples/cloud-deployments/gcp/vendor \
    --requirement examples/cloud-deployments/gcp/dependency-lock.txt
printf 'BOX_GCP_PHASE=running\n'
export BOX_BIN=/home/boxdemo/box-src/target/release/box
export EXPERIMENTAL_LINUX_SUPPORT=TRUE
ulimit -n 65536
/usr/bin/python3 -I -B - <<'RUN'
import base64
import gzip
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
config = json.loads(Path('/var/lib/box-gcp/config.json').read_text())
runner = '/home/boxdemo/box-src/examples/cloud-deployments/gcp/run-demo.py'
command = [sys.executable, '-I', '-B', runner, '--project', config['project'], '--location', config['location']]
if config.get('model'):
    command.extend(['--model', config['model']])
receipt = {key: config[key] for key in ('owner', 'source_revision', 'payload_sha256')}
attempt = Path(tempfile.mkdtemp(prefix='box-gcp-attempt-', dir='/home/boxdemo'))
receipt['attempt'] = attempt.name
for mode, extra in [('probe', ['--probe-only']), ('demo', [])]:
    if mode == 'demo' and config['probe_only']:
        break
    output = attempt / (mode + '-results.json')
    result = subprocess.run(command + extra + ['--output', str(output)])
    receipt[mode] = json.loads(output.read_text()) if output.exists() else {'exit_code': result.returncode}
    receipt[mode + '_exit_code'] = result.returncode
    if result.returncode:
        break
Path('/home/boxdemo/results.json').write_text(json.dumps(receipt, indent=2) + '\n')
encoded = base64.b64encode(gzip.compress(json.dumps(receipt).encode())).decode()
digest = hashlib.sha256(encoded.encode()).hexdigest()
chunks = [encoded[start:start + 1000] for start in range(0, len(encoded), 1000)]
for index, chunk in enumerate(chunks):
    print(f'BOX_GCP_RECEIPT_CHUNK={digest}:{index}:{len(chunks)}:{chunk}', flush=True)
raise SystemExit(result.returncode)
RUN
BUILD
printf 'BOX_GCP_PHASE=complete\n'
