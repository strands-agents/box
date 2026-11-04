FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS box-build
RUN dnf install -y gcc gcc-c++ make cmake openssl-devel pkgconf-pkg-config git curl-minimal tar gzip perl python3 && dnf clean all
ARG BOX_REV=f0dc6f49ea8bb8608502afffa50c8748f6c24ca2
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.98.1
ENV PATH="/root/.cargo/bin:${PATH}"
RUN git init /src && git -C /src remote add origin https://github.com/strands-agents/box.git && git -C /src fetch --depth 1 origin ${BOX_REV} && git -C /src checkout --detach FETCH_HEAD && test "$(git -C /src rev-parse HEAD)" = "${BOX_REV}"
WORKDIR /src
RUN cargo build --locked --release --all-features -p strands-box -p strands-box-containment
RUN mkdir -p /out && cp target/release/strands-box /out/box && cp target/release/strands-box-sock-alias target/release/strands-box-contain-trampoline /out/ && python3 -c 'import hashlib; from pathlib import Path; Path("/out/box.sha256").write_text(hashlib.sha256(Path("/out/box").read_bytes()).hexdigest())'

FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS runtime
RUN dnf install -y python3.12 bash libstdc++ ca-certificates shadow-utils && dnf clean all && groupadd -g 991 agent && useradd -u 991 -g 991 -m agent
COPY --from=box-build /out/ /opt/box/
ENV HOME=/home/agent LANG=C.UTF-8
WORKDIR /app

FROM runtime AS claude
RUN dnf install -y python3.12-pip && dnf clean all
COPY claude/requirements.txt /tmp/requirements.txt
RUN python3.12 -m pip install --no-cache-dir -r /tmp/requirements.txt
COPY claude/ /demo/
RUN python3.12 -c 'import json,urllib.request,hashlib,base64; from pathlib import Path; d=json.loads(Path("/demo/claude-package.json").read_text()); b=urllib.request.urlopen(d["url"]).read(); assert "sha512-"+base64.b64encode(hashlib.sha512(b).digest()).decode()==d["integrity"]; Path("/app/claude.tar.gz").write_bytes(b)'
USER 991:991
CMD ["/usr/bin/python3.12", "/demo/main.py"]

FROM runtime AS scripted
COPY app/practice.py /app/practice.py
USER 991:991
CMD ["/usr/bin/python3.12", "/app/practice.py"]
