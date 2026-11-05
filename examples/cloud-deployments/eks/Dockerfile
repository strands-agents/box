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

FROM public.ecr.aws/docker/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS strands-box-build
ARG TARGETARCH
ARG STRANDS_BOX_REV=e24d903412cf3f34766f0b77c941ddd1a048991d
ARG STRANDS_BOX_SOURCE_SHA256=0575b4d8702a2e0a407a5ef658a2b7fd05fa8e7dd96d397aeef07bc45c60fc09
RUN test "$TARGETARCH" = arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && apt-get clean
WORKDIR /build
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      "https://codeload.github.com/strands-agents/box/tar.gz/${STRANDS_BOX_REV}" -o source.tar.gz \
    && echo "${STRANDS_BOX_SOURCE_SHA256}  source.tar.gz" | sha256sum --check - \
    && tar --extract --gzip --file source.tar.gz --strip-components=1
RUN cargo build --locked --release --all-features \
      -p strands-box -p strands-box-containment --jobs 4

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f AS strands
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean
COPY --from=strands-box-build /build/target/release/strands-box /usr/local/bin/
COPY --from=strands-box-build /build/target/release/strands-box-sock-alias /usr/local/bin/
COPY --from=strands-box-build /build/target/release/strands-box-contain-trampoline /usr/local/bin/
COPY strands/requirements.txt /opt/strands/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /opt/strands/requirements.txt
COPY strands/*.py /opt/strands/
COPY strands/fixtures/ /opt/strands/fixtures/
ARG STRANDS_BOX_REV=e24d903412cf3f34766f0b77c941ddd1a048991d
RUN python3 -c 'import hashlib,json,os; from pathlib import Path; names=["strands-box","strands-box-sock-alias","strands-box-contain-trampoline"]; Path("/opt/strands/box-build.json").write_text(json.dumps({"revision":os.environ["STRANDS_BOX_REV"],"binaries":{n:hashlib.sha256((Path("/usr/local/bin")/n).read_bytes()).hexdigest() for n in names}}))' \
    && useradd --create-home --uid 1000 agent \
    && mkdir -p /evidence \
    && chown 1000:1000 /evidence
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    HOME=/home/agent EXPERIMENTAL_LINUX_SUPPORT=TRUE
USER 1000:1000
WORKDIR /evidence
ENTRYPOINT ["python3", "/opt/strands/entrypoint.py"]

FROM runtime AS scripted
COPY app/practice.py /app/practice.py
USER 991:991
CMD ["/usr/bin/python3.12", "/app/practice.py"]
