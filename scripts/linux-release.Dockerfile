FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:c07ab0773eddf9449c0994a87d8148300db98bdf8d8dad672a9dc26321c104fc

ARG RUST_VERSION
RUN dnf install -y gcc gcc-c++ make perl-core pkgconf-pkg-config \
    openssl-devel git tar gzip xz binutils findutils python3 shadow-utils \
    && dnf clean all
RUN test -n "$RUST_VERSION" \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal --default-toolchain "$RUST_VERSION"
RUN useradd --uid 1000 --create-home box-test

ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /src
