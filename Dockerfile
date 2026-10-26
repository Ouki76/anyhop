# syntax=docker/dockerfile:1
#
# anyhop — single-binary gateway + embedded dashboard.
#   docker build -t anyhop .
#   docker run --rm -p 8080:8080 -v $PWD/anyhop.toml:/etc/anyhop/anyhop.toml:ro -v anyhop-data:/data anyhop
#
# The image is ~150 MB: a Debian slim runtime with the Rust binary, running as
# an unprivileged user (uid 10001).
#
# The mounted config must listen on 0.0.0.0 so the published port works:
#     [server]
#     listen = "0.0.0.0:8080"

# ---------- stage 1: dashboard bundle (Sycamore -> WASM) ----------
# Base images are pinned by manifest-list digest, not by tag: a tag can be moved
# to different content, a digest cannot. Multi-arch index (amd64 + arm64) so the
# digest is valid on either build platform.
FROM rust:1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS ui

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# Pinned: trunk's output layout (and therefore the CSP hashes computed at runtime)
# is tied to the version that built dist/.
#
# The release asset name carries the *host* architecture, so it must follow the
# build platform: an arm64 build that downloaded the x86_64 binary would fail (or,
# worse under emulation, silently run the wrong one).
#
# `TRUNK_SHA256` below pins the release asset: a plain `curl | tar` trusts whatever
# GitHub serves at that URL, so a replaced or tampered asset would produce a
# backdoored image with no signal. With the checksum it is a hard build failure.
ARG TRUNK_VERSION=v0.21.14
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) TRUNK_ARCH=x86_64-unknown-linux-gnu ;; \
      arm64) TRUNK_ARCH=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported build platform '$TARGETARCH' (amd64 and arm64 only)" >&2; exit 1 ;; \
    esac \
 && case "$TRUNK_ARCH" in \
      x86_64-unknown-linux-gnu) TRUNK_SHA256=f2b4680cd239693a646a2795e4633c625328d7b2a044fbe749fa3a2fe9e7036b ;; \
      aarch64-unknown-linux-gnu) TRUNK_SHA256=b1d8e60e454f7fc182d9a4d95d1506ffbae947d8ba90f8f6f02da93b60f980f9 ;; \
      *) echo "no pinned checksum for '$TRUNK_ARCH'" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/trunk.tar.gz \
      "https://github.com/trunk-rs/trunk/releases/download/${TRUNK_VERSION}/trunk-${TRUNK_ARCH}.tar.gz" \
 && echo "${TRUNK_SHA256}  /tmp/trunk.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/trunk.tar.gz -C /usr/local/bin trunk \
 && rm -f /tmp/trunk.tar.gz \
 && trunk --version

WORKDIR /src/ui
COPY ui/ ./
RUN trunk build --release

# ---------- stage 2: gateway ----------
FROM rust:1-slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS build

# tikv-jemalloc-sys compiles C, so a toolchain is required even for a "pure" Rust crate.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# Cargo.toml declares two bench targets, so `cargo build` refuses to parse the
# manifest when benches/ is missing — the image had not been rebuilt since the
# benches were added, and this COPY is what kept it broken.
COPY benches ./benches
# Dashboard assets must exist before `cargo build`: rust-embed needs the folder.
COPY --from=ui /src/ui/dist ./ui/dist

RUN cargo build --release --locked

# ---------- stage 3: runtime ----------
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin anyhop \
 && mkdir -p /data /etc/anyhop \
 && chown -R anyhop:anyhop /data

COPY --from=build /src/target/release/anyhop /usr/local/bin/anyhop

USER anyhop
WORKDIR /data

# Config is mounted read-only; redb state and logs live in /data (the volume).
ENV ANYHOP_CONFIG=/etc/anyhop/anyhop.toml \
    RUST_LOG=info \
    ANYHOP_HEALTH_URL=http://127.0.0.1:8080/healthz

EXPOSE 8080
VOLUME ["/data"]

# Kept overridable because the port lives in the config file, not in the image.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["sh", "-c", "curl -fsS \"$ANYHOP_HEALTH_URL\" || exit 1"]

ENTRYPOINT ["/usr/local/bin/anyhop"]