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
FROM rust:1-slim-bookworm AS ui

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# Pinned: trunk's output layout (and therefore the CSP hashes computed at runtime)
# is tied to the version that built dist/.
ARG TRUNK_VERSION=v0.21.14
RUN curl -fsSL \
      "https://github.com/trunk-rs/trunk/releases/download/${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
    | tar -xz -C /usr/local/bin trunk

WORKDIR /src/ui
COPY ui/ ./
RUN trunk build --release

# ---------- stage 2: gateway ----------
FROM rust:1-slim-bookworm AS build

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
FROM debian:bookworm-slim

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