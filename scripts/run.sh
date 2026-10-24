#!/bin/sh
# Start the gateway with the OAuth client loaded from outside the repository.
#
# The antigravity (Google) flow needs ANYHOP_ANTIGRAVITY_CLIENT_ID and
# ANYHOP_ANTIGRAVITY_CLIENT_SECRET; they live in ~/.config/anyhop/env (0600) so
# they never end up in git.
set -eu
ENV_FILE="${ANYHOP_ENV_FILE:-$HOME/.config/anyhop/env}"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
export ANYHOP_CONFIG="${ANYHOP_CONFIG:-anyhop.toml}"
exec ./target/release/anyhop "$@"
