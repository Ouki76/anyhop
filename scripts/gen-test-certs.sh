#!/bin/sh
# Generate the throwaway certificate the TLS tests use.
#
# The pair is deliberately NOT committed: a private key in a repository — even a
# self-signed test one — trips secret scanners and invites "why is there a key in
# this repo?" questions. Tests call this script (or the same openssl invocation)
# when the files are missing; openssl lives on every build machine.
#
#   scripts/gen-test-certs.sh [output-dir]     # default: test/certs
set -eu
OUT="${1:-test/certs}"
mkdir -p "$OUT"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$OUT/localhost.key" -out "$OUT/localhost.crt" -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
chmod 600 "$OUT/localhost.key"
echo "wrote $OUT/localhost.{crt,key}"
