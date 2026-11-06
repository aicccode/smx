#!/bin/bash
# Builds both sides with the same release profile. Idempotent; prints only errors.
set -e
cd "$(dirname "$0")"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
for side in base new; do
  "$CARGO" build --release --quiet --offline \
    --manifest-path "bench_$side/Cargo.toml" --target-dir "target/$side"
done
