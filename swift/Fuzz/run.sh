#!/bin/sh
# Usage: Fuzz/run.sh [cases-per-function] [seed]
# Builds the library sources plus Fuzz/main.swift with release flags (overflow and bounds traps stay on) and runs it.
# Set GMSWIFT_FUZZ_FLAGS to add compiler flags, for example -sanitize=address.
set -e
here=$(cd "$(dirname "$0")" && pwd)
binary=$(mktemp -d)/gmswift-fuzz
# shellcheck disable=SC2086
swiftc -O -wmo -module-name GMSwiftFuzz $GMSWIFT_FUZZ_FLAGS "$here"/../Sources/GMSwift/*.swift "$here/main.swift" -o "$binary"
exec "$binary" "$@"
