#!/bin/sh
# Usage: Benchmarks/run.sh [sources-dir] [output-binary]
# Builds the library sources plus Benchmarks/main.swift with release flags (-O -wmo) and runs the result.
# Set GMSWIFT_BENCH_PIN to a CPU number to pin the run with taskset.
set -e
here=$(cd "$(dirname "$0")" && pwd)
sources=${1:-$here/../Sources/GMSwift}
binary=${2:-$(mktemp -d)/gmswift-bench}
swiftc -O -wmo -module-name GMSwiftBench "$sources"/*.swift "$here/main.swift" -o "$binary"
if [ -n "$GMSWIFT_BENCH_PIN" ]; then
    exec taskset -c "$GMSWIFT_BENCH_PIN" "$binary"
fi
exec "$binary"
