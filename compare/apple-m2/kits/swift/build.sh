#!/bin/sh
# Builds base and new with the same flags: swiftc -O -wmo. Prints nothing but errors.
set -e
here=$(cd "$(dirname "$0")" && pwd)
SWIFTC=${SWIFTC:-swiftc}
mkdir -p "$here/build"
for side in base new; do
    "$SWIFTC" -O -wmo -suppress-warnings -module-name SMXBench \
        "$here/$side"/*.swift "$here/bench/main.swift" -o "$here/build/bench-$side"
done
