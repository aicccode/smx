#!/bin/sh
# Builds both sides with the same compiler and flags. Prints nothing but errors.
set -e
cd "$(dirname "$0")"
CC=${CC:-cc}
CFLAGS="-O3 -std=c99 -w"
mkdir -p bin
for side in base new; do
    $CC $CFLAGS -I"$side/c" -o "bin/macbench_$side" macbench.c \
        "$side/c/bigint256.c" "$side/c/sm3.c" "$side/c/sm4.c" "$side/c/sm2.c"
done
