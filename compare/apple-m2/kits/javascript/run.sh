#!/bin/sh
# Usage: run.sh <base|new>. Prints one result line per operation.
set -e
cd "$(dirname "$0")"
: "${NODE:?set NODE to the Node.js 22 binary}"
case "$1" in base|new) ;; *) echo "usage: run.sh <base|new>" >&2; exit 2 ;; esac
exec "$NODE" bench.mjs "$1"
