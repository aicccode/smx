#!/bin/sh
# Usage: run.sh <base|new>. Prints one result line per operation.
set -e
cd "$(dirname "$0")"
case "$1" in
  base|new) ;;
  *) echo "usage: run.sh <base|new>" >&2; exit 2 ;;
esac
PY="${PYTHON:-/usr/bin/python3}"
# -I ignores PYTHON* variables and user site-packages; caches stay at their defaults.
env -u SMX_DISABLE_KEY_CACHE "$PY" -I bench.py "$PWD/$1"
