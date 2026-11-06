#!/bin/sh
# Byte-compiles both sides ahead of time, so no run pays for compilation.
set -e
cd "$(dirname "$0")"
PY="${PYTHON:-/usr/bin/python3}"
"$PY" -m compileall -q base/smx new/smx bench.py >/dev/null
