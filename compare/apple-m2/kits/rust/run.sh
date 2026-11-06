#!/bin/bash
# Runs one side once; prints only result lines: name, median us, min us.
set -e
case "$1" in
  base|new) exec "$(dirname "$0")/target/$1/release/smx-bench-$1" ;;
  *) echo "usage: $0 <base|new>" >&2; exit 2 ;;
esac
