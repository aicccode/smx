#!/bin/sh
# Runs one side once: ./run.sh base|new. Prints only result lines.
cd "$(dirname "$0")"
case "$1" in
base | new) exec "bin/macbench_$1" ;;
*)
    echo "usage: $0 base|new" >&2
    exit 2
    ;;
esac
