#!/bin/sh
# Usage: run.sh <base|new>. Prints only result lines; the self-check summary goes to stderr.
set -e
here=$(cd "$(dirname "$0")" && pwd)
case "$1" in
    base | new) exec "$here/build/bench-$1" ;;
    *) echo "usage: run.sh <base|new>" >&2; exit 2 ;;
esac
