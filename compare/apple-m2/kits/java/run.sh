#!/bin/bash
# Runs one side once: ./run.sh base|new. Prints only result lines.
set -e
cd "$(dirname "$0")"
case "$1" in base|new) ;; *) echo "usage: $0 base|new" >&2; exit 2 ;; esac
exec "${JAVA_HOME:?JAVA_HOME must be set}/bin/java" -cp "out/$1" MacBench
