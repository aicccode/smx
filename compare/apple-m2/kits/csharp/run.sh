#!/bin/sh
# Runs one side once: ./run.sh base|new. Prints only result lines.
set -e
cd "$(dirname "$0")"
case "$1" in base|new) ;; *) echo "usage: run.sh base|new" >&2; exit 2;; esac
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
DOTNET="${DOTNET:-dotnet}"
exec "$DOTNET" bench/$1/bin/Release/net8.0/SmxBench.dll
