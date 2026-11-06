#!/bin/bash
# Runs on the Mac. Builds every language kit; prints one status line per kit.
set -u
here=$(cd "$(dirname "$0")" && pwd)
K=${KITS:-$here/kits}
T=${TOOLS:-$HOME/smx-bench/tools}
export CC=cc
export CARGO=$HOME/.cargo/bin/cargo
export GO=$T/go/bin/go
export NODE=$T/node/bin/node
export DOTNET=$T/dotnet/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export JAVA_HOME=${JAVA_HOME:-$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.11/Contents/Home}
export PYTHON=/usr/bin/python3
export SWIFTC=/usr/bin/swiftc
export PATH=$T/go/bin:$T/node/bin:$T/dotnet:$JAVA_HOME/bin:$PATH
for lang in "$@"; do
  start=$(date +%s)
  if (cd "$K/$lang" && ./build.sh) >"$K/$lang.build.log" 2>&1; then
    echo "$lang build ok ($(( $(date +%s) - start ))s)"
  else
    echo "$lang BUILD FAILED, last lines:"; tail -8 "$K/$lang.build.log"
  fi
done
