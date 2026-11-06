#!/bin/bash
# Runs on the Mac under caffeinate. Measures everything sequentially; nothing else should run meanwhile.
set -u
here=$(cd "$(dirname "$0")" && pwd)
K=${KITS:-$here/kits}
T=${TOOLS:-$HOME/smx-bench/tools}
R=${RESULTS:-$here/results}
ROUNDS=${ROUNDS:-3}
COOLDOWN=${COOLDOWN:-10}
export CC=cc CARGO=$HOME/.cargo/bin/cargo GO=$T/go/bin/go NODE=$T/node/bin/node DOTNET=$T/dotnet/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export JAVA_HOME=${JAVA_HOME:-$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.11/Contents/Home}
export PYTHON=/usr/bin/python3 SWIFTC=/usr/bin/swiftc
export PATH=$T/go/bin:$T/node/bin:$T/dotnet:$JAVA_HOME/bin:$PATH
mkdir -p "$R"
log() { echo "$(date '+%F %T') $*" >>"$R/progress.log"; }
state() { echo "$(date '+%T') load=$(sysctl -n vm.loadavg) therm=$(pmset -g therm 2>/dev/null | grep -i CPU_Speed_Limit | tr -d ' \t')" >>"$R/state.log"; }
one() { # label command...
  local label=$1; shift
  sleep "$COOLDOWN"; state
  local start=$(date +%s)
  if "$@" >"$R/$label.txt" 2>"$R/$label.err"; then log "$label ok $(( $(date +%s) - start ))s"
  else log "$label FAILED exit=$? $(( $(date +%s) - start ))s"; fi
}
log "start rounds=$ROUNDS"
sw_vers -productVersion >"$R/system.txt"; sysctl -n machdep.cpu.brand_string >>"$R/system.txt"

for v in ${OPENSSL_VERSIONS-3.0.13 3.6.5}; do
  [ -x "$K/openssl/ob-$v" ] || { log "openssl-$v skipped: not built"; continue; }
  for i in $(seq 1 "$ROUNDS"); do one "openssl-$v-$i" "$K/openssl/ob-$v"; done
done
if [ "${SKIP_BC:-0}" != 1 ]; then
  for i in $(seq 1 "$ROUNDS"); do
    one "bc-$i" "$JAVA_HOME/bin/java" -cp "$K/bc/cls:$K/bc/bcprov-jdk18on-1.86.jar" BcMacBench
  done
fi
for lang in ${LANGS:-c rust go csharp java javascript python swift}; do
  for i in $(seq 1 "$ROUNDS"); do
    for side in ${SIDES:-base new}; do
      # LABEL_new renames the "new" side in the result files, e.g. LABEL_new=perf for the main branch
      label=$side; [ "$side" = new ] && label=${LABEL_new:-new}
      one "$lang-$label-$i" bash -c "cd '$K/$lang' && ./run.sh $side"
    done
  done
done
log "finished"
touch "$R/DONE"
