#!/bin/sh
# Nothing to compile: JavaScript runs from source. This checks that the runtime and
# both trees are present, so a missing piece fails here rather than mid-run.
set -e
cd "$(dirname "$0")"
: "${NODE:?set NODE to the Node.js 22 binary}"
"$NODE" -e "if (+process.versions.node.split('.')[0] < 18) process.exit(1)" ||
  { echo "Node.js 18 or later is required" >&2; exit 1; }
for side in base new; do
  [ -f "$side/javascript/sm2/sm2.js" ] || { echo "missing $side/javascript" >&2; exit 1; }
done
