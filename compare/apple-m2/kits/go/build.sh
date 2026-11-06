#!/bin/bash
# Builds bin/base and bin/new from the same benchmark source. Needs $GO.
set -euo pipefail
cd "$(dirname "$0")"
: "${GO:?set GO to the go binary}"
export GOTOOLCHAIN=local GOPROXY=off GOFLAGS= CGO_ENABLED=0 GOWORK=off
mkdir -p bin
cd bench
# go.mod points at new/go; go.base.mod points at base/go.
"$GO" build -trimpath -o ../bin/new .
"$GO" build -trimpath -modfile=go.base.mod -o ../bin/base .
