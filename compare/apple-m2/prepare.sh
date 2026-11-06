#!/bin/sh
# Fills kits/<lang>/base and kits/<lang>/new from git: base is the code before the rework,
# new is the given revision. Run from anywhere inside the repository.
#   ./prepare.sh [BASE_REV] [NEW_REV]      defaults: 3397c6d and HEAD
set -eu
BASE=${1:-3397c6d}
NEW=${2:-HEAD}
here=$(cd "$(dirname "$0")" && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)
K=$here/kits

# extract REV DEST STRIP PATH...: git archive PATH... at REV into DEST, dropping STRIP leading components
extract() {
    rev=$1 dest=$2 strip=$3
    shift 3
    mkdir -p "$dest"
    git -C "$top" archive "$rev" "$@" | tar -x -C "$dest" --strip-components="$strip"
}

for side in base new; do
    if [ "$side" = base ]; then rev=$BASE; else rev=$NEW; fi
    for lang in c go csharp java javascript python rust swift; do
        if [ -e "$K/$lang/$side" ]; then
            echo "$K/$lang/$side already exists; remove it first" >&2
            exit 1
        fi
    done
    extract "$rev" "$K/c/$side" 0 c
    extract "$rev" "$K/go/$side" 0 go
    extract "$rev" "$K/csharp/$side" 1 csharp/SMX
    extract "$rev" "$K/java/$side" 0 java/src/site java/pom.xml
    extract "$rev" "$K/javascript/$side" 0 javascript
    extract "$rev" "$K/python/$side" 1 python
    extract "$rev" "$K/rust/$side" 1 rust
    extract "$rev" "$K/swift/$side" 3 swift/Sources/GMSwift
done
echo "kits filled: base=$BASE new=$(git -C "$top" rev-parse --short "$NEW")"
