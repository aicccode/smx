#!/bin/bash
# Builds test_ct_trace.c for each compiler and flag set and fails if any trace depends on the
# data. Control flow only: see test_ct_trace.c. Exits 0 with a note where it cannot run.
# SM4 on this branch uses secret-indexed tables, so its memory accesses depend on secrets by
# design; this check never looked at addresses and still requires its control flow, padding
# check included, to be the same for every input.
# CT_TRACE_JOBS sets the number of parallel runs; each takes about a minute.
set -u
cd "$(dirname "$0")/.." || exit 2
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) ;;
*)
    echo "check_ct_trace: needs Linux on x86-64; not run on $(uname -s)-$(uname -m)"
    exit 0
    ;;
esac

BASE="-std=gnu99 -w -g -no-pie -Wl,-z,now"
SOURCES="test_ct_trace.c bigint256.c sm3.c"
VARIANTS=("" "-DSMX_NO_INT128 -DSMX_NO_SIMD" "-DSMX_SM4_MAX_TIER=0" "-DSMX_SM4_MAX_TIER=2")
n=0
: >"$OUT/list"
for cc in gcc clang; do
    command -v "$cc" >/dev/null || continue
    for opt in -O1 -O2 -O3 -Os; do
        for variant in "${VARIANTS[@]}"; do
            # the SM4 tiers differ only in SM4 code, so one level each is enough for them
            case "$variant" in *MAX_TIER*) [ "$opt" = "-O3" ] || [ "$opt" = "-Os" ] || continue ;; esac
            n=$((n + 1))
            label="$cc $opt $variant"
            # shellcheck disable=SC2086
            if ! $cc $opt $variant $BASE -o "$OUT/t$n" $SOURCES; then
                echo "check_ct_trace: build failed: $label"
                exit 2
            fi
            printf '%s\t%s\n' "$OUT/t$n" "$label" >>"$OUT/list"
        done
    done
done

JOBS=${CT_TRACE_JOBS:-4}
# shellcheck disable=SC2016
xargs -a "$OUT/list" -d '\n' -P "$JOBS" -I{} bash -c '
    bin=${1%%$(printf "\t")*}; label=${1#*$(printf "\t")}
    "$bin" "$label" >"$bin.out" 2>&1; echo $? >"$bin.rc"
' _ {}

fail=0
while IFS=$'\t' read -r bin label; do
    rc=$(cat "$bin.rc" 2>/dev/null || echo 2)
    if [ "$rc" = "77" ]; then
        echo "check_ct_trace: ptrace is not permitted; not run"
        exit 0
    fi
    tail -1 "$bin.out"
    if [ "$rc" != "0" ]; then
        grep -E "DIFFERS|did not" "$bin.out" | grep -v "^$label" || true
        fail=1
    fi
done <"$OUT/list"
if [ "$fail" != 0 ]; then
    echo "check_ct_trace: a trace depends on the data"
    exit 1
fi
echo "check_ct_trace: every trace identical in $n builds"
