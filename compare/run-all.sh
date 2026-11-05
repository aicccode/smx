#!/usr/bin/env bash
# Benchmarks every SMX implementation, OpenSSL and BouncyCastle on one CPU core, one after another.
#
# Usage: compare/run-all.sh [name...]   names: openssl bc c rust go csharp java js python swift
# Environment:
#   CORE      CPU core to pin to (default 6; pick a performance core on hybrid CPUs)
#   CORE2     second core for the JVM's compiler threads (default 7)
#   OUT       output directory (default compare/out)
#   BC_JAR    path to bcprov-jdk18on-*.jar (required for "bc")
#   JAVA      java executable (default java)
# Needs: taskset, a C compiler with OpenSSL 3 headers (libssl-dev), and each language's toolchain.
# Build Java first with `mvn -q test` in java/, so target/classes and target/test-classes exist.
# Run on an otherwise idle machine; other load changes the numbers a lot.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
core=${CORE:-6}
core2=${CORE2:-7}
out=${OUT:-$here/out}
java=${JAVA:-java}
mkdir -p "$out"
pin=(taskset -c "$core")
names=("$@")
[ ${#names[@]} -gt 0 ] || names=(openssl bc c rust go csharp java js python swift)
go_filter='BenchmarkSM3/|BenchmarkSM4KeySchedule|BenchmarkSM4Encrypt/|BenchmarkSM4Decrypt/|BenchmarkSM2KeyGen|BenchmarkSM2Sign|BenchmarkSM2Verify|BenchmarkSM2Encrypt/|BenchmarkSM2Decrypt/|BenchmarkSM2KeyExchange'
export PYTHONDONTWRITEBYTECODE=1

for name in "${names[@]}"; do
  echo "$(date +%T) $name"
  case $name in
    openssl)
      cc -O2 -o "$out/openssl_bench" "$here/openssl_bench.c" -lcrypto || exit 1
      for i in 1 2 3; do "${pin[@]}" "$out/openssl_bench" 400 5 >"$out/openssl-$i.txt" 2>&1; done ;;
    bc)
      : "${BC_JAR:?set BC_JAR to the bcprov-jdk18on jar}"
      mkdir -p "$out/bc-classes"
      javac -Xlint:-options -cp "$BC_JAR" -d "$out/bc-classes" "$here/BcBench.java" || exit 1
      for i in 1 2; do
        taskset -c "$core,$core2" "$java" -cp "$out/bc-classes:$BC_JAR" BcBench 5000 700 3 >"$out/bc-$i.txt" 2>&1
      done ;;
    c)
      (cd "$repo/c" && make -s clean && make -s bench) || exit 1
      for i in 1 2 3; do "${pin[@]}" "$repo/c/bench" >"$out/c-$i.txt" 2>&1; done
      (cd "$repo/c" && make -s clean) ;;
    rust)
      exe=$(cd "$repo/rust" && cargo bench --no-run 2>&1 | sed -nE 's/.*Executable .*\((target[^)]*sm_bench[^)]*)\).*/\1/p' | tail -1)
      [ -n "$exe" ] || { echo "rust bench build failed"; exit 1; }
      for i in 1 2 3; do (cd "$repo/rust" && "${pin[@]}" "./$exe") >"$out/rust-$i.txt" 2>&1; done ;;
    go)
      (cd "$repo/go" && go test -c -o "$out/go.test" .) || exit 1
      for i in 1 2 3; do
        (cd "$repo/go" && "${pin[@]}" "$out/go.test" -test.run xxx -test.bench "$go_filter" -test.benchtime=300ms -test.benchmem) >"$out/go-$i.txt" 2>&1
      done ;;
    csharp)
      (cd "$repo/csharp/SMX.Bench" && dotnet build -c Release >/dev/null) || exit 1
      for i in 1 2 3; do
        "${pin[@]}" dotnet "$repo/csharp/SMX.Bench/bin/Release/net8.0/SMX.Bench.dll" --rounds 8 --millis 80 >"$out/csharp-$i.txt" 2>&1
      done ;;
    java)
      for i in 1 2; do
        taskset -c "$core,$core2" "$java" -cp "$repo/java/target/classes:$repo/java/target/test-classes" \
          site.aicc.bench.SmxBench 5000 700 3 >"$out/java-$i.txt" 2>&1
      done ;;
    js)
      for i in 1 2 3; do (cd "$repo/javascript" && "${pin[@]}" node bench/bench.js) >"$out/js-$i.txt" 2>&1; done ;;
    python)
      for i in 1 2; do
        "${pin[@]}" python3 "$repo/python/benchmarks/bench.py" --root "$repo/python" --min-time 0.05 --repeat 5 >"$out/python-$i.txt" 2>&1
      done ;;
    swift)
      (cd "$repo/swift" && swiftc -O -wmo -module-name GMSwiftBench Sources/GMSwift/*.swift Benchmarks/main.swift -o "$out/swift.bin") || exit 1
      for i in 1 2 3; do "${pin[@]}" "$out/swift.bin" >"$out/swift-$i.txt" 2>&1; done ;;
    *) echo "unknown name: $name"; exit 2 ;;
  esac
done
echo "$(date +%T) done; summarize with: python3 $here/summarize.py $out"
