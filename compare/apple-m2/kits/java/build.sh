#!/bin/bash
# Builds both sides with javac --release 8 from $JAVA_HOME. Idempotent; prints nothing but errors.
set -e
cd "$(dirname "$0")"
JAVAC="${JAVA_HOME:?JAVA_HOME must be set}/bin/javac"
compile() {
  # -nowarn and -Xlint:-options silence the "source value 8 is obsolete" notes of newer javac.
  "$JAVAC" --release 8 -nowarn -Xlint:-options -encoding UTF-8 "$@" 2>&1 | grep -v '^Note: ' || true
}
for side in base new; do
  mkdir -p "out/$side"
  find "out/$side" -name '*.class' -delete
  find "$side/java/src/site" -name '*.java' > "out/$side.sources"
  compile -d "out/$side" @"out/$side.sources"
  compile -cp "out/$side" -d "out/$side" bench/MacBench.java
  test -f "out/$side/MacBench.class" || { echo "build failed for $side" >&2; exit 1; }
done
