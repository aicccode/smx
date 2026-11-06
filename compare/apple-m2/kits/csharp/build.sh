#!/bin/sh
# Builds both sides. Needs $DOTNET (a .NET 8 SDK). No network access is needed: nothing references a NuGet package.
set -e
cd "$(dirname "$0")"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_GENERATE_ASPNET_CERTIFICATE=0
DOTNET="${DOTNET:-dotnet}"
for side in base new; do
  "$DOTNET" build bench/$side/Bench.csproj -c Release -nologo -v q -clp:ErrorsOnly -p:TreatWarningsAsErrors=false -p:WarningLevel=0 >/dev/null 2>build-$side.log || { cat build-$side.log >&2; exit 1; }
  rm -f build-$side.log
done
