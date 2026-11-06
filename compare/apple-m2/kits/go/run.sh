#!/bin/bash
# Runs one side once: ./run.sh base|new
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
base | new) exec "./bin/$1" ;;
*)
	echo "usage: $0 base|new" >&2
	exit 2
	;;
esac
