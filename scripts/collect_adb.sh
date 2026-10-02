#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-adb-acquisition}"
PKG="${2:-}"
mkdir -p "$OUT"
if ! command -v adb >/dev/null; then echo "adb not found. Install Android SDK Platform-Tools." >&2; exit 1; fi
ARGS=(collect-adb -o "$OUT")
if [[ -n "$PKG" ]]; then ARGS+=(--package "$PKG"); fi
python -m mafkit.cli "${ARGS[@]}"
echo "ADB acquisition saved to: $OUT"
