#!/usr/bin/env bash
# Regenerate docs/screenshots/*.png from real terminal sessions.
#
#   1. builds the binaries in the Docker toolchain stage,
#   2. runs capture.py in a container (pty + pyte terminal emulator),
#   3. renders each HTML page to PNG with headless Chrome.
#
# Requirements: Docker and Chrome/Chromium (set CHROME to its path).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/scripts/screenshots/out"
CHROME="${CHROME:-google-chrome}"
PYTHON_IMAGE="python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72"
mkdir -p "$OUT" "$ROOT/docs/screenshots"

# Git Bash on Windows needs Windows-style paths for bind mounts and Chrome.
host_path() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }
file_url() { if command -v cygpath >/dev/null; then echo "file:///$(cygpath -m "$1")"; else echo "file://$1"; fi; }

docker build -q --target toolchain -t securechat-toolchain:dev "$ROOT" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -v "$(host_path "$ROOT"):/src" -w /src \
  securechat-toolchain:dev make -s BUILD=build/screens all

MSYS_NO_PATHCONV=1 docker run --rm -v "$(host_path "$ROOT"):/src" -w /src \
  "$PYTHON_IMAGE" sh -c '
    apt-get update -qq >/dev/null &&
    apt-get install -y -qq --no-install-recommends libsodium23 >/dev/null &&
    pip install -q --root-user-action=ignore --disable-pip-version-check \
      -r scripts/screenshots/requirements.txt &&
    python scripts/screenshots/capture.py build/screens scripts/screenshots/out'

for page in "$OUT"/*.html; do
  name="$(basename "$page" .html)"
  # Fit the viewport to the terminal: 24 rows -> 680 px, 22 px less per row.
  rows="$(awk '/<pre>/ {p = 1} p {c++} /<\/pre>/ {p = 0} END {print c}' "$page")"
  height=$((680 - (24 - rows) * 22))
  "$CHROME" --headless=new --hide-scrollbars --window-size=1000,"$height" \
    --screenshot="$(host_path "$ROOT/docs/screenshots/$name.png")" \
    "$(file_url "$page")" >/dev/null 2>&1
  echo "docs/screenshots/$name.png"
done
