#!/usr/bin/env bash
# Set up Haruspex for Optio — standalone, no Praetor required.
#
# Haruspex is an optional, local, calibrated decision model. When it runs, Optio's
# `h` key re-ranks the next actions by predicted value (and it abstains when
# unsure). Optio works fully without it; this script just stands it up.
#
# What it does:
#   1. Clone (or update) TyrusRC/haruspex into a local directory.
#   2. Install it with uv.
#   3. Start the server on 127.0.0.1:3000.
#   4. Tell you the one env var to export so Optio finds it.
#
# Usage:
#   scripts/setup-haruspex.sh            # clone + install + run on :3000
#   scripts/setup-haruspex.sh --install  # clone + install only, do not run
#   HARUSPEX_DIR=/opt/haruspex PORT=3100 scripts/setup-haruspex.sh
set -euo pipefail

REPO="${HARUSPEX_REPO:-https://github.com/TyrusRC/haruspex.git}"
DIR="${HARUSPEX_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/optio/haruspex}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-3000}"
INSTALL_ONLY=0
[ "${1:-}" = "--install" ] && INSTALL_ONLY=1

command -v uv >/dev/null 2>&1 || {
  echo "error: uv is not installed. See https://docs.astral.sh/uv/ ." >&2
  exit 1
}
command -v git >/dev/null 2>&1 || { echo "error: git is not installed." >&2; exit 1; }

# 1. clone or update
if [ -d "$DIR/.git" ]; then
  echo "[*] updating $DIR"
  git -C "$DIR" pull --ff-only
else
  echo "[*] cloning $REPO -> $DIR"
  mkdir -p "$(dirname "$DIR")"
  git clone --depth 1 "$REPO" "$DIR"
fi

# 2. install
echo "[*] installing with uv"
( cd "$DIR" && uv sync )

export_line="export OPTIO_HARUSPEX_URL=http://$HOST:$PORT"
if [ "$INSTALL_ONLY" -eq 1 ]; then
  echo "[+] installed. To run it later:"
  echo "      ( cd '$DIR' && uv run haruspex serve --host $HOST --port $PORT )"
  echo "[+] then point Optio at it:"
  echo "      $export_line"
  exit 0
fi

# 3. run — try the documented entry point, fall back to the module form.
echo "[*] starting Haruspex on http://$HOST:$PORT (ctrl-c to stop)"
echo "[+] in another shell, point Optio at it with:"
echo "      $export_line"
cd "$DIR"
if uv run haruspex --help >/dev/null 2>&1; then
  exec uv run haruspex serve --host "$HOST" --port "$PORT"
else
  echo "[!] 'haruspex' CLI not found; falling back to the module entry point." >&2
  echo "[!] if this fails, check the Haruspex README in $DIR for its run command." >&2
  exec uv run python -m haruspex --host "$HOST" --port "$PORT"
fi
