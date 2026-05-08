#!/usr/bin/env bash
# Open5GS build helper — Meson + Ninja
#
# Usage:
#   ./build.sh                        # configure (or reconfigure) + compile
#   ./build.sh -Dmysql_pcrf=true      # enable PCRF ↔ PyHSS MySQL (needs libmysqlclient)
#   MYSQL_PCRF=1 ./build.sh           # same as -Dmysql_pcrf=true
#   BUILD_DIR=debug ./build.sh        # use ./debug instead of ./build
#
# Debian/Ubuntu MySQL client dev package (one of):
#   sudo apt install default-libmysqlclient-dev
#   sudo apt install libmariadb-dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="${BUILD_DIR:-build}"

EXTRA=()
if [[ "${MYSQL_PCRF:-0}" == 1 ]]; then
    EXTRA+=(-Dmysql_pcrf=true)
fi

if [[ -d "$BUILD_DIR/meson-private" ]]; then
    meson setup "$BUILD_DIR" --reconfigure "${EXTRA[@]}" "$@"
else
    meson setup "$BUILD_DIR" "${EXTRA[@]}" "$@"
fi

ninja -C "$BUILD_DIR"
