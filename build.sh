#!/usr/bin/env bash
# Pretty5GS / Open5GS build helper — Meson + Ninja
#
# Usage:
#   ./build.sh                              # release build (default), configure + compile
#   BUILDTYPE=debug ./build.sh              # debug symbols for gdb
#   MYSQL_PCRF=1 ./build.sh                 # link PCRF with libmysqlclient (PyHSS MySQL)
#   PREFIX=/usr INSTALL=1 ./build.sh        # build, install, ldconfig, restart EPC daemons
#   CLEAN=1 BUILDTYPE=release ./build.sh    # wipe build/ then fresh release configure
#   BUILD_DIR=debug ./build.sh              # use ./debug instead of ./build
#
# Environment:
#   BUILDTYPE   release (default) | debug | debugoptimized | plain
#   PREFIX      /usr (default) — passed to meson setup
#   BUILD_DIR   build (default)
#   MYSQL_PCRF  1 → add -Dmysql_pcrf=true
#   INSTALL     1 → ninja install + ldconfig + restart daemons (needs sudo)
#   CLEAN       1 → remove BUILD_DIR before configure (use when switching BUILDTYPE)
#
# YAML-only PCRF (pcrf.policy in pcrf.yaml): do NOT pass -Dmysql_pcrf=true.
# If pcrf.yaml has pcrf.mysql, set enabled: false unless PyHSS MySQL is up.
#
# Debian/Ubuntu MySQL client dev package (one of):
#   sudo apt install default-libmysqlclient-dev
#   sudo apt install libmariadb-dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="${BUILD_DIR:-build}"
PREFIX="${PREFIX:-/usr}"
BUILDTYPE="${BUILDTYPE:-release}"

EXTRA=(--prefix="$PREFIX" --buildtype="$BUILDTYPE")
if [[ "${MYSQL_PCRF:-0}" == 1 ]]; then
    EXTRA+=(-Dmysql_pcrf=true)
fi

if [[ "${CLEAN:-0}" == 1 ]]; then
    rm -rf "$BUILD_DIR"
fi

echo "==> meson: prefix=$PREFIX buildtype=$BUILDTYPE dir=$BUILD_DIR"

if [[ -d "$BUILD_DIR/meson-private" ]]; then
    meson setup "$BUILD_DIR" --reconfigure "${EXTRA[@]}" "$@"
else
    meson setup "$BUILD_DIR" "${EXTRA[@]}" "$@"
fi

ninja -C "$BUILD_DIR"

if [[ "${INSTALL:-0}" == 1 ]]; then
    sudo ninja -C "$BUILD_DIR" install
    sudo ldconfig
    sudo systemctl daemon-reload
    sudo systemctl restart \
        open5gs-hssd open5gs-pcrfd open5gs-smfd open5gs-mmed \
        open5gs-sgwcd open5gs-sgwud open5gs-upfd open5gs-cgfd
    echo "==> installed and restarted EPC daemons"
fi
