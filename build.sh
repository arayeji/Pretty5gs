#!/usr/bin/env bash
# Open5GS build helper — Meson + Ninja
#
# Usage:
#   ./build.sh                        # configure (or reconfigure) + compile
#   ./build.sh -Dmysql_pcrf=true      # optional PyHSS MySQL on PCRF (YAML policy works without it)
#   MYSQL_PCRF=1 ./build.sh           # same as -Dmysql_pcrf=true
#   PREFIX=/usr INSTALL=1 ./build.sh  # build, install, ldconfig, restart daemons
#   BUILD_DIR=debug ./build.sh        # use ./debug instead of ./build
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

if [[ "${INSTALL:-0}" == 1 ]]; then
    PREFIX="${PREFIX:-/usr}"
    sudo ninja -C "$BUILD_DIR" install
    sudo ldconfig
    sudo systemctl daemon-reload
    sudo systemctl restart \
        open5gs-hssd open5gs-pcrfd open5gs-smfd open5gs-mmed \
        open5gs-sgwcd open5gs-sgwud open5gs-upfd open5gs-cgfd
fi
