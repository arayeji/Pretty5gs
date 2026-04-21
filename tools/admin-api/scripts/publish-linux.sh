#!/usr/bin/env bash
# ===========================================================================
# publish-linux.sh — build a self-contained linux-x64 Admin API binary
# ===========================================================================
#
# Produces a single-file, self-contained .NET 9 executable that has NO
# runtime dependency on the target host (no `apt install dotnet` needed
# over there). Output lands in:
#
#   tools/admin-api/dist/admin-api/
#       open5gs-admin-api         # the executable
#       appsettings.json          # baseline config, overridable by env
#       *.pdb                     # symbols (safe to strip before shipping)
#
# Run from any OS that has the .NET 9 SDK installed. On Windows/WSL this
# happily cross-compiles for linux-x64 without mono or wine.
#
# Usage:
#   tools/admin-api/scripts/publish-linux.sh            # linux-x64, Release
#   RID=linux-arm64 tools/admin-api/scripts/publish-linux.sh
#   CONFIG=Debug    tools/admin-api/scripts/publish-linux.sh
# ===========================================================================
set -euo pipefail

# Resolve paths relative to this script so it works no matter the CWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ADMIN_API_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
CSPROJ="${ADMIN_API_DIR}/src/Open5gs.AdminApi/Open5gs.AdminApi.csproj"
OUT_DIR="${ADMIN_API_DIR}/dist/admin-api"

RID="${RID:-linux-x64}"
CONFIG="${CONFIG:-Release}"

command -v dotnet >/dev/null 2>&1 || {
    echo "error: dotnet SDK not found in PATH; install .NET 9 SDK first." >&2
    exit 1
}

echo "publishing Open5GS Admin API"
echo "  csproj : ${CSPROJ}"
echo "  rid    : ${RID}"
echo "  config : ${CONFIG}"
echo "  out    : ${OUT_DIR}"
echo

# Clean the output so an older .NET version's hostfxr doesn't linger.
rm -rf -- "${OUT_DIR}"

dotnet publish "${CSPROJ}"                         \
    --configuration "${CONFIG}"                    \
    --runtime "${RID}"                             \
    --self-contained true                          \
    -p:PublishSingleFile=true                      \
    -p:IncludeNativeLibrariesForSelfExtract=true   \
    -p:DebugType=embedded                          \
    --output "${OUT_DIR}"

# Sanity check: we should have exactly one ELF executable named
# open5gs-admin-api on linux-* RIDs. Fail loudly if publish produced a
# shared-framework layout by mistake.
if [[ "${RID}" == linux-* ]]; then
    if [[ ! -x "${OUT_DIR}/open5gs-admin-api" ]]; then
        echo "error: expected ${OUT_DIR}/open5gs-admin-api to exist after publish" >&2
        exit 2
    fi
fi

echo
echo "done. ship the contents of:"
echo "  ${OUT_DIR}"
echo "to the target host (e.g. scp -r or rsync)."
