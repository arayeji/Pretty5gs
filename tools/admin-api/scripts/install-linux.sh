#!/usr/bin/env bash
# ===========================================================================
# install-linux.sh — drop a published Admin API into the service path
# ===========================================================================
#
# Run this AS ROOT on the target Linux host after copying the output of
# publish-linux.sh (the `dist/admin-api/` directory). It:
#
#   1. Creates the open5gs user/group if the NF packages haven't already.
#   2. Installs the self-contained binary + appsettings.json into
#      /opt/open5gs/admin-api/ with sane ownership/perms.
#   3. Seeds /etc/open5gs/admin-api.env from the installed example
#      (only on first install — never clobbers an existing token).
#   4. Installs the systemd unit if `meson install` hasn't already.
#   5. Reloads systemd, enables, and starts the service.
#
# Usage:
#   sudo PUBLISH_DIR=/path/to/dist/admin-api \
#        tools/admin-api/scripts/install-linux.sh
#
# Optional overrides (env vars):
#   SERVICE_DIR   default /opt/open5gs/admin-api
#   ENV_FILE      default /etc/open5gs/admin-api.env
#   UNIT_FILE     default /lib/systemd/system/open5gs-admin-api.service
#   SERVICE_USER  default open5gs
#   NO_RESTART=1  install files but don't touch systemctl (handy for
#                 first-time deploys where you still need to edit the
#                 env file before letting the service come up).
# ===========================================================================
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ADMIN_API_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

PUBLISH_DIR="${PUBLISH_DIR:-${REPO_ADMIN_API_DIR}/dist/admin-api}"
SERVICE_DIR="${SERVICE_DIR:-/opt/open5gs/admin-api}"
ENV_FILE="${ENV_FILE:-/etc/open5gs/admin-api.env}"
UNIT_FILE="${UNIT_FILE:-/lib/systemd/system/open5gs-admin-api.service}"
SERVICE_USER="${SERVICE_USER:-open5gs}"

# The env-file template is shipped by `meson install` to /usr/share. If
# the operator built .debs only and skipped meson install, fall back to
# the copy in the source tree.
ENV_EXAMPLE_PRIMARY="/usr/share/open5gs/admin-api/open5gs-admin-api.env.example"
ENV_EXAMPLE_FALLBACK="$(cd -- "${REPO_ADMIN_API_DIR}/../../configs/systemd" >/dev/null 2>&1 && pwd)/open5gs-admin-api.env.example"
UNIT_SRC_FALLBACK="$(cd -- "${REPO_ADMIN_API_DIR}/../../configs/systemd" >/dev/null 2>&1 && pwd)/open5gs-admin-api.service.in"

if [[ ! -x "${PUBLISH_DIR}/open5gs-admin-api" ]]; then
    echo "error: no published binary at ${PUBLISH_DIR}/open5gs-admin-api" >&2
    echo "run publish-linux.sh first, or set PUBLISH_DIR=/path/to/dist/admin-api" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# 1. user / group
# ---------------------------------------------------------------------------
if ! getent group  "${SERVICE_USER}" >/dev/null; then
    groupadd --system "${SERVICE_USER}"
fi
if ! getent passwd "${SERVICE_USER}" >/dev/null; then
    useradd --system --gid "${SERVICE_USER}" \
            --home-dir /var/lib/open5gs --shell /usr/sbin/nologin \
            "${SERVICE_USER}"
fi

# ---------------------------------------------------------------------------
# 2. binary + appsettings
# ---------------------------------------------------------------------------
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${SERVICE_DIR}"

install -m 0755 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    "${PUBLISH_DIR}/open5gs-admin-api" "${SERVICE_DIR}/open5gs-admin-api"

if [[ -f "${PUBLISH_DIR}/appsettings.json" ]]; then
    install -m 0644 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
        "${PUBLISH_DIR}/appsettings.json" "${SERVICE_DIR}/appsettings.json"
fi

# .pdb alongside the binary makes stack traces readable; harmless if absent.
if compgen -G "${PUBLISH_DIR}/*.pdb" >/dev/null; then
    install -m 0644 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
        "${PUBLISH_DIR}"/*.pdb "${SERVICE_DIR}/"
fi

# ---------------------------------------------------------------------------
# 3. env file (first-run only)
# ---------------------------------------------------------------------------
install -d -o root -g root -m 0755 "$(dirname "${ENV_FILE}")"
if [[ ! -e "${ENV_FILE}" ]]; then
    ENV_SRC=""
    if   [[ -f "${ENV_EXAMPLE_PRIMARY}"  ]]; then ENV_SRC="${ENV_EXAMPLE_PRIMARY}"
    elif [[ -f "${ENV_EXAMPLE_FALLBACK}" ]]; then ENV_SRC="${ENV_EXAMPLE_FALLBACK}"
    fi
    if [[ -n "${ENV_SRC}" ]]; then
        install -m 0640 -o root -g "${SERVICE_USER}" \
            "${ENV_SRC}" "${ENV_FILE}"
        echo "seeded ${ENV_FILE} from ${ENV_SRC}"
        echo "  -> edit it and set OPEN5GS_ADMIN_TOKEN before enabling the service."
    else
        echo "warning: no env-file example found; create ${ENV_FILE} manually" >&2
    fi
else
    echo "${ENV_FILE} already exists — leaving it alone."
fi

# ---------------------------------------------------------------------------
# 4. systemd unit (only if meson install didn't place it)
# ---------------------------------------------------------------------------
if [[ ! -f "${UNIT_FILE}" ]]; then
    if [[ -f "${UNIT_SRC_FALLBACK}" ]]; then
        # The .in file only has @-substitutions for bindir/sysconfdir,
        # which we don't reference in the admin-api unit, so a plain
        # copy is fine. Strip the `.in` extension on destination.
        install -m 0644 -o root -g root \
            "${UNIT_SRC_FALLBACK}" "${UNIT_FILE}"
        echo "installed unit ${UNIT_FILE}"
    else
        echo "warning: no unit file found at ${UNIT_FILE} and no fallback to copy" >&2
        echo "         run 'meson install' in your build dir, or copy" >&2
        echo "         configs/systemd/open5gs-admin-api.service.in manually." >&2
    fi
fi

# ---------------------------------------------------------------------------
# 5. reload + start
# ---------------------------------------------------------------------------
if [[ "${NO_RESTART:-0}" == "1" ]]; then
    echo
    echo "NO_RESTART=1 set — skipping systemctl. Finish up with:"
    echo "  sudo \$EDITOR ${ENV_FILE}"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable --now open5gs-admin-api.service"
    exit 0
fi

systemctl daemon-reload

# Enable + start only if the operator has actually set a token; bringing
# it up with the placeholder would hand out an unauthenticated API.
if grep -qE '^OPEN5GS_ADMIN_TOKEN=replace-me' "${ENV_FILE}" 2>/dev/null; then
    echo
    echo "WARNING: ${ENV_FILE} still has the placeholder token."
    echo "         Edit it, then run:"
    echo "           sudo systemctl enable --now open5gs-admin-api.service"
    exit 0
fi

systemctl enable  open5gs-admin-api.service
systemctl restart open5gs-admin-api.service

echo
systemctl --no-pager --full status open5gs-admin-api.service || true
echo
echo "tail logs with:   journalctl -u open5gs-admin-api.service -f"
