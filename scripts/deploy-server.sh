#!/usr/bin/env bash
# Full rebuild + install Open5GS on your Open5GS host (or any host with systemd units).
# Run on the server as a user with passwordless sudo, from any directory:
#   bash /opt/open5gs/scripts/deploy-server.sh
#
# Prerequisite: push fixes to github/main first, then run this script on the server.

set -euo pipefail

REPO_DIR="${OPEN5GS_REPO:-/opt/open5gs}"
GITHUB_REMOTE="${GITHUB_REMOTE:-github}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"

MME_ADMIN_URL="${MME_ADMIN_URL:-http://127.0.0.1:9090}"
MAINTENANCE="${MAINTENANCE:-1}"          # 1 = block new attaches while verifying stack
VERIFY="${VERIFY:-1}"                    # 1 = run post-install health checks
SKIP_CLEAN="${SKIP_CLEAN:-0}"            # 1 = keep local untracked files (skip git clean -fd)

log() { printf '[deploy] %s\n' "$*"; }
die() { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

mme_maintenance() {
    local action="$1"
    if [[ "$MAINTENANCE" != "1" ]]; then
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        log "curl missing; skipping MME maintenance $action"
        return 0
    fi
    if ! curl -sf -X POST "${MME_ADMIN_URL}/admin/maintenance/${action}" >/dev/null; then
        log "warning: MME maintenance/${action} failed (is mmed up on ${MME_ADMIN_URL}?)"
        return 1
    fi
    log "MME maintenance ${action} OK"
}

wait_active() {
    local unit="$1" tries="${2:-30}"
    local i=0
    while (( i < tries )); do
        if systemctl is-active --quiet "$unit"; then
            log "$unit is active"
            return 0
        fi
        sleep 1
        (( i++ )) || true
    done
    die "$unit did not become active within ${tries}s"
}

verify_libs() {
    local gtp pfcp ok=0
    gtp="$(find /usr/lib -maxdepth 2 -name 'libogsgtp.so*' -type f 2>/dev/null | head -1 || true)"
    pfcp="$(find /usr/lib -maxdepth 2 -name 'libogspfcp.so*' -type f 2>/dev/null | head -1 || true)"

    if [[ -z "$gtp" || -z "$pfcp" ]]; then
        log "warning: could not locate libogsgtp.so / libogspfcp.so under /usr/lib"
        return 1
    fi

    if strings "$gtp" | grep -qF 'Stale GTP Transaction'; then
        log "OK: GTP xact hardening present in $gtp"
        ok=1
    else
        log "warning: Stale GTP Transaction string missing in $gtp (old libogsgtp?)"
    fi

    if strings "$pfcp" | grep -qF 'Stale PFCP Transaction'; then
        log "OK: PFCP xact hardening present in $pfcp"
        ok=1
    else
        log "warning: Stale PFCP Transaction string missing in $pfcp (old libogspfcp?)"
    fi

    ls -la "$gtp" "$pfcp" \
        "$(command -v open5gs-smfd 2>/dev/null || echo /usr/bin/open5gs-smfd)" \
        "$(command -v open5gs-sgwcd 2>/dev/null || echo /usr/bin/open5gs-sgwcd)" 2>/dev/null || true

    [[ "$ok" -eq 1 ]]
}

verify_stack() {
    local smf_log=/var/log/open5gs/smf.log
    local sgwc_log=/var/log/open5gs/sgwc.log
    local pcrf_log=/var/log/open5gs/pcrf.log

    if [[ "$VERIFY" != "1" ]]; then
        return 0
    fi

    log "verifying daemons (last 2 minutes of logs)..."

    if journalctl -u open5gs-smfd --since '2 min ago' 2>/dev/null \
            | grep -qiE 'SIGABRT|corrupted size'; then
        die "open5gs-smfd shows SIGABRT/heap corruption in journal"
    fi
    if journalctl -u open5gs-sgwcd --since '2 min ago' 2>/dev/null \
            | grep -qiE 'SIGABRT|corrupted size'; then
        die "open5gs-sgwcd shows SIGABRT/heap corruption in journal"
    fi

    if [[ -f "$pcrf_log" ]]; then
        if ! grep -q 'CONNECTED TO' "$pcrf_log" 2>/dev/null; then
            log "warning: no PCRF Diameter CONNECTED line in $pcrf_log yet"
        else
            log "OK: PCRF Diameter peer CONNECTED"
        fi
    fi

    if [[ -f "$sgwc_log" ]]; then
        if grep -q 'PFCP associated' "$sgwc_log" 2>/dev/null; then
            log "OK: SGWC PFCP associated"
        else
            log "warning: PFCP associated not found in $sgwc_log yet"
        fi
    fi

    if [[ -f "$smf_log" ]]; then
        if tail -200 "$smf_log" | grep -q 'No Gx Diameter Peer'; then
            log "warning: SMF still reports No Gx Diameter Peer"
        fi
    fi
}

# --- git sync ---
cd "$REPO_DIR" || die "repo not found: $REPO_DIR"

log "syncing ${GITHUB_REMOTE}/${GITHUB_BRANCH} in $REPO_DIR"
git remote add "$GITHUB_REMOTE" https://github.com/arayeji/Pretty5gs.git 2>/dev/null || true
git fetch "$GITHUB_REMOTE" "$GITHUB_BRANCH"
git reset --hard "${GITHUB_REMOTE}/${GITHUB_BRANCH}"
if [[ "$SKIP_CLEAN" != "1" ]]; then
    git clean -fd
fi
log "HEAD: $(git rev-parse --short HEAD) $(git log -1 --oneline)"

# --- stop (block new work; MME stop ends attach storm) ---
log "stopping Open5GS daemons"
sudo systemctl stop \
    open5gs-mmed \
    open5gs-sgwcd \
    open5gs-smfd \
    open5gs-pcrfd \
    open5gs-hssd \
    open5gs-cgfd \
    2>/dev/null || true

# Optional: uncomment if you run NRF on this host
# sudo systemctl stop open5gs-nrfd 2>/dev/null || true

# --- build + install (libs + daemons) ---
log "clean build"
sudo rm -rf build
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
sudo ldconfig

verify_libs || log "library verification reported warnings (see above)"

sudo systemctl daemon-reload

# --- restart: diameter/AAA first, then PGW/SGW-C, then MME last ---
log "restarting PCRF + HSS + CG"
sudo systemctl restart open5gs-pcrfd open5gs-hssd open5gs-cgfd
sleep 3
wait_active open5gs-pcrfd 20 || true
wait_active open5gs-hssd 20 || true

log "restarting SMF (wait for Gx peer)"
sudo systemctl restart open5gs-smfd
sleep 8
wait_active open5gs-smfd 30

log "restarting SGWC (wait for PFCP association to SGW-U)"
sudo systemctl restart open5gs-sgwcd
sleep 5
wait_active open5gs-sgwcd 30

# Block new attaches while we sanity-check SMF/SGWC (MME still down)
# (no effect until mmed is started)

log "restarting MME"
sudo systemctl restart open5gs-mmed
sleep 3
wait_active open5gs-mmed 30

mme_maintenance enable || true
sleep 2
verify_stack
mme_maintenance disable || true

# Optional admin-api proxy
if systemctl list-unit-files open5gs-admin-api.service >/dev/null 2>&1; then
    sudo systemctl restart open5gs-admin-api 2>/dev/null || true
fi

log "deploy finished — service status:"
systemctl --no-pager --full status \
    open5gs-pcrfd open5gs-hssd open5gs-smfd open5gs-sgwcd open5gs-mmed \
    2>/dev/null | sed -n '1,40p' || true

log "done. HEAD $(git -C "$REPO_DIR" rev-parse --short HEAD)"
