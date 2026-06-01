#!/bin/bash
# Apply freeDiameter rt_default routing on MME (DRA hub: all Dest-Realms → hss01).
# Run on epc-host01 as root: sudo bash apply-mme-rt-default.sh

set -euo pipefail

MMECONF=/etc/freeDiameter/mmelocal.conf
RTCONF=/etc/freeDiameter/rt_default.conf
RTFDX=/usr/lib/x86_64-linux-gnu/freeDiameter/rt_default.fdx
DRA_PEER='hss01.epc.mnc070.mcc999.3gppnetwork.org'
TS=$(date +%Y%m%d%H%M%S)

if [[ $(id -u) -ne 0 ]]; then
    echo "Run with: sudo bash $0"
    exit 1
fi

if [[ ! -f "$MMECONF" ]]; then
    echo "Missing $MMECONF"
    exit 1
fi

if [[ ! -f "$RTFDX" ]]; then
    echo "Missing $RTFDX — install freeDiameter rt_default extension"
    exit 1
fi

cp -a "$MMECONF" "${MMECONF}.bak.${TS}"
echo "Backup: ${MMECONF}.bak.${TS}"

# Comment NoRelay (enable relay path; rt_default overrides routing table)
if grep -qE '^[[:space:]]*NoRelay[[:space:]]*;' "$MMECONF"; then
    sed -i 's/^[[:space:]]*NoRelay[[:space:]]*;/#NoRelay;/' "$MMECONF"
    echo "Commented NoRelay in $MMECONF"
fi

# Add rt_default LoadExtension if not present
if ! grep -q 'rt_default.fdx' "$MMECONF"; then
    awk -v ins="LoadExtension = \"${RTFDX}\" : \"${RTCONF}\";" '
        /^LoadExtension = .*dict_dcca_3gpp/ {
            print
            print ins
            next
        }
        { print }
    ' "$MMECONF" > "${MMECONF}.tmp" && mv "${MMECONF}.tmp" "$MMECONF"
    echo "Added rt_default LoadExtension"
else
    echo "rt_default LoadExtension already present"
fi

# rt_default.conf — route all outbound Diameter to DRA peer
cat > "$RTCONF" <<EOF
# MME → DRA for all Destination-Realms (011, 012, …). DRA forwards by Dest-Realm.
* : "${DRA_PEER}" += 100;
EOF
chmod 644 "$RTCONF"
echo "Wrote $RTCONF"

echo "--- Active snippets ---"
grep -E 'NoRelay|rt_default|ConnectPeer' "$MMECONF" || true
cat "$RTCONF"

systemctl restart open5gs-mmed
sleep 2
if systemctl is-active --quiet open5gs-mmed; then
    echo "open5gs-mmed: active"
else
    echo "open5gs-mmed failed to start — restore backup:"
    echo "  cp ${MMECONF}.bak.${TS} $MMECONF && systemctl restart open5gs-mmed"
    exit 1
fi

echo "--- Recent Diameter peer / routing (tail) ---"
grep -iE 'rt_default|hss01|ROUTING ERROR|CONNECT|DISCONNECT' /var/log/open5gs/mme.log 2>/dev/null | tail -15 || true

echo "Done. Test a 999-70 attach; expect no 'No remaining suitable candidate'."
