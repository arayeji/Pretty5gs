#!/bin/bash
# Non-root prep + single sudo install. Run: bash install-mme-rt-default-remote.sh
set -euo pipefail
sudo cp -a /etc/freeDiameter/mmelocal.conf "/etc/freeDiameter/mmelocal.conf.bak.$(date +%Y%m%d%H%M%S)"
sudo cp /tmp/mmelocal.conf.new /etc/freeDiameter/mmelocal.conf
sudo cp /tmp/rt_default.conf /etc/freeDiameter/rt_default.conf
sudo chmod 644 /etc/freeDiameter/rt_default.conf
echo "--- verify ---"
grep -E 'NoRelay|rt_default|ConnectPeer' /etc/freeDiameter/mmelocal.conf
cat /etc/freeDiameter/rt_default.conf
sudo systemctl restart open5gs-mmed
sleep 2
systemctl is-active open5gs-mmed && echo "open5gs-mmed: active" || { echo "MME failed"; exit 1; }
grep -iE 'ROUTING ERROR|rt_default|hss01' /var/log/open5gs/mme.log 2>/dev/null | tail -10 || true
