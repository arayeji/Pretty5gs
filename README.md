# Pretty5GS

Pretty5GS is a production-oriented fork of [Open5GS](https://open5gs.org/) for LTE/EPC deployments. It rebases on current upstream Open5GS and adds operator-focused changes for attach diagnostics, PLMN-aware GTP selection, RADIUS, roaming, and scale.

Upstream docs: [open5gs.org](https://open5gs.org/open5gs/docs/). This README describes **what Pretty5GS adds** and how to turn optional features on.

## What changed vs upstream Open5GS

| Area | Upstream | Pretty5GS |
|------|----------|-------------|
| **RADIUS (SMF)** | Basic support | Multi-server RADIUS, framed IP, Framed-Route / Framed-IPv6-Route, accounting, admin API controls |
| **PFCP / SMF pools** | Standard pools | Multi-DNN subnets sharing one UE pool; pool-exhaustion logs with IMSI/DNN |
| **Admin HTTP API** | Limited | MME/SMF `:9090` — metrics under load, per-IMSI trace, RADIUS/subnet tuning |
| **MME scale** | Fixed large pools | Configurable per-UE pool multipliers, peak stats, SIGUSR1 pool dump, soft-cap LRU |
| **MME lookups** | Linear scans | O(1) `enb_ue` by S1AP-ID; EBI → bearer map |
| **SCTP** | Reconnect edge cases | Stale eNB/gNB SCTP context replaced on reconnect |
| **TAI / PLMN** | Standard caps | Higher TAI limits; serving-only TAI; ePLMN; S1 PLMN preference |
| **SGWC / SMF (GTP-C)** | First matching peer | Selection by `serving_plmn_id`, `imsi_plmn_id`, `plmn_id` |
| **PGW / SMF (MME)** | First configured SMF | Same PLMN rules as SGWC under `mme.gtpc.client.smf` |
| **Roaming** | Baseline | Inbound roam, SGW-U NWI wildcard, EPLMN serving-only, ULA tolerance, configurable T3450 |
| **Tracing** | Global log level | Per-IMSI DEBUG without restart; correlated MME/SGWC/SMF attach logs |
| **Attach visibility** | Mostly INFO/DEBUG | `ATTACH step:` at ERROR; SGW/PGW pick logs with rule name |
| **CDR (4G)** | Partial ULI | ULI in MME/SMF/SGWC CDRs; SGWC `servedMSISDN`; higher APN / SGsAP caps |
| **Milenage K4** | Not present | Optional Huawei HSS9860 K/OPc unwrap (**off by default**) |
| **PCRF / Gx + PyHSS** | MongoDB `db_uri` | Optional PyHSS MySQL policy (**off by default**); YAML policy unchanged |

## Build and install

Same as Open5GS (Meson/Ninja). Use **one prefix** for all libs and binaries (do not mix `/usr/lib` and `/usr/local/lib`).

```bash
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
sudo ldconfig
```

After any change under `lib/app/` or `lib/crypt/`, always run **`ninja install`** (or copy **both** `libogsapp` and `libogscrypt` from the same build). Partial installs cause `undefined symbol: ogs_milenage_k4_apply_config` on every daemon.

Verify:

```bash
ldd /usr/bin/open5gs-sgwcd | grep -E 'ogsapp|ogscrypt'
nm -D /usr/lib/x86_64-linux-gnu/libogscrypt.so.2 | grep ogs_milenage_k4_apply_config
```

PyHSS MySQL on PCRF requires `meson setup build -Dmysql_pcrf=true` and MySQL client dev packages.

## Optional features (disabled by default)

### Milenage K4 (Huawei stored credentials)

Decrypts AES-wrapped K/OPc from HSS9860-style exports. **Disabled unless explicitly enabled.**

```yaml
# Any NF config with global: (e.g. hss.yaml)
global:
  milenage:
    enabled: true
    k4_file: /etc/open5gs/milenage_k4.key
```

Or environment: `OPEN5GS_K4_ENABLED=1` plus `OPEN5GS_K4` (32 hex chars) or `OPEN5GS_K4_FILE` (path).

Copy `configs/open5gs/milenage_k4.key.example` to a root-only file. All-zero key = no unwrap. For PyHSS, configure K4 in that stack separately (env `OPEN5GS_K4_*` / YAML `global.milenage` apply to Open5GS C Milenage only).

### PCRF Gx via PyHSS MySQL

Uses PyHSS `subscriber` + `apn` tables when YAML policy does not match. **Disabled unless `pcrf.mysql.enabled: true`.**

```yaml
# pcrf.yaml
pcrf:
  mongodb: true   # Mongo fallback when YAML/MySQL miss (standard Open5GS)
  mysql:
    enabled: true
    server: 127.0.0.1
    port: 3306
    user: pyhss
    password: change-me
    database: pyhss
```

Order: YAML `pcrf.policy` → MySQL (if enabled) → MongoDB (if `mongodb: true` and `db_uri` set).

## Configuration highlights

**Per-IMSI debug (no restart)**

```yaml
mme:
  trace_imsi:
    - 001010000000001
```

```bash
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=001010000000001'
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=list'
```

**SGWC / SMF PLMN selection (MME)** — put narrower `imsi_plmn_id` rows **before** `plmn_id` / `serving_plmn_id` under `mme.gtpc.client.sgwc` and `mme.gtpc.client.smf`.

**Production attach grep**

```bash
grep 'ATTACH step' /var/log/open5gs/mme.log
grep 'SGW' /var/log/open5gs/mme.log
grep 'PGW/SMF selected' /var/log/open5gs/mme.log
grep 'UE IP assign' /var/log/open5gs/smf.log
```

## Community and upstream

- Upstream issues: [open5gs/open5gs](https://github.com/open5gs/open5gs/issues)
- Pretty5GS fork: [github.com/arayeji/Pretty5gs](https://github.com/arayeji/Pretty5gs)

## License

AGPL-3.0+, same as Open5GS. See `LICENSE` and per-file copyrights.
