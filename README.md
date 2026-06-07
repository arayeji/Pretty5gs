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
| **SGWC / SMF (GTP-C)** | First matching peer | Selection by `serving_plmn_id`, `imsi_plmn_id`, `plmn_id`; inbound roam uses IMSI PLMN by default |
| **PGW / SMF (MME)** | First configured SMF | Same PLMN rules as SGWC under `mme.gtpc.client.smf` |
| **Roaming** | Baseline | Inbound roam GTP APN/OI, home-PGW interop, SGW-U NWI wildcard, EPLMN serving-only, ULA tolerance, configurable T3450 |
| **SGs (CSFB)** | No Ts6-1 | Per-UE **Ts6-1** on SGs Location Update → EPS-only attach accept on timeout (default 10 s) |
| **GTP CSR interop** | Always sends Indication IE | Optional global `omit_indication_on_gtp_csr` for vendor PGW/SGWC |
| **Attach cleanup** | Limited | S11 Delete Session when Attach Accept cannot be sent after CSR ok; safe OLD→NEW UE session merge on re-attach |
| **SGWC roam S5** | TEID offset fallback only | Stale Update Bearer TEID validated; late PGW CSR no longer aborts SGWC |
| **Tracing** | Global log level | Per-IMSI DEBUG without restart; correlated MME/SGWC/SMF attach logs |
| **Attach visibility** | Mostly INFO/DEBUG | `ATTACH step:` funnel (INFO + ERROR on failures); SGW/PGW pick logs; **GTP timeout shows S11 peer** |
| **HSS / S6a ACL** | Attach-only PLMN check; unmapped IMSIs still hit default DRA realm | Block AIR/ULR before Diameter when IMSI fails `access_control`, `imsi_acl`, or `hss_map` (auto-enforced) |
| **CDR (4G)** | Partial ULI | ULI in MME/SMF/SGWC CDRs; SGWC `servedMSISDN`; higher APN / SGsAP caps |
| **Milenage K4** | Not present | Optional Huawei HSS9860 K/OPc unwrap (**off by default**) |
| **PCRF / Gx + PyHSS** | MongoDB `db_uri` | Optional PyHSS MySQL policy (**off by default**); YAML policy unchanged |

## Build and install

Use **`build.sh`** (release by default). One prefix for all libs and binaries (do not mix `/usr/lib` and `/usr/local/lib`).

```bash
./build.sh                                    # release compile only
MYSQL_PCRF=1 PREFIX=/usr INSTALL=1 ./build.sh # release + install + restart EPC daemons
BUILDTYPE=debug ./build.sh                    # debug symbols for gdb
```

Manual Meson (same as `./build.sh` defaults):

```bash
meson setup build --prefix=/usr --buildtype=release
ninja -C build
sudo ninja -C build install
sudo ldconfig
```

See **`build.md`** for the full server recipe (PyHSS MySQL, debug vs release, verify).

After any change under `lib/app/` or `lib/crypt/`, always run **`ninja install`** from the same build. Partial installs cause missing `libogsapp`/`libogscrypt` symbols on every daemon.

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

**HSS ACL — block unknown IMSIs before S6a (AIR/ULR)**

Stops attach/TAU paths from flooding HSS/DRA with authentication and update-location requests for PLMNs or IMSI ranges you do not serve. Rejection happens **before** any Diameter message is sent; the UE gets a NAS attach reject (typically `PLMN not allowed`).

Enforcement is active when **any** of these are configured:

| Mechanism | Config | Behaviour |
|-----------|--------|-----------|
| PLMN whitelist | `access_control` (`plmn_id`) | Listed HPLMNs allowed for **all** subscribers; others rejected (optional `reject_cause`, `default_reject_cause`) |
| Inbound roam site list | `access_control` (`imsi_prefix` + optional `tac` / `enb_id`) | **Inbound roam only** (IMSI HPLMN ≠ serving TAI PLMN): IMSI must match prefix; if `tac` / `enb_id` are set, UE location must match |
| IMSI prefix whitelist | `imsi_acl` | Only IMSIs matching at least one prefix may reach HSS |
| HSS map | `hss_map` + `require_hss_map` | Only HPLMNs listed in `hss_map` may reach HSS. **`require_hss_map` auto-enables** when `hss_map` is present unless you set `require_hss_map: false` |

```yaml
mme:
  access_control:
    - plmn_id: { mcc: 999, mnc: 70 }   # home / all subscribers
    - plmn_id: { mcc: 999, mnc: 71 }
    - default_reject_cause: 13
    - imsi_prefix: "00101"              # inbound roam only
      reject_cause: 13
      tac: [10003, 10012]              # optional; omit = any TAC for this prefix
      enb_id: [260003, 450004]        # optional; omit = any eNB for this prefix

  hss_map:
    - plmn_id: { mcc: 999, mnc: 70 }
      realm: epc.mnc070.mcc999.3gppnetwork.org
    - plmn_id: { mcc: 999, mnc: 71 }
      realm: epc.mnc071.mcc999.3gppnetwork.org
  # require_hss_map: true   # default when hss_map is set

  # optional finer IMSI filter (in addition to access_control / hss_map):
  # imsi_acl:
  #   - 99970
  #   - 00101
```

Generate `access_control` from a site CSV (TAC + eNodeB columns):

```bash
python scripts/gen_roam_access_from_csv.py \
  --csv "configs/open5gs/roam-sites.example.csv" \
  --prefix 00101 --prefix 99970 \
  --output configs/open5gs/roam-access.generated.yaml
```

Output is **gitignored** (`configs/open5gs/roam-access.generated.yaml`). It is a full `mme:` fragment — merge into `/etc/open5gs/mme.yaml` or splice `mme.access_control`. Prefix `00101` = home PLMN (999-70), `99970` = 999-71 inbound roamers.

Log lines when blocked:

```bash
grep -E 'inbound roam|access_control|IMSI not in ACL' /var/log/open5gs/mme.log
```

Verify binary after deploy:

```bash
strings /usr/bin/open5gs-mmed | grep 'IMSI not in ACL'
```

**SGWC / SMF PLMN selection (MME)** — under `mme.gtpc.client.sgwc` and `mme.gtpc.client.smf`:

- `imsi_plmn_id` — match UE **home** IMSI PLMN (recommended for inbound roam PGW/SGWC rows).
- `serving_plmn_id` — match **visited** TAI PLMN.
- `plmn_id` — meaning depends on `inbound_roam.gtpc_plmn_id_is_imsi_plmn` (**default `true`** → IMSI PLMN; set `false` for legacy serving-PLMN behaviour).

Put narrower IMSI rows **before** default / serving rows.

**Inbound roam (MME)**

```yaml
mme:
  omit_indication_on_gtp_csr: false   # global: omit GTP Indication IE on all CSRs
  inbound_roam:
    gtp_apn_format: fqdn              # received | fqdn
    gtpc_plmn_id_is_imsi_plmn: true   # plmn_id on gtpc.client = IMSI HPLMN
    strip_pap_from_gtp_pco: false
    force_ipv4_pdn_on_home_pgw: false
  time:
    sgs_ts6_1:
      value: 10                       # SGs LU timeout (Ts6-1); EPS-only fallback
```

**SGWC inbound roam (S5 TEID interop)**

```yaml
sgwc:
  inbound_roam:
    gtpc:
      teid_offset: 0x80000000         # S5-C TEID offset for home PGW interop
```

**Production attach grep**

```bash
# Attach funnel (all steps at INFO; failures at ERROR)
grep 'ATTACH step' /var/log/open5gs/mme.log

# Key funnel steps
grep -E 'imsi_known|create_session_req|create_session_rsp_ok|attach_accept|attach_complete|attach_reject|attach_accept_no_s1|attach_accept_cleanup|sgsap_lu_timeout|sgsap_lu_reject' /var/log/open5gs/mme.log

# SGW/PGW selection
grep -E 'SGW confirmed|SGW reselected|PGW/SMF selected' /var/log/open5gs/mme.log

# GTP timeouts (includes S11 peer IP:port and message name)
grep 'GTP Timeout S11' /var/log/open5gs/mme.log

# SGWC stale roam UBR
grep -E 'Stale Update Bearer|No Context in TEID' /var/log/open5gs/sgwc.log

grep 'UE IP assign' /var/log/open5gs/smf.log
```

## Community and upstream

- Upstream issues: [open5gs/open5gs](https://github.com/open5gs/open5gs/issues)
- Pretty5GS fork: [github.com/arayeji/Pretty5gs](https://github.com/arayeji/Pretty5gs)

## License

AGPL-3.0+, same as Open5GS. See `LICENSE` and per-file copyrights.
