# Pretty5GS

Pretty5GS is a production-oriented fork of [Open5GS](https://open5gs.org/) for LTE/EPC deployments. It rebases on current upstream Open5GS and adds operator-focused features for scale (SMP workers), attach diagnostics, PLMN-aware GTP selection, RADIUS, roaming, CDR/CGF throughput, NMS admin APIs, and optional collapsed SAEGW-C.

Upstream docs: [open5gs.org](https://open5gs.org/open5gs/docs/). This README describes **what Pretty5GS adds** (vs `open5gs/open5gs`) and how to turn optional features on. Deep dives: `docs/smp-workers.md`, `docs/collapsed-saegw.md`, `docs/nms-sighup-reload.md`, `docs/lawful-interception.md`.

## What changed vs upstream Open5GS

| Area | Upstream | Pretty5GS |
|------|----------|-------------|
| **RADIUS (SMF)** | Basic support | Multi-server RADIUS, framed IP, Framed-Route / Framed-IPv6-Route, accounting, admin API controls |
| **PFCP / SMF pools** | Standard pools | Multi-DNN subnets sharing one UE pool; pool-exhaustion logs with IMSI/DNN |
| **Admin HTTP API** | Limited | MME/SMF/SGWC/HSS `:9090` — metrics, per-IMSI trace, RADIUS/subnet tuning, maintenance/drain, session delete, HSS CLR, queues |
| **Production metrics** | Global gauges only on MME; SMF/UPF 5G-style | Per-PLMN attach/auth/registered UE (MME), SGWC UE/session by PGW, SMF UE by PLMN, UPF sessions by CP peer (SGWU/PGWU); PFCP peer state |
| **MME / SGWC SMP** | Single-threaded hot path | Optional `mme.workers` / Stage C, S1AP RX/TX offload, SGsAP TX I/O, GTP-C RX thread; `sgwc.workers` session shards (**default off**) — see `docs/smp-workers.md` |
| **Collapsed SAEGW-C** | Always MME→SGW-C→SMF | Optional `smf.collapsed` — MME S11 terminates on SMF (no SGW-C/U); S8 relay for home-routed roamers (**default off**) — `docs/collapsed-saegw.md` |
| **CGF (Ga / GTP')** | Single drain path | Parallel `cgf.workers`, `send_mode: round_robin` across UP peers, multi-file drain (`max_active_files`) |
| **NMS PACKET dumps** | Hexdump / log level only | Per-traced-IMSI `PACKET: proto=… dir=… b64=…` (S1AP/GTP/PFCP/Diameter/RADIUS) for PCAP rebuild |
| **MME scale** | Fixed large pools | Configurable per-UE pool multipliers, peak stats, SIGUSR1 pool dump, soft-cap LRU |
| **MME lookups** | Linear scans | O(1) `enb_ue` by S1AP-ID; served-TAI hash; EBI → bearer map; O(1) sock maps |
| **SCTP** | Reconnect edge cases | Stale eNB/gNB SCTP context replaced on reconnect |
| **TAI / PLMN** | Standard caps | Higher TAI limits; serving-only TAI; ePLMN; S1 PLMN preference |
| **SGWC / SMF (GTP-C)** | First matching peer | Selection by `serving_plmn_id`, `imsi_plmn_id`, `plmn_id`, `order`; inbound roam uses IMSI PLMN by default |
| **PGW / SMF (MME)** | First configured SMF | Same PLMN rules as SGWC under `mme.gtpc.client.smf`; MIP host DNS cache invalidate API |
| **Roaming** | Baseline | Inbound roam GTP APN/OI, home-PGW interop, SGW-U NWI wildcard, EPLMN serving-only, ULA tolerance, configurable T3450 / T3346 |
| **SGs (CSFB)** | No Ts6-1 | Per-UE **Ts6-1** on SGs Location Update → EPS-only attach accept on timeout; optional `fake_csfb` SMS-only Combined |
| **GTP CSR interop** | Always sends Indication IE | Optional global `omit_indication_on_gtp_csr` for vendor PGW/SGWC |
| **Attach cleanup** | Limited | S11 Delete Session when Attach Accept cannot be sent after CSR ok; safe OLD→NEW UE session merge; orphan sweeps |
| **SGWC roam S5** | TEID offset fallback only | Stale Update Bearer TEID validated; late PGW CSR no longer aborts SGWC; PFCP RESTI / DROBU idle buffering |
| **SGWC Gn** | Not present | Optional GTPv1 Gn toward legacy GGSNs |
| **HSS Sh / CS** | S6a-centric | 3GPP **Sh** server + S6a NOR; CS-domain via IWF **S6d** ULR |
| **Tracing** | Global log level | Per-IMSI DEBUG without restart; correlated MME/SGWC/SMF/HSS logs; MSISDN/IMEI alias resolve |
| **Attach visibility** | Mostly INFO/DEBUG | `ATTACH step:` funnel; SGW/PGW pick logs; **GTP timeout shows S11 peer**; demoted race/churn noise |
| **HSS / S6a ACL** | Attach-only PLMN check; unmapped IMSIs still hit default DRA realm | Block AIR/ULR before Diameter when IMSI fails `access_control`, `imsi_acl`, or `hss_map` (auto-enforced) |
| **CDR (4G)** | Partial ULI | ULI in MME/SMF/SGWC CDRs; SGWC `servedMSISDN`; serving-node / advertise-IP fixes; partial CDR `recordOpeningTime` |
| **Lawful interception** | Not present | Optional HI event reporting on MME/SMF (**off by default**) — `docs/lawful-interception.md` |
| **Milenage K4** | Not present | Optional Huawei HSS9860 K/OPc unwrap (**off by default**) |
| **PCRF / Gx + PyHSS** | MongoDB `db_uri` | Optional PyHSS MySQL policy (**off by default**); YAML policy unchanged |
| **URRP / T-ADS** | Limited | S6a URRP-MME UE reachability + admin paging API |
| **Maintenance** | Restart / manual | Maintenance mode + graceful drain on MME/SGWC/SMF |
| **Crash hardening** | Many `ogs_assert` aborts | Soft-fail races (stale SGs CONNREFUSED, empty paging type, empty bearer lists, late DSR, …) |
| **Runtime config reload (MME)** | Restart for any YAML change | **SIGHUP** reload: timers, GTP echo, full-replace lists (TAI, ACL, peers, trace), **logger** without dropping UEs |
| **Runtime config reload (SMF / SGWC)** | Restart for bind addresses | **SIGHUP** reload: SMF session subnets/APN pools, UPF peers, CDR/RADIUS; SGWC roam/TEID/**CDR spool_dir**/NWI/SGW-U peers, **logger** |
| **Runtime config reload (HSS)** | Restart for any YAML change | **SIGHUP** reload: `hss.trace_imsi` + **logger** |

### Features (new capabilities)

- **Collapsed SAEGW-C** — `smf.collapsed: true`: MME talks S11 to SMF; UPF terminates S1-U; home-routed roamers use S8 relay (`docs/collapsed-saegw.md`). Classic MME→SGW-C→SMF path unchanged when collapsed is off.
- **SMP / Stage C** — optional MME UE shards (`mme.workers`, `stage_c`), S1AP RX/TX workers, SGsAP I/O thread, GTP-C RX thread; SGW-C session workers (`sgwc.workers`). All default **0 / off**.
- **CGF scale-out** — `cgf.workers`, `send_mode: round_robin`, `batch.max_active_files` for multi-peer Ga drain.
- **NMS PACKET line** — IMSI-filtered base64 wire dumps (`/admin/trace/imsi`) for PrettyNMS PCAP rebuild (S1AP, GTP, PFCP, Diameter, RADIUS).
- **Admin ops** — maintenance enable/drain, `/admin/session/delete` (MME/SMF/SGWC), HSS `POST /admin/s6a/clr`, UE page, `/admin/queues`, PGW-host DNS cache clear, reload audit + `/admin/config`.
- **HSS Sh + CS** — Sh interface; S6a Notify; IWF S6d path for VLR/MSC.
- **SGWC Gn** — GTPv1 toward legacy GGSNs.
- **URRP-MME / T-ADS** — arm/report UE reachability; admin paging.
- **fake_csfb** — protocol-complete SMS-only Combined Accept without a live MSC (does not override HSS packet-only NAM).
- **Lawful interception (HI)** — optional MME/SMF event reporting (**off by default**).
- **Enterprise metrics** — per-PLMN / per-SGW / per-PGW / per-CP-peer gauges (see metrics section below).

### Improvements (ops, interop, reliability)

- Attach/TAU funnel logging, richer IMSI/peer/TAC/TEID context on errors; race/churn demoted from ERROR→WARN.
- Inbound-roam ACL (IMSI prefix + optional TAC/eNB), `hss_map` enforcement, APN allow-lists / correction policies.
- S11 recovery / GTP echo, SGWC restart purge, orphan UE/eNB sweeps, held-DDN and TX-hold watchdogs.
- PFCP idle buffering: DROP / REARM / **DROBU** (TS 23.401 paging-fail), RESTI on restore paths.
- Countless production crash guards (null VLR on SGs down, stale paging type 0, empty modify lists, late Delete Session, …).
- CDR field correctness (serving-node IP, advertise IP, partial CDR opening time, Ga seq / Possibly-Dup).

### Integrations

- **PrettyNMS** — metrics + admin HTTP on `:9090`, SIGHUP reload matrix (`docs/nms-sighup-reload.md`), IMSI trace sync, PACKET dumps.
- **PyHSS** — optional PCRF Gx MySQL; K4 for Milenage unwrap when enabled.
- **Huawei / vendor PGW** — K4, `omit_indication_on_gtp_csr`, roam TEID offset / NWI rewrite.
- **RADIUS farms** — multi-server auth/acct + PoD; admin/SIGHUP apply.
- **CGF / Ga billing** — spool + multi-worker GTP' toward charging peers.

### Performance

- Dropped global `ogs_malloc` allocator mutex (plain heap) under SMP load.
- O(1) MME served-TAI and SCTP sock lookups; bounded event queues; non-blocking main-thread queue posts.
- Optional S1AP RX decode + TX encode offload; SGsAP send offload; ASN.1 free offload.
- SGW-C owner-sharded workers; CGF parallel drain + multi-file Ga window fill.
- Lazy `ogs_debug`/`ogs_trace` formatting; skip discarded log format cost; rate-limited IMSI-trace / PACKET lines.

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

### Collapsed SAEGW-C (no SGW-C / SGW-U)

```yaml
smf:
  collapsed: true   # MME S11 → this SMF; restart smfd after change
```

Point `mme.gtpc.client.sgwc` at the SMF GTP-C address. Details: `docs/collapsed-saegw.md`.

### SMP workers (MME / SGWC)

```yaml
mme:
  workers: 0              # UE shards; 0 = off
  stage_c: 0
  s1ap_rx_workers: 0
  s1ap_tx_workers: 0
sgwc:
  workers: 0              # session shards; 0 = off
```

See `docs/smp-workers.md`. Leave at 0 unless you have soak-tested the deployment.

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
mme:   # also smf / sgwc / hss
  trace_imsi:
    - 001010000000001
```

```bash
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=001010000000001'
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=list'
```

HSS traces S6a / Cx / SWx / Sh Diameter exchanges for matching IMSIs (PROC=`S6a-AIR`, `Cx-UAR`, `SWx-MAR`, `Sh-UDR`, …). YAML `hss.trace_imsi` loads at start and on **SIGHUP** (`systemctl reload open5gs-hssd`); runtime add/list/clear also via the metrics port.

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
    - plmn_id: { mcc: 999, mnc: 70 }   # home / all subscribers (example)
    - plmn_id: { mcc: 999, mnc: 71 }
    - default_reject_cause: 13
    - imsi_prefix: "00101"              # inbound roam only (example)
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

Output is **gitignored** (`configs/open5gs/roam-access.generated.yaml`). It is a full `mme:` fragment — merge into `/etc/open5gs/mme.yaml` or splice `mme.access_control`. Use your real IMSI prefixes and PLMNs only in private server config, not in git.

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

**Runtime config reload (MME)**

Full NMS matrix (every reloadable YAML key): **`docs/nms-sighup-reload.md`**.

Fictional full config samples (all services, lab PLMN 999/70): **`configs/nms/samples/`**.

Edit `/etc/open5gs/mme.yaml`, then reload without restarting the daemon (attached UEs stay up):

```bash
sudo systemctl reload open5gs-mmed
# or: sudo kill -HUP "$(pidof open5gs-mmed)"
```

On success, `mme.log` shows `MME SIGHUP reload completed` and lines like `SIGHUP: sgwc peer added` or `SIGHUP: trace_imsi replaced`.

| Reload type | Keys | Behaviour |
|-------------|------|-----------|
| **Scalars** | `mme.time` (`t3402`, `t3396`, `t3412`, `t3423`, `idle`, `t3346`, `bearer_setup`, `s11_holding`) | Re-read from YAML; applies to **new** timer starts |
| **Scalars** | `mme.gtpc.echo_interval` | Reschedules S11 GTP echo to all SGWC peers |
| **Full replace lists** | `tai`, `access_control`, `hss_map`, `equivalent_plmn`, `imsi_acl`, `trace_imsi`, `emergency` | Rebuilt from YAML on each reload (add, remove, reorder) |
| **Peer sync** | `mme.gtpc.client.sgwc`, `mme.gtpc.client.smf` | New peers connect immediately; removed peers dropped when no S11 context (SGWC) or anytime (SMF/PGW selection list) |
| **Policy scalars** | `attach_accept`, `equivalent_plmn_serving_only`, `ims_voice_over_ps_in_s1_mode`, `tai_list_in_accept`, `require_hss_map`, `ambr_limit` | Updated in memory for subsequent attach/TAU |
| **Logger** | `logger.level`, `logger.domain`, `logger.file`, timestamps | Applied on every SIGHUP |

**Not reloadable via SIGHUP** (daemon restart required): `mme.gtpc.recovery`, SCTP/S1 bind addresses, pool sizes, and most other `mme:` keys. If reload fails, the previous config is kept (`Configuration reload failed` in the log).

**Key-absent semantics (all NFs):** full-replace keys are rebuilt only when the key is *present* in the YAML — deleting a key entirely keeps the previous values. To clear a list, keep the key with an empty value (e.g. `trace_imsi: []`). Exception: an empty or unparsable `tai:` section is rejected and the previous served TAI list is kept, so the MME never ends up serving zero TAIs.

**Runtime config reload (SMF)**

Edit `/etc/open5gs/smf.yaml`, then:

```bash
sudo systemctl reload open5gs-smfd
# or: sudo kill -HUP "$(pidof open5gs-smfd)"
```

| Reload type | Keys | Behaviour |
|-------------|------|-----------|
| **Session pools** | `smf.session[]` (`subnet`, `dnn`/`apn`, `gateway`, `range`, `dev`) | Add new pools; remove pools no longer in YAML when all IPs are free |
| **Peer sync** | `smf.pfcp.client.upf[]` | Add new UPF PFCP peers; remove peers no longer in YAML when no PFCP sessions |
| **Full replace** | `smf.trace_imsi`, `smf.dns` | Rebuilt from YAML on each reload |
| **Scalars** | `smf.mtu` | Updated for subsequent sessions |
| **Full replace** | `smf.cdr`, `smf.radius` | Same safe path as admin API: CDR writer close/reopen; RADIUS farm + optional PoD listener swap |
| **Logger** | `logger.level`, `logger.domain`, `logger.file`, timestamps | Applied on every SIGHUP |

**Not reloadable:** `smf.pfcp.server`, `smf.gtpc.server`, `smf.sbi.server`, metrics listen addresses. Admin API watcher remains an alternative for the same CDR/RADIUS keys.

**Runtime config reload (SGWC)**

Edit `/etc/open5gs/sgwc.yaml`, then:

```bash
sudo systemctl reload open5gs-sgwcd
# or: sudo kill -HUP "$(pidof open5gs-sgwcd)"
```

| Reload type | Keys | Behaviour |
|-------------|------|-----------|
| **Scalars** | `sgwc.gtpc.echo_interval`, `sgwc.gtpu.*`, `sgwc.inbound_roam.gtpc` (except source port), `sgwc.inbound_roam.gtpu.*` | Applied in memory |
| **Full replace** | `sgwc.cdr` (incl. `spool_dir`) | Writer close/reopen (same as SMF) |
| **Full replace lists** | `sgwc.sgwu_nwi_rewrite`, `sgwc.inbound_roam.sgwu_nwi_rewrite` | Rebuilt from YAML (both keys merge into one list per reload pass) |
| **Peer sync** | `sgwc.pfcp.client.sgwu[]` / `sgwc.sgwu[]` | Add new SGW-U PFCP peers; remove peers no longer in YAML when no PFCP sessions |
| **Full replace** | `sgwc.gn.pgw`, `sgwc.trace_imsi` | Rebuilt from YAML on each reload |
| **Logger** | `logger.level`, `logger.domain`, `logger.file`, timestamps | Applied on every SIGHUP (MME/SMF/SGWC) |

**Not reloadable:** `sgwc.gtpc.server`, `sgwc.pfcp.server`, `sgwc.metrics.server`, `sgwc.inbound_roam.gtpc.source_port` (extra S5 bind socket), **`sgwc.gn.server`** (GTPv1 Gn bind).

SMF RADIUS/Ga and CGF GTP' peer changes can also be pushed through the **admin API** file watcher — see `tools/admin-api/README.md`.

**Runtime config reload (HSS)**

Edit `/etc/open5gs/hss.yaml`, then:

```bash
sudo systemctl reload open5gs-hssd
# or: sudo kill -HUP "$(pidof open5gs-hssd)"
```

| Kind | Keys | Behaviour |
|------|------|-----------|
| **Full replace** | `hss.trace_imsi` | Rebuilt from YAML on each reload (`trace_imsi: []` clears) |
| **Logger** | `logger.level`, `logger.domain`, `logger.file`, timestamps | Applied on every SIGHUP |

**Not reloadable:** `hss.freeDiameter`, `hss.metrics`, `hss.sms_over_ims`, `hss.use_mongodb_change_stream`. Per-IMSI filters can also be changed live via `GET /admin/trace/imsi` on the metrics port.

**Prometheus metrics (MME / SGWC / SMF / UPF)**

Each NF exposes OpenMetrics on `GET /metrics` (default listener in YAML `metrics.server`, typically port **9090**). SGWC now has a metrics HTTP server — add `metrics` to `sgwc.yaml` if your live config predates this fork.

| NF | Gauge / counter | Labels | Meaning |
|----|-----------------|--------|---------|
| MME | `mme_attach_attempt_total` | `plmnid` | Attach requests accepted for processing |
| MME | `mme_attach_success_total` | `plmnid` | Attach completed (registered) |
| MME | `mme_attach_reject_total` | `plmnid`, `cause` | Attach reject sent (EMM cause) |
| MME | `mme_auth_request_total` | `plmnid` | Authentication requests sent |
| MME | `mme_auth_success_total` | `plmnid` | Authentication responses OK |
| MME | `mme_auth_fail_total` | `plmnid` | Authentication reject / failure |
| MME | `mme_ue_registered` | `plmnid` | Currently registered UEs (home PLMN from IMSI) |
| MME | `mme_ue_lost_total` | `reason` | Registered UE removed (`ue_detach`, `mme_explicit`, `hss_explicit`, `mme_implicit`, `hss_implicit`, `other`) |
| MME | `mme_session_active_by_sgw` | `sgw`, `plmnid`, `apn` | Active PDN sessions per selected SGWC (S11 peer address), IMSI home PLMN and APN — counts sessions on SGWs that expose no metrics themselves (e.g. third-party cores) |
| MME | `mme_ue_active_by_sgw` | `sgw`, `plmnid` | ECM-CONNECTED UEs per selected SGWC and IMSI home PLMN (one count per `enb_ue` S1 context; `sum(mme_ue_active_by_sgw)` <= `enb_ue` — S1 contexts still mid-attach, before IMSI/SGW are known, are not yet labelled) |
| SGWC | `sgwc_ue_active` | `plmnid` | UEs with S11 context |
| SGWC | `sgwc_session_active` | `plmnid`, `pgw_addr` | Active PDN sessions per PGW/SMF S5-C peer |
| SMF | `smf_ue_active` | `plmnid` | UEs with at least one SMF context |
| UPF | `upf_sessionnbr_by_cp` | `cp_addr` | PFCP sessions per control-plane peer (SGWC on SGWU, SMF on PGWU) |

PLMN labels use IMSI home PLMN (`ogs_plmn_id_from_imsi_bcd`). On SGWC, session PLMN falls back to `serving_plmn_id` when set.

Example scrape config (Prometheus):

```yaml
scrape_configs:
  - job_name: open5gs
    static_configs:
      - targets:
          - 127.0.0.2:9090   # mme
          - 127.0.0.3:9090   # sgwc
          - 127.0.0.4:9090   # smf
          - 127.0.0.6:9090   # upf (SGWU instance)
          - 127.0.0.7:9090   # upf (PGWU instance, if separate)
```

Quick check:

```bash
curl -s http://127.0.0.2:9090/metrics | grep -E '^mme_ue_registered|^mme_attach_'
curl -s http://127.0.0.3:9090/metrics | grep '^sgwc_'
curl -s http://127.0.0.4:9090/metrics | grep '^smf_ue_active'
curl -s http://127.0.0.6:9090/metrics | grep '^upf_sessionnbr_by_cp'
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
