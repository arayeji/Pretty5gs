# Pretty5GS

Pretty5GS is a production-oriented fork of [Open5GS](https://open5gs.org/) focused on LTE/EPC operability, RADIUS integration, roaming, and attach-path diagnostics. It tracks upstream Open5GS for core 5GC behavior and adds features below that operators typically patch locally.

## Compared to upstream Open5GS

| Area | Upstream Open5GS | Pretty5GS |
|------|------------------|-----------|
| RADIUS (SMF) | Limited / evolving | Multi-server RADIUS, framed IP, Framed-Route / Framed-IPv6-Route, accounting, optional Gx bypass with PyHSS MySQL policy |
| PFCP / SMF pools | Standard pools | Multi-DNN subnets sharing one UE pool; clearer pool-exhaustion logging with IMSI/DNN |
| Admin API | Basic | HTTP admin on MME/SMF (9090): metrics under load, per-IMSI trace filter, SMF RADIUS/subnet controls |
| MME scale | Fixed large pools | Configurable per-UE pool multipliers, peak tracking, SIGUSR1 pool dump, soft-cap LRU eviction |
| MME lookups | Linear scans | O(1) `enb_ue` by S1AP-ID; EBI → bearer map |
| SCTP | Reconnect quirks | Stale eNB/gNB SCTP context replaced on reconnect |
| TAI / PLMN | Standard limits | Higher TAI caps; serving-only TAI list; ePLMN; S1 PLMN preference |
| SGWC / SMF GTP | Default selection | SGWC/SMF selection by serving PLMN and IMSI PLMN; S5-C F-TEID handling |
| PGW / SMF (MME) | First configured SMF | SMF/PGW pick by `plmn_id` / `serving_plmn_id` / `imsi_plmn_id` (same model as SGWC) |
| Roaming | Baseline | Inbound roam interop, SGW-U NWI wildcard, EPLMN serving-only, ULA tolerance, configurable T3450 |
| Tracing | Global log level only | Per-IMSI DEBUG without restart (`trace_imsi` YAML + `/admin/trace/imsi`); correlated MME/SGWC/SMF attach logs |
| Attach visibility | Mostly INFO/DEBUG | `ATTACH step:` lines at ERROR for production grep; SGW/PGW selection logged with rule name |
| CDR (4G) | Partial ULI | ULI in MME/SMF/SGWC CDRs; SGWC `servedMSISDN`; higher APN / SGsAP TAI-LAI limits |
| Milenage K4 (Huawei HSS9860) | Not present | Optional AES unwrap of stored K/OPc via env or `global.milenage` in YAML (disabled = all-zero key) |
| PyHSS | Separate | `milenage.py` K4 parity with Open5GS; optional MySQL PCRF path documented in local `build.md` (gitignored) |

## Quick start

Build and install follow upstream Open5GS (Meson/Ninja). Use the example configs under `configs/open5gs/`; replace addresses, PLMN IDs, and secrets with your lab values.

```bash
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
```

## Configuration highlights

**Per-IMSI debug (no restart)**

```yaml
# mme.yaml
mme:
  trace_imsi:
    - 001010000000001
```

```bash
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=001010000000001'
curl 'http://127.0.0.1:9090/admin/trace/imsi?imsi=list'
```

**Milenage K4 (Huawei ciphertext in MongoDB)**

```yaml
# hss.yaml (or any NF that loads global:)
global:
  milenage:
    k4_file: /etc/open5gs/milenage_k4.key
```

Copy `configs/open5gs/milenage_k4.key.example` to a root-only file and set your 32-hex-char key, or use `OPEN5GS_K4` / `OPEN5GS_K4_FILE`. All zeros disables unwrap.

**SGWC / SMF PLMN selection (MME)**

List more specific `imsi_plmn_id` entries before broader `plmn_id` / `serving_plmn_id` rows under `mme.gtpc.client.sgwc` and `mme.gtpc.client.smf`.

**Production attach grep**

```bash
grep 'ATTACH step' /var/log/open5gs/mme.log
grep 'SGW' /var/log/open5gs/mme.log
grep 'PGW/SMF selected' /var/log/open5gs/mme.log
grep 'UE IP assign' /var/log/open5gs/smf.log
```

## Branch layout (Pretty5GS remote)

Topic branches are stacked on `main` for review without merge conflicts when merged in order:

1. `feat/pretty5gs-radius` — RADIUS, PFCP multi-DNN, admin-api SMF, PyHSS Gx
2. `feat/pretty5gs-mme-tai` — TAI/ePLMN, SGWC Ga CDR, hot-path reductions
3. `feat/pretty5gs-mme-perf` — Pools, SCTP fix, metrics scale
4. `feat/pretty5gs-cdr-trace` — CDR fixes, correlated trace
5. `feat/pretty5gs-plmn-gtp` — PLMN/SGWC/SMF GTP selection
6. `feat/pretty5gs-roaming` — Roam, T3450, EPLMN
7. `feat/pretty5gs-imsi-trace` — Per-IMSI trace filter
8. `feat/pretty5gs-attach-diag` — Attach steps, PGW PLMN pick, SMF IP logs

Integration branch: `feat/pretty5gs` (full stack).

## License

Same as Open5GS: AGPL-3.0+. See upstream `LICENSE` and component copyrights in source files.
