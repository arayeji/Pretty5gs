# MME configuration catalog (operator help)

Grounded in this fork's parsers and reload paths — not a generic Open5GS dump.

**Machine-readable catalog (authoritative path list):** [`mme-config-catalog.json`](./mme-config-catalog.json) (356 rows). List containers use a trailing `[]` on the path (e.g. `mme.pgw_selection.rules[]`); nested fields keep `[].` for items.

## Evidence sources

- `src/mme/mme-context.c` — `mme_context_parse_config`, `mme_context_prepare`, `mme_attach_accept_*`, `mme_context_reload_runtime`, GUMMEI/TAI/GTP-C/paging/pgw_selection
- `src/mme/mme-reload-lists.c` — `mme_reload_lists_key_add_only`, `reload_attach_accept_scalars`
- `src/mme/s1ap-overload.c` — `mme_overload_config_set`, `OVL_*` defaults
- `src/mme/mme-inbound-roam-apn.c`, `mme-apn-policy.c`, `mme-li.c`, `eplmn-config.c`
- `lib/app/ogs-config.c` / `ogs-init.c` — `global.*`, `logger.*`
- `configs/nms/mme-reference.yaml`, `configs/nms/samples/mme.yaml`, `configs/nms/nms-config-catalog.json`, `docs/nms-sighup-reload.md`
- Global rule: **key absent on SIGHUP keeps the previous value** (`mme_context_reload_runtime` / NMS global rules).

## Known traps (verify first)

| Wrong / ambiguous | Canonical in this repo |
|---|---|
| `overload.traffic_load_reduction` | `mme.overload.traffic_reduction` (int 1..99; default **50**) |
| `paging.first_wave` as integer | enum **`tai` \| `last_enb`** (default `tai`) |
| `pgw_selection.dns: true` | `pgw_selection.dns.enabled: true` |
| `pgw_selection.rule[]` + `address`/`order` | `pgw_selection.rules[]` with `apn`/`imsi_prefix`/`plmn*` + `mode`/`fallback` |
| `gummei.plmn_id` only as one object | also **list** of `{mcc,mnc}` under one GUMMEI |
| Flat `sgsap.client.tai` / `.lai` | must be `client[].map.tai` / `map.lai` (collapsed or expanded clients) |
| `global.time.*` in samples | **unused**; timers are under `mme.time.*` |

## Logger

### `logger.level`

- **What:** Global log severity for this NF process.
- **Type:** `enum` enum=['fatal', 'error', 'warn', 'info', 'debug', 'trace']
- **Default when omitted:** `info`
- **Reload:** `sighup`
- **Notes / quirks:** Parsed by ogs app logger; SIGHUP via ogs_app_config_reload. Evidence: lib/app + mme_context_reload_runtime.
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

### `logger.domain`

- **What:** Per-subsystem log levels (mme, s1ap, gtp, s6a, nas, …).
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Keys are domain names; values are level enums.
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

### `logger.file.path`

- **What:** Log file path when file logging is enabled.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `/var/log/open5gs/mme.log`
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

### `logger.file`

- **What:** Legacy scalar file path (prefer logger.file.path).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Legacy shape still accepted by common logger parser.
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

### `logger.file.timestamp`

- **What:** Include timestamps in file logger output.
- **Type:** `boolean`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

### `logger.default.timestamp`

- **What:** Default timestamp flag for logger.
- **Type:** `boolean`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `mme_context_reload_runtime / ogs_app_reload_parameter_scalars`

## Global

Parsed by `ogs_app_parse_global_conf` (`lib/app/ogs-config.c`). Full row list is in the JSON catalog (`group: global`). Pool/`max`/`parameter` (except two flags below) need **restart**.

### Defaults when omitted (compiled)

| Path | Default |
|---|---|
| `global.max.ue` | **1024** |
| `global.max.peer` (alias `enb`) | **64** |
| `global.max.tai` | **4096** |
| `global.max.eps_tai0_partial_list` | **20000** |
| `global.max.gtp_peer` / sess / bearer / … | **0** → derived |
| `global.parameter.*` bools | **false** |
| `global.sockopt.no_delay` | **true** |
| `global.parameter.fake_csfb` / `ignore_sgs` / `use_openair` / `openair_short_enfs` / `openair_omit_hashmme` | **false**; **SIGHUP** |
| `global.parameter.fake_csfb_lai` | **true** (with fake_csfb); **SIGHUP** |

### `global.time` — sample-only / unused

Samples may show `global.time.message.duration`. **Not accepted** under `global:`. Put timers under `mme.time.*` (including `mme.time.message.duration`).

### Operator-visible flags

### `global.max.ue`

- **What:** Maximum UE contexts (pool sizing).
- **Type:** `integer`
- **Default when omitted:** `1024`
- **Reload:** `restart`
- **Notes / quirks:** Pool sizes are process-lifetime; restart required.
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.max.peer`

- **What:** Maximum peer (eNB) contexts.
- **Type:** `integer`
- **Default when omitted:** `64`
- **Reload:** `restart`
- **Aliases:** `enb`
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.max.tai`

- **What:** Max TAC entries per GTP-C client filter lists (`sgwc`/`smf` `tac:`).
- **Type:** `integer`
- **Default when omitted:** `4096`
- **Reload:** `restart`
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.max.eps_tai0_partial_list`

- **What:** Bound for TAI0 partial list packing in `mme.tai`.
- **Type:** `integer`
- **Default when omitted:** `20000`
- **Reload:** `restart`
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.parameter.use_upg_vpp`

- **What:** Prefer UPG/VPP datapath integration flag.
- **Type:** `boolean`
- **Default when omitted:** `false`
- **Reload:** `restart`
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.parameter.prefer_ipv4`

- **What:** Prefer IPv4 when dual-stack addresses exist.
- **Type:** `boolean`
- **Default when omitted:** `false`
- **Reload:** `restart`
- **Evidence:** `lib/app/ogs-config.c:ogs_app_parse_global_conf`

### `global.parameter.fake_csfb` / `fake_csfb_lai` / `ignore_sgs` / `use_openair` / `openair_short_enfs` / `openair_omit_hashmme`

- **What:** Hot-reloadable `global.parameter` scalars.
- **Defaults:** `fake_csfb`/`ignore_sgs`/`use_openair`/`openair_short_enfs`/`openair_omit_hashmme` = `false`; `fake_csfb_lai` = `true`
- **Reload:** `sighup` via `ogs_app_reload_parameter_scalars`
- **Evidence:** `mme-context.c:mme_context_reload_runtime` → `ogs_app_reload_parameter_scalars`

## Identity

### `mme.mme_name`

- **What:** MME name used in S1AP (PrintableString).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `open5gs-mme0`
- **Notes / quirks:** Copied with ogs_strdup; not applied on SIGHUP. Restart required.
- **Evidence:** `src/mme/mme-context.c`

### `mme.relative_capacity`

- **What:** Relative MME capacity advertised to eNB.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 0xff`
- **Reload:** `restart`
- **Notes / quirks:** mme_context_prepare sets 0xff. Not in mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/mme-context.c`

### `mme.network_name.full`

- **What:** Full network name for NAS EMM information.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.network_name.short`

- **What:** Short network name for NAS EMM information.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

## S1AP

### `mme.s1ap.server`

- **What:** S1AP SCTP server bind list.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap.server[].address`

- **What:** S1-MME listen address.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `127.0.0.2`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap.server[].port`

- **What:** S1AP SCTP port.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 36412`
- **Reload:** `restart`
- **Notes / quirks:** OGS_S1AP_SCTP_PORT=36412 in lib/sctp/ogs-sctp.h; mme_context_prepare.
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap.server[].option.sctp_nodelay`

- **What:** SCTP nodelay option for S1AP server.
- **Type:** `boolean`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap.server[].option.sctp.sinit_num_ostreams`

- **What:** SCTP init outbound streams for S1AP.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

## GTP-C

### `mme.gtpc.server`

- **What:** GTP-C server bind list.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.server[].address`

- **What:** GTP-C listen address.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.server[].port`

- **What:** GTP-C port (typically 2123).
- **Type:** `integer`
- **Default when omitted:** `2123`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.recovery`

- **What:** GTP recovery counter; ignored on SIGHUP.
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `restart`
- **Notes / quirks:** mme_context_reload_runtime warns restart required.
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.recovery_counter_file`

- **What:** Path for persisted GTP recovery counter.
- **Type:** `string`
- **Default when omitted:** `compiled-default: MME_RECOVERY_COUNTER_FILE`
- **Reload:** `restart`
- **Notes / quirks:** SIGHUP ignored with audit warning.
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.echo_interval`

- **What:** S11 GTP Echo interval seconds; 0 means use 60s at schedule time.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 0 (scheduled as 60s)`
- **Reload:** `sighup`
- **Notes / quirks:** Stored 0 in prepare; mme_sgw_echo_schedule uses 60 when 0. SIGHUP reschedules.
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc`

- **What:** SGW-C / S11 peer list (add/sync on SIGHUP).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].address`

- **What:** SGWC peer address or hostname.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].port`

- **What:** SGWC peer GTP-C port.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].family`

- **What:** Address family hint for peer resolution.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].plmn_id`

- **What:** PLMN match; meaning depends on inbound_roam.gtpc_plmn_id_is_imsi_plmn.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Parsed via mme_gtpc_client_parse_plmn_id_key.
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].plmn_id.mcc`

- **What:** MCC for sgwc plmn_id.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `999`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].plmn_id.mnc`

- **What:** MNC for sgwc plmn_id.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `70`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].serving_plmn_id`

- **What:** Serving PLMN match for SGWC selection.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].serving_plmn_id.mcc`

- **What:** Serving PLMN MCC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].serving_plmn_id.mnc`

- **What:** Serving PLMN MNC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].imsi_plmn_id`

- **What:** IMSI-home PLMN match for SGWC selection.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].tac`

- **What:** TAC match list for SGWC selection.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].e_cell_id`

- **What:** E-UTRAN Cell Identity match list.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].order`

- **What:** Selection order weight for this SGWC entry.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgwc[].imsi_prefix`

- **What:** IMSI prefix match for SGWC peer.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf`

- **What:** SMF/PGW-C peer list for S5/S8 selection (SIGHUP sync).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].address`

- **What:** SMF/PGW address or hostname.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].port`

- **What:** SMF GTP-C port.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].apn`

- **What:** APN/DNN match for this SMF entry (scalar or list in parser).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `internet`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].tac`

- **What:** TAC match for SMF selection.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].plmn_id`

- **What:** PLMN match (IMSI vs serving per inbound_roam flag).
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].serving_plmn_id`

- **What:** Serving PLMN match for SMF.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].imsi_plmn_id`

- **What:** IMSI PLMN match for SMF.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].order`

- **What:** Selection order for SMF entry.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].imsi_prefix`

- **What:** IMSI prefix match for SMF.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.smf[].force`

- **What:** Force this YAML SMF entry in selection.
- **Type:** `boolean`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn`

- **What:** Gn/Gp SGSN peer list (not hot-reloaded).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].address`

- **What:** SGSN address (scalar or list).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].port`

- **What:** SGSN GTP-C port.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].family`

- **What:** Address family for SGSN resolution.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].routes`

- **What:** RAI/CI route list for SGSN.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].routes[].rai`

- **What:** Route Area Identity under SGSN route.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].routes[].ci`

- **What:** Cell Identity for SGSN route.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].default_route`

- **What:** Mark SGSN as default route.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gtpc.client.sgsn[].name`

- **What:** Not a parsed SGSN key; sample YAML only (warns unknown).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** Parser accepts address/port/family/routes/default_route; name is unknown key.
- **Evidence:** `src/mme/mme-context.c`

## Metrics

### `mme.metrics.server`

- **What:** Prometheus/metrics HTTP bind list.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.metrics.server[].address`

- **What:** Metrics listen address.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.metrics.server[].port`

- **What:** Metrics listen port.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `9090`
- **Evidence:** `src/mme/mme-context.c`

## Diameter

### `mme.freeDiameter`

- **What:** Path to freeDiameter config file (scalar form).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `/etc/open5gs/freeDiameter/mme.conf`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.identity`

- **What:** Diameter identity when embedding freeDiameter mapping.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.realm`

- **What:** Diameter realm for embedded freeDiameter mapping.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.listen_on`

- **What:** Local Diameter listen address.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.connect`

- **What:** Diameter peer connect list (identity/address).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.connect[].identity`

- **What:** Peer Diameter identity.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `hss.localdomain`
- **Evidence:** `src/mme/mme-context.c`

### `mme.freeDiameter.connect[].address`

- **What:** Peer Diameter address/hostname.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

## GUMMEI

### `mme.gummei`

- **What:** Served GUMMEI list (required).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].plmn_id`

- **What:** One PLMN mapping or a SEQUENCE of PLMNs per GUMMEI.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Notes / quirks:** Parser accepts mapping or sequence (mme-context.c gummei.plmn_id). Under-documented in sparse NMS catalog.
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].plmn_id.mcc`

- **What:** MCC when plmn_id is a single mapping.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `999`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].plmn_id.mnc`

- **What:** MNC when plmn_id is a single mapping.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `70`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].plmn_id[].mcc`

- **What:** MCC for each PLMN when plmn_id is a list.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].plmn_id[].mnc`

- **What:** MNC for each PLMN when plmn_id is a list.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].mme_gid`

- **What:** MME Group ID (scalar or list).
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `2`
- **Evidence:** `src/mme/mme-context.c`

### `mme.gummei[].mme_code`

- **What:** MME Code (scalar or list).
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `1`
- **Evidence:** `src/mme/mme-context.c`

## TAI

### `mme.tai`

- **What:** Served TAI list; empty/unparsable keeps previous on reload.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** mme_reload_lists_key_add_only("tai").
- **Evidence:** `src/mme/mme-context.c`

### `mme.tai[].plmn_id`

- **What:** PLMN for served TAI entry.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.tai[].plmn_id.mcc`

- **What:** Served TAI MCC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.tai[].plmn_id.mnc`

- **What:** Served TAI MNC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.tai[].tac`

- **What:** TAC values or ranges (e.g. 10-20).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `[1, 2, '10-20']`
- **Evidence:** `src/mme/mme-context.c`

## SGsAP

### `mme.sgsap`

- **What:** SGsAP / VLR client configuration (CSFB).
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Maps add/update on SIGHUP; VLR bind changes need restart.
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.max_csmap`

- **What:** Maximum TAI-LAI map entries.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 8000`
- **Reload:** `sighup`
- **Notes / quirks:** MAX_NUM_OF_CSMAP 8000 in mme-context.c
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client`

- **What:** VLR client list; new addresses added on SIGHUP.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].address`

- **What:** VLR address/hostname (rebind of existing needs restart).
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `msc.example.net`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].local_address`

- **What:** Local SCTP bind for SGsAP client.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Notes / quirks:** Ignored on SIGHUP with audit warning.
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].port`

- **What:** SGsAP SCTP port.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].option`

- **What:** SCTP options for SGsAP client.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map`

- **What:** TAI-LAI / IMSI map entries under client (required shape).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Flat client.tai/lai rejected with hard error.
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].tai`

- **What:** TAI key for CS map entry.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].tai.plmn_id`

- **What:** TAI PLMN.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].tai.tac`

- **What:** TAI TAC (start).
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].tai.tac_end`

- **What:** Optional TAC range end.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].lai`

- **What:** LAI mapped for CSFB.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].lai.plmn_id`

- **What:** LAI PLMN.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].lai.lac`

- **What:** Location Area Code.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].map[].imsi_prefix`

- **What:** Optional IMSI prefix for map entry.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].tai`

- **What:** Rejected flat key; must be map.tai.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** ogs_error: tai/lai configuration changed to map.tai/map.lai
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `mme.sgsap.client[].lai`

- **What:** Rejected flat key; must be map.lai.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `global.parameter.fake_csfb`

- **What:** If UE requested Combined attach/TAU and CS is not refused, advertise Combined EPS/IMSI result (or Combined TAU).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** Does not upgrade EPS-only requests. Does **not** override HSS `Network-Access-Mode=ONLY_PACKET` (subscriber stays EPS-only / TA-updated with EMM cause 18). Pair with `fake_csfb_lai` for synthetic LAI/P-TMSI. Not a real CS registration.
- **Evidence:** `src/mme/emm-build.c`

### `global.parameter.fake_csfb_lai`

- **What:** When `fake_csfb` is true and no real VLR P-TMSI exists, synthesize LAI (csmap or serving TAC as LAC) and P-TMSI (from GUTI/M-TMSI) on Combined Accept/TAU. Alias: `fake_csfb_ptmsi`.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Notes / quirks:** Set `false` for Combined result without LAI/P-TMSI IEs (illegal NAS per TS 24.301; many UEs reply EMM #101).
- **Evidence:** `src/mme/emm-build.c`

### `global.parameter.ignore_sgs`

- **What:** Skip SGsAP Location Update (e.g. roamers / no VLR).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** SIGHUP via ogs_app_reload_parameter_scalars; mme_context_reload_runtime.
- **Evidence:** `src/mme/mme-context.c:mme_sgsap_config_parse / sgsap_config_parse_body`

### `global.parameter.use_openair`

- **What:** Umbrella for both OpenAir quirks below (short ENFS + omit HashMME). Kept for backward compatibility.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** Prefer the split flags. Applies to all UEs when true.
- **Evidence:** `lib/app/ogs-config.c:ogs_app_reload_parameter_scalars`, `src/mme/emm-build.c`

### `global.parameter.openair_short_enfs`

- **What:** Emit 1-byte EPS Network Feature Support on Attach/TAU Accept (OpenAir compatibility). Does not omit HashMME.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** Also enabled when `use_openair` is true. Safe compatibility quirk vs commercial UEs that expect 2-byte ENFS.
- **Evidence:** `src/mme/emm-build.c`

### `global.parameter.openair_omit_hashmme`

- **What:** Omit HashMME IE from Security Mode Command (OpenAir UEs that reject HashMME).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** Also enabled when `use_openair` is true. Security tradeoff: weakens bidding-down protection on unprotected Attach/TAU (TS 33.401). Prefer leaving false and using `openair_short_enfs` alone when possible.
- **Evidence:** `src/mme/emm-build.c`

## Overload

### `mme.overload`

- **What:** S1AP overload control and ingress admission.
- **Type:** `object`
- **Default when omitted:** `compiled-default: enabled`
- **Reload:** `sighup`
- **Notes / quirks:** mme_overload_config_set; SIGHUP in mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.enabled`

- **What:** Enable overload control (default on).
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Notes / quirks:** mme_context_prepare / s1ap-overload.c
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.signal_enb`

- **What:** Send S1AP OVERLOAD START/STOP to eNB.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.enb_initial_ue_rate`

- **What:** Max new Initial UE messages/s per eNB (0=off).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.enb_initial_ue_burst`

- **What:** Token bucket burst (0=2x rate).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.congest_lease_sec`

- **What:** Congestion lease seconds.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 3`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.lag_high_ms`

- **What:** Event-lag high watermark (ms).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 1500`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.lag_critical_ms`

- **What:** Event-lag critical watermark (ms).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 4000`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.global_sustain_sec`

- **What:** Seconds lag must sustain before global overload.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 3`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.traffic_reduction`

- **What:** Percent traffic reduction sent to eNB in OVERLOAD START.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 50`
- **Reload:** `sighup`
- **Notes / quirks:** Real key is traffic_reduction (s1ap-overload.c). NOT traffic_load_reduction.
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.traffic_load_reduction`

- **What:** Wrong name; parser does not accept this key.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** Misconfig trap: use mme.overload.traffic_reduction.
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.resend_interval_sec`

- **What:** Resend OVERLOAD START interval.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 10`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

### `mme.overload.recovery_sec`

- **What:** Recovery dwell before OVERLOAD STOP.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 5`
- **Reload:** `sighup`
- **Evidence:** `src/mme/s1ap-overload.c:mme_overload_config_set`

## Paging

### `mme.paging`

- **What:** Paging policy object.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c (paging) / mme-reload-lists.c`

### `mme.paging.first_wave`

- **What:** First paging wave strategy.
- **Type:** `enum` enum=['tai', 'last_enb']
- **Default when omitted:** `tai`
- **Reload:** `sighup`
- **Notes / quirks:** String enum tai|last_enb (not integer). mme-context.c + mme-reload-lists.c.
- **Evidence:** `src/mme/mme-context.c (paging) / mme-reload-lists.c`

## PGW selection

### `mme.pgw_selection`

- **What:** PGW selection policy (mode/dns/rules).
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Fully reloaded on SIGHUP including rules list replace.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.mode`

- **What:** Selection mode: standard vs force YAML/static.
- **Type:** `enum` enum=['standard', 'standard-with-dns', 'force', 'force_yaml', 'static-only', 'static_only']
- **Default when omitted:** `standard`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.force_yaml`

- **What:** Force YAML SMF list (alias keys force/force_yaml).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.pgw_selection.force`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.force`

- **What:** Alias of force_yaml.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.pgw_selection.force_yaml`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.dns`

- **What:** Nested DNS APN resolution object (not a bare bool).
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** Must use dns.enabled; bare dns: true is wrong shape.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.dns.enabled`

- **What:** Enable APN DNS for PGW selection.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules`

- **What:** Ordered PGW selection rules (key name rules, not rule).
- **Type:** `list`
- **Default when omitted:** `[]`
- **Reload:** `sighup`
- **Notes / quirks:** mme_pgw_sel_rules_parse; replaces whole list on reload.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].apn`

- **What:** APN/DNN match (scalar or list); alias dnn.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.pgw_selection.rules[].dnn`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].dnn`

- **What:** Alias of rules[].apn.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.pgw_selection.rules[].apn`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].imsi_prefix`

- **What:** IMSI prefix match for rule.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].plmn_id`

- **What:** PLMN match; serving vs IMSI depends on inbound_roam.gtpc_plmn_id_is_imsi_plmn.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].serving_plmn_id`

- **What:** Serving PLMN match for rule.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].imsi_plmn_id`

- **What:** IMSI PLMN match for rule.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].mode`

- **What:** Rule mode; only dns is accepted.
- **Type:** `enum` enum=['dns']
- **Default when omitted:** `dns`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].fallback`

- **What:** Fallback when DNS rule misses.
- **Type:** `enum` enum=['none', 'hss', 'yaml', 'static']
- **Default when omitted:** `none`
- **Reload:** `sighup`
- **Notes / quirks:** yaml and static are aliases in parser.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rule`

- **What:** Wrong key name; parser expects rules[].
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** Trap: use pgw_selection.rules not rule.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].address`

- **What:** Not a rules field; peers live under gtpc.client.smf.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.pgw_selection.rules[].order`

- **What:** Not a rules field (order is for gtpc client peers).
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Evidence:** `src/mme/mme-context.c:mme_pgw_sel_rules_parse`

### `mme.mip_home_agent_host_dns`

- **What:** Resolve HSS MIP Home-Agent-Host via DNS.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `restart`
- **Notes / quirks:** Not in SIGHUP path; restart.
- **Evidence:** `src/mme/mme-context.c`

### `mme.omit_indication_on_gtp_csr`

- **What:** Omit Indication IE on GTP Create Session Request.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `restart`
- **Aliases:** `mme.omit_gtp_indication`
- **Evidence:** `src/mme/mme-context.c`

### `mme.omit_gtp_indication`

- **What:** Alias of omit_indication_on_gtp_csr.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `restart`
- **Aliases:** `mme.omit_indication_on_gtp_csr`
- **Evidence:** `src/mme/mme-context.c`

## Attach/EPLMN

### `mme.attach_accept`

- **What:** Nested Attach/TAU Accept NAS options object.
- **Type:** `object`
- **Default when omitted:** `compiled-default: mme_attach_accept_set_defaults`
- **Reload:** `unknown`
- **Notes / quirks:** SIGHUP: tai_list, equivalent_plmn (bool), equivalent_plmn_serving_only, equivalent_plmn_access_control_tac, ims_voice_over_ps. Nested `equivalent_plmn` must stay a boolean — the PLMN **list** is flat `mme.equivalent_plmn[]` (also SIGHUP). t3402/esm/legacy need restart. `/admin/config` exposes the list as `runtime.eplmn` and `runtime.equivalent_plmn`.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.tai_list`

- **What:** TAI list in Attach/TAU Accept: serving_only or all.
- **Type:** `enum` enum=['serving_only', 'all']
- **Default when omitted:** `serving_only`
- **Reload:** `sighup`
- **Notes / quirks:** reload_attach_accept_scalars; flat alias tai_list_in_accept.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.equivalent_plmn`

- **What:** Include Equivalent PLMN list in Accept.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `restart`
- **Notes / quirks:** Parsed at startup; NOT in reload_attach_accept_scalars.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.equivalent_plmn_serving_only`

- **What:** When true, send only the configured EPLMN that matches the UE IMSI home PLMN (not visited TAI PLMN); when no IMSI match, send the full list.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Notes / quirks:** SIGHUP subset + flat alias. Name is historical; filter key is IMSI PLMN.
- **Evidence:** `src/mme/eplmn-config.c:mme_eplmn_build_nas_list_for_imsi / emm-build.c`

### `mme.attach_accept.equivalent_plmn_access_control_tac`

- **What:** When true, include EPLMN only if the UE matches `access_control` (IMSI prefix/PLMN) and the current TAC is allowed on that entry (no tac list means all TACs allowed).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.equivalent_plmn_access_control_tac`
- **Notes / quirks:** Reuses existing access_control TAC hashes; eNB-ID lists are ignored for this gate.
- **Evidence:** `src/mme/mme-access-control-match.c / emm-build.c`

### `mme.attach_accept.ims_voice_over_ps`

- **What:** IMS voice over PS indicator in S1 mode.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.ims_voice_over_ps_in_s1_mode`
- **Notes / quirks:** Nested alias ims_voice_over_ps_in_s1_mode accepted in parse.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.ims_voice_over_ps_in_s1_mode`

- **What:** Alias of attach_accept.ims_voice_over_ps.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.ims_voice_over_ps`
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.t3402`

- **What:** Include T3402 IE in Attach/TAU Accept when timer configured.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `restart`
- **Notes / quirks:** Not in SIGHUP subset.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.esm_cause_pdn_type_mismatch`

- **What:** Include ESM cause on PDN type mismatch.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `restart`
- **Notes / quirks:** Not in SIGHUP subset.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.attach_accept.legacy_gprs_qos`

- **What:** Emit legacy GPRS QoS IE behaviour.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `restart`
- **Notes / quirks:** Not in SIGHUP subset.
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.tai_list_in_accept`

- **What:** Flat alias of attach_accept.tai_list.
- **Type:** `enum` enum=['serving_only', 'all']
- **Default when omitted:** `serving_only`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.tai_list`
- **Evidence:** `src/mme/mme-context.c:mme_attach_accept_parse_yaml / mme-reload-lists.c:reload_attach_accept_scalars`

### `mme.equivalent_plmn_serving_only`

- **What:** Flat alias of attach_accept.equivalent_plmn_serving_only.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.equivalent_plmn_serving_only`
- **Evidence:** `src/mme/mme-context.c`

### `mme.equivalent_plmn_access_control_tac`

- **What:** Flat alias of attach_accept.equivalent_plmn_access_control_tac.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.equivalent_plmn_access_control_tac`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ims_voice_over_ps_in_s1_mode`

- **What:** Flat alias of attach_accept.ims_voice_over_ps.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Aliases:** `mme.attach_accept.ims_voice_over_ps`
- **Evidence:** `src/mme/mme-context.c`

### `mme.equivalent_plmn`

- **What:** Configured Equivalent PLMN list (MCC/MNC entries).
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** eplmn-config / mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/mme-context.c`

### `mme.equivalent_plmn[].mcc`

- **What:** EPLMN MCC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `999`
- **Evidence:** `src/mme/mme-context.c`

### `mme.equivalent_plmn[].mnc`

- **What:** EPLMN MNC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `71`
- **Evidence:** `src/mme/mme-context.c`

## Roaming/APN

### `mme.inbound_roam`

- **What:** Inbound roaming / GTP APN policy object.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** mme_inbound_roam_config_parse; SIGHUP.
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.gtp_apn_format`

- **What:** How APN is encoded toward GTP.
- **Type:** `enum` enum=['fqdn', 'as_received', 'received']
- **Default when omitted:** `fqdn`
- **Reload:** `sighup`
- **Notes / quirks:** aliases as_received/received in mme-inbound-roam-apn.c
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.gtp_apn_lowercase`

- **What:** Force lowercase GTP APN.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.apn_lowercase`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.apn_lowercase`

- **What:** Alias of gtp_apn_lowercase.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.strip_pap_from_gtp_pco`

- **What:** Strip PAP from GTP PCO for roamers.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.strip_pap_from_pco`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.strip_pap_from_pco`

- **What:** Alias of strip_pap_from_gtp_pco.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.gtpc_plmn_id_is_imsi_plmn`

- **What:** Treat bare plmn_id on GTP-C clients as IMSI PLMN (default true).
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.plmn_id_is_imsi_plmn`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.plmn_id_is_imsi_plmn`

- **What:** Alias of gtpc_plmn_id_is_imsi_plmn.
- **Type:** `boolean`
- **Default when omitted:** `True`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.force_ipv4_pdn_on_home_pgw`

- **What:** Force IPv4 PDN toward home PGW.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.force_ipv4_pdn`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.force_ipv4_pdn`

- **What:** Alias of force_ipv4_pdn_on_home_pgw.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.zero_bearer_mbr_for_non_gbr`

- **What:** Zero bearer MBR for non-GBR on roam path.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.non_gbr_zero_bearer_mbr`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.non_gbr_zero_bearer_mbr`

- **What:** Alias of zero_bearer_mbr_for_non_gbr.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.apn_reject_cause`

- **What:** NAS/ESM reject cause for denied APN.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: missing_or_unknown_apn`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.omit_indication_on_gtp_csr`

- **What:** Roam-scoped omit Indication (also top-level aliases exist).
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.omit_gtp_indication`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.allow_apn`

- **What:** Allowed APN list for inbound roam.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.allowed_apn`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.allowed_apn`

- **What:** Alias of allow_apn.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.deny_apn`

- **What:** Denied APN list for inbound roam.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.inbound_roam.denied_apn`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.denied_apn`

- **What:** Alias of deny_apn.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.inbound_roam.apn_rule`

- **What:** Structured APN allow/deny rules with PLMN/IMSI match.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-inbound-roam-apn.c`

### `mme.apn_correction`

- **What:** APN correction / PDN-type policy rules.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** mme_apn_policy_parse; SIGHUP.
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].name`

- **What:** Optional rule name.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].imsi_prefix`

- **What:** IMSI prefix for APN correction rule.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].requested_apn`

- **What:** Requested APN match.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.apn_correction[].apn`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].apn`

- **What:** Alias of requested_apn.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].correct_to`

- **What:** Corrected APN to use.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].pdn_type`

- **What:** Forced/expected PDN type.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].on_apn_mismatch`

- **What:** Action when APN mismatches.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].on_pdn_type_mismatch`

- **What:** Action when PDN type mismatches.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

### `mme.apn_correction[].reject_cause`

- **What:** Reject cause for correction policy.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-apn-policy.c:mme_apn_policy_parse`

## AMBR

### `mme.ambr_limit`

- **What:** UE AMBR clamp policy.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.enabled`

- **What:** Enable AMBR limiting.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.force`

- **What:** Force AMBR even when subscription higher.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.downlink`

- **What:** Downlink AMBR cap in Mbps.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 200`
- **Reload:** `sighup`
- **Aliases:** `mme.ambr_limit.downlink_mbps`
- **Notes / quirks:** Stored as bps (mbps*1e6); prepare default 200 Mbps.
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.downlink_mbps`

- **What:** Alias of downlink (Mbps).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 200`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.uplink`

- **What:** Uplink AMBR cap in Mbps.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 200`
- **Reload:** `sighup`
- **Aliases:** `mme.ambr_limit.uplink_mbps`
- **Evidence:** `src/mme/mme-context.c`

### `mme.ambr_limit.uplink_mbps`

- **What:** Alias of uplink (Mbps).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 200`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

## Access/HSS/Security

### `mme.access_control`

- **What:** IMSI/PLMN/TAC/eNB access control entries.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** SIGHUP list reload.
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].default_reject_cause`

- **What:** Default reject cause for access_control.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].imsi_prefix`

- **What:** IMSI prefix for ACL entry.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].reject_cause`

- **What:** Reject cause for matched ACL entry.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].tac`

- **What:** TAC filter for ACL entry.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].enb_id`

- **What:** eNB ID filter for ACL entry.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.access_control[].plmn_id`

- **What:** PLMN allow entry.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.imsi_acl`

- **What:** IMSI prefix allow-list.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.require_hss_map`

- **What:** Require hss_map match for attach.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Notes / quirks:** Auto-true if hss_map present and not explicit false.
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map`

- **What:** IMSI-PLMN to HSS realm/host map.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].plmn_id`

- **What:** PLMN for HSS map entry.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].plmn_id.mcc`

- **What:** HSS map MCC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].plmn_id.mnc`

- **What:** HSS map MNC.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].realm`

- **What:** Diameter realm for HSS.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].host`

- **What:** Diameter host for HSS.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.hss_map[].order`

- **What:** Selection order among HSS map entries.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.security.integrity_order`

- **What:** NAS integrity algorithm preference order.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `['EIA2', 'EIA1', 'EIA0']`
- **Notes / quirks:** Required at validation; restart.
- **Evidence:** `src/mme/mme-context.c`

### `mme.security.ciphering_order`

- **What:** NAS ciphering algorithm preference order.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Example (fictional):** `['EEA0', 'EEA1', 'EEA2']`
- **Evidence:** `src/mme/mme-context.c`

### `mme.trace_imsi`

- **What:** IMSI prefix list enabling focused tracing.
- **Type:** `list`
- **Default when omitted:** `[]`
- **Reload:** `sighup`
- **Example (fictional):** `['999700000000001']`
- **Notes / quirks:** Empty sequence clears filter. SIGHUP list reload.
- **Evidence:** `src/mme/mme-context.c`

## Time

### `global.time`

- **What:** Sample/docs-only global.time tree; MME uses mme.time.* instead.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** Present in some sample YAMLs; MME parser does not apply global.time. Use mme.time.*.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `global.time.message.duration`

- **What:** Sample-only message duration under global.time.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `unknown`
- **Sample-only / trap:** do not treat as a supported production key.
- **Notes / quirks:** Not read by MME context parser; timers live under mme.time.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3402.value`

- **What:** T3402 seconds (NAS).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 720`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3396.value`

- **What:** T3396 seconds (ESM).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 720`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3412.value`

- **What:** T3412 periodic TAU seconds.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 600`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3423.value`

- **What:** T3423 seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.idle.mobile_reachable_margin`

- **What:** Mobile reachable = T3412 + margin (seconds).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 240`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.idle.implicit_detach_margin`

- **What:** Implicit detach margin seconds.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 240`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3346.value`

- **What:** T3346 seconds (0=disabled).
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 0`
- **Reload:** `sighup`
- **Notes / quirks:** mme.time.* reloaded in mme_context_reload_runtime; applies to new timer starts.
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3346.include_any_reject`

- **What:** Include T3346 on any reject.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3413.value`

- **What:** T3413 paging timer value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3413.max_count`

- **What:** T3413 max retransmissions.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3422.value`

- **What:** T3422 value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3422.max_count`

- **What:** T3422 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3450.value`

- **What:** T3450 value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3450.max_count`

- **What:** T3450 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.bearer_setup.value`

- **What:** Bearer setup / T3450 shared value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.time.sae_bearer_setup.value`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.bearer_setup.max_count`

- **What:** Bearer setup max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.time.sae_bearer_setup.max_count`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.sae_bearer_setup.value`

- **What:** Alias of bearer_setup.value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.sae_bearer_setup.max_count`

- **What:** Alias of bearer_setup.max_count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3460.value`

- **What:** T3460 value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3460.max_count`

- **What:** T3460 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3470.value`

- **What:** T3470 value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3470.max_count`

- **What:** T3470 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3489.value`

- **What:** T3489 value seconds.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3489.max_count`

- **What:** T3489 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3495.value`

- **What:** T3495 / NAS deactivate bearer value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.time.nas_deactivate_bearer.value`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.t3495.max_count`

- **What:** T3495 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.nas_deactivate_bearer.value`

- **What:** Alias of t3495.value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.nas_deactivate_bearer.max_count`

- **What:** Alias of t3495.max_count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.sgs_ts6_1.value`

- **What:** SGs TS6-1 timer value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.time.ts6_1.value`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.sgs_ts6_1.max_count`

- **What:** SGs TS6-1 max count.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.ts6_1.value`

- **What:** Alias of sgs_ts6_1.value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.s6a.value`

- **What:** S6a transaction timeout value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Aliases:** `mme.time.s6a_timeout.value`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.s6a_timeout.value`

- **What:** Alias of s6a.value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

### `mme.time.s11_holding.value`

- **What:** S11 holding timer value.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c:mme_time_config_parse / mme_context_reload_runtime`

## Emergency

### `mme.emergency`

- **What:** Emergency DNN / number configuration.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.emergency.dnn`

- **What:** Emergency DNN/APN.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `sos`
- **Evidence:** `src/mme/mme-context.c`

### `mme.emergency.number`

- **What:** Emergency number list with categories.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Evidence:** `src/mme/mme-context.c`

### `mme.emergency.number[].digits`

- **What:** Emergency number digits.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `112`
- **Evidence:** `src/mme/mme-context.c`

### `mme.emergency.number[].categories`

- **What:** Categories: police|ambulance|fire|marine|mountain or bitmask.
- **Type:** `list`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Example (fictional):** `['police', 'ambulance', 'fire']`
- **Evidence:** `src/mme/mme-context.c`

## LI

### `mme.li`

- **What:** Lawful Intercept MDF client config.
- **Type:** `object`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Notes / quirks:** mme_li_parse_config; restart.
- **Evidence:** `src/mme/mme-li.c:mme_li_parse_config`

### `mme.li.enabled`

- **What:** Enable MME LI reporting.
- **Type:** `boolean`
- **Default when omitted:** `False`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-li.c:mme_li_parse_config`

### `mme.li.mdf.addr`

- **What:** MDF address/hostname.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Aliases:** `mme.li.mdf.address`
- **Evidence:** `src/mme/mme-li.c:mme_li_parse_config`

### `mme.li.mdf.address`

- **What:** Alias of mdf.addr.
- **Type:** `string`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-li.c:mme_li_parse_config`

### `mme.li.mdf.port`

- **What:** MDF HTTP port.
- **Type:** `integer`
- **Default when omitted:** `compiled-default: 9051`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-li.c:mme_li_parse_config`

## Performance

### `mme.workers`

- **What:** UE-shard bounce worker threads (0=off).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `restart`
- **Notes / quirks:** Bounds 0..OGS_MAX_WORKERS-1; restart.
- **Evidence:** `src/mme/mme-context.c`

### `mme.pkbuf_thread_pool`

- **What:** Packet buffer thread pool size.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_rx_workers`

- **What:** S1AP RX decode offload threads (0=off).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_tx_workers`

- **What:** S1AP TX encode offload threads (0=off).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_io_thread`

- **What:** Dedicated S1AP SCTP send thread (0/1).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `restart`
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_io_write_queue_max`

- **What:** Per-eNB outbound PDU queue cap (0=default 10240).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `sighup`
- **Notes / quirks:** Reloaded in mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_io_stall_teardown_sec`

- **What:** Seconds with full write-queue before CONNREFUSED teardown.
- **Type:** `integer`
- **Default when omitted:** `None`
- **Reload:** `sighup`
- **Notes / quirks:** SIGHUP via mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/mme-context.c`

### `mme.s1ap_io_congest_depth`

- **What:** Queue depth reported as TX-congested (0=max/4).
- **Type:** `integer`
- **Default when omitted:** `0`
- **Reload:** `sighup`
- **Notes / quirks:** SIGHUP via mme_reload_lists_key_add_only.
- **Evidence:** `src/mme/mme-context.c`

## NMS mapping diffs

- Existing `configs/nms/nms-config-catalog.json` is sparse (~53 MME fields) versus the full parser surface documented here.
- `docs/nms-sighup-reload.md` MME section omits `overload.*`, `paging.*`, `pgw_selection.*`, and `s1ap_io_write_queue_max` / `s1ap_io_stall_teardown_sec` / `s1ap_io_congest_depth` even though `mme_reload_lists_key_add_only` reloads them.
- Wrong names / shapes seen in older NMS drafts: `traffic_load_reduction` (real: `traffic_reduction`); `pgw_selection.dns` as bare bool (real: nested `dns.enabled`); `rule[]` (real: `rules[]`); rules `address`/`order` (not rule fields); `first_wave` as int (real: enum `tai|last_enb`).
- Catalog gaps for reloadable keys: `apn_correction`, inbound_roam lists/scalars, `overload.*`, partial `attach_accept` fields, `sgsap.client[].map`, flat attach aliases, `require_hss_map`, `ambr_limit`, etc.
- `gummei[].plmn_id` list-of-PLMNs shape is under-documented in the sparse catalog (parser accepts mapping or sequence).
- `global.time` in samples is unused by MME; operators must configure `mme.time.*`.
- Nested siblings differ on reload: `attach_accept.equivalent_plmn` / `t3402` / `esm_cause_pdn_type_mismatch` / `legacy_gprs_qos` are **restart**, while `tai_list`, `equivalent_plmn_serving_only`, `equivalent_plmn_access_control_tac`, and `ims_voice_over_ps` are **SIGHUP**.
- **Key absent on SIGHUP keeps the old value** — deleting a scalar/list key does not reset defaults; clear lists with an empty sequence where supported (e.g. `trace_imsi: []`).
