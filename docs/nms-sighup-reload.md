# NMS reference: SIGHUP runtime config reload

This document lists every YAML key that **open5gs-mmed**, **open5gs-smfd**, and **open5gs-sgwcd** apply on **SIGHUP** without restarting the daemon (attached UEs / sessions stay up).

Branch: `feature/sighup-list-replace` (Pretty5gs fork).

**Other NFs** (AMF, UPF, HSS, PCRF, NRF, …) have **no SIGHUP handler** — any config change requires a daemon restart.

---

## How to reload

| Daemon | systemd | manual |
|--------|---------|--------|
| MME | `sudo systemctl reload open5gs-mmed` | `sudo kill -HUP "$(pidof open5gs-mmed)"` |
| SMF | `sudo systemctl reload open5gs-smfd` | `sudo kill -HUP "$(pidof open5gs-smfd)"` |
| SGWC | `sudo systemctl reload open5gs-sgwcd` | `sudo kill -HUP "$(pidof open5gs-sgwcd)"` |

### Log signals

| Outcome | Log lines |
|---------|-----------|
| Success | `Configuration reloaded: '…'`, `MME/SMF/SGWC SIGHUP reload completed`, audit notes (`SIGHUP: …`) |
| YAML parse failure | `Configuration reload failed` — **previous config kept** |
| Partial apply | Warnings such as `peer removal skipped (sessions active)` or `DNS resolution failure` |

---

## Global rules (NMS must enforce)

| Rule | Behaviour |
|------|-----------|
| **Key absent** | Deleting a reloadable key from YAML **keeps the old value**. To clear a list, keep the key with an empty sequence, e.g. `trace_imsi: []`. |
| **Timers (MME)** | New timer values apply to **new** timer starts only; already-running timers keep their current expiry. |
| **Peer / pool removal** | Peers and session pools are removed only when **idle** (no S11/PFCP sessions, no allocated IPs). Otherwise the entry stays and the log warns. |
| **DNS failure during reload** | Peer removal is **skipped** if hostname resolution fails (transient DNS outage). |
| **Logger section absent** | If `logger:` is missing from the new YAML, logger settings are **unchanged** (not reset). |
| **Protected lists** | Empty or unparsable `mme.tai:` → previous served TAI list kept. Empty `sgwc.gn.pgw:` → previous Gn PGW list kept. Invalid `smf.radius:` → previous RADIUS config kept. |

---

## Logger (all three NFs)

Top-level section in each NF YAML (`mme.yaml`, `smf.yaml`, `sgwc.yaml`).

| YAML path | SIGHUP |
|-----------|--------|
| `logger.level` | yes |
| `logger.domain` | yes |
| `logger.file` (legacy scalar) | yes |
| `logger.file.path` | yes |
| `logger.default.timestamp` | yes |
| `logger.file.timestamp` | yes |

---

## MME (`/etc/open5gs/mme.yaml` → `mme:`)

### Timers — `mme.time.*`

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `mme.time.t3402.value` | yes | new procedures only |
| `mme.time.t3396.value` | yes | |
| `mme.time.t3412.value` | yes | |
| `mme.time.t3423.value` | yes | |
| `mme.time.idle.mobile_reachable_margin` | yes | |
| `mme.time.idle.implicit_detach_margin` | yes | |
| `mme.time.t3346.value` | yes | |
| `mme.time.t3346.include_any_reject` | yes | |
| `mme.time.bearer_setup` / `sae_bearer_setup` | yes | |
| `mme.time.s11_holding` | yes | |
| `mme.time.t3413` | yes | |
| `mme.time.t3422` | yes | |
| `mme.time.t3450` | yes | |
| `mme.time.t3460` | yes | |
| `mme.time.t3470` | yes | |
| `mme.time.t3489` | yes | |
| `mme.time.t3495` / `nas_deactivate_bearer` | yes | |
| `mme.time.sgs_ts6_1` / `ts6_1` | yes | |
| `mme.time.s6a` / `s6a_timeout` | yes | |

### GTP-C — `mme.gtpc.*`

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `mme.gtpc.echo_interval` | yes | reschedules S11 GTP echo to all SGWC peers |
| `mme.gtpc.client.sgwc[]` | yes | **peer sync**: add new; remove when no S11 context |
| `mme.gtpc.client.smf[]` | yes | **peer sync**: add new; remove from PGW selection list |
| `mme.gtpc.recovery` | **no** | restart required |
| `mme.gtpc.recovery_counter_file` | **no** | restart required |
| `mme.gtpc.server` | **no** | bind address — restart required |

Peer entry fields on add/sync: `address`, `port`, `family`, `tac`, `e_cell_id`, `apn`, `serving_plmn_id`, `plmn_id` (IMSI-PLMN rules).

### Lists — full replace when key present

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `mme.tai[]` | yes | empty/bad section rejected — previous list kept |
| `mme.access_control[]` | yes | incl. `default_reject_cause`, `imsi_prefix`, `plmn_id`, `reject_cause`, `tac`, `enb_id` |
| `mme.hss_map[]` | yes | PLMN → Diameter realm/host |
| `mme.equivalent_plmn[]` | yes | |
| `mme.imsi_acl[]` | yes | |
| `mme.trace_imsi[]` | yes | |
| `mme.emergency[]` | yes | emergency number list |

### Policy scalars

| YAML path | SIGHUP |
|-----------|--------|
| `mme.attach_accept.tai_list` (`serving_only` / `all`) | yes |
| `mme.attach_accept.equivalent_plmn_serving_only` | yes |
| `mme.attach_accept.ims_voice_over_ps` | yes |
| `mme.equivalent_plmn_serving_only` | yes |
| `mme.ims_voice_over_ps_in_s1_mode` | yes |
| `mme.tai_list_in_accept` | yes |
| `mme.require_hss_map` | yes |
| `mme.ambr_limit.enabled` | yes |
| `mme.ambr_limit.force` | yes |
| `mme.ambr_limit.downlink` / `downlink_mbps` | yes |
| `mme.ambr_limit.uplink` / `uplink_mbps` | yes |

### MME — restart required (typical)

S1/SCTP bind addresses, pool sizes, GUMMEI, NAS security algorithms, metrics listen, and **any other `mme:` key not listed above**.

---

## SMF (`/etc/open5gs/smf.yaml` → `smf:`)

### Session pools — `smf.session[]`

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `smf.session[].subnet` | yes | add/remove pool |
| `smf.session[].gateway` | yes | |
| `smf.session[].range` | yes | |
| `smf.session[].dev` | yes | |
| `smf.session[].apn` / `dnn` | yes | |
| Per-APN `radius:` blocks inside session entries | yes | table rebuilt on reload |

Removal: only when **all IPs in the pool are free**.

### PFCP — `smf.pfcp.*`

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `smf.pfcp.client.upf[]` | yes | **peer sync**: add; remove when no PFCP sessions |
| `smf.pfcp.server` | **no** | bind address — restart required |

UPF entry fields: `address`, `port`, `family`, `apn`/`dnn`, `tac`.

### Lists / blocks — full replace

| YAML path | SIGHUP |
|-----------|--------|
| `smf.trace_imsi[]` | yes |
| `smf.dns[]` | yes |

### Scalars and service blocks

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `smf.mtu` | yes | applies to new sessions |
| `smf.cdr.enabled` | yes | writer close/reopen |
| `smf.cdr.spool_dir` / `directory` | yes | |
| `smf.cdr.node_id` / `nodeid` | yes | |
| `smf.cdr.local_address` / `pgw_address` | yes | |
| `smf.cdr.max_records` | yes | |
| `smf.cdr.max_bytes` | yes | |
| `smf.cdr.max_seconds` | yes | |
| `smf.cdr.triggers` | yes | `start`, `interim`, `stop` |
| `smf.radius.enabled` | yes | farm + optional PoD listener swap |
| `smf.radius.pod_enabled` / `pod` | yes | |
| `smf.radius.use_framed_ip_for_ue` | yes | |
| `smf.radius.servers[]` | yes | `host`, `secret`, ports, `role`, `weight` |
| `smf.radius.server` / `secret` (flat form) | yes | |
| `smf.radius.auth_port` / `acct_port` / `port` | yes | |
| `smf.radius.nas_identifier` / `nas_ip` | yes | |
| `smf.radius.timeout` / `retry` | yes | |
| `smf.radius.acct_interim_interval` | yes | |
| `smf.radius.pod_bind` / `pod_address` | yes | |
| `smf.radius.pod_port` / `pod_secret` | yes | |
| `smf.radius.pod_teardown_timeout_ms` | yes | |
| `smf.radius.select` / `select_mode` | yes | `primary_failover` or `hash_imsi` |

Invalid `smf.radius` on reload → previous RADIUS config kept.

Alternative: SMF CDR/RADIUS can also be pushed via the **admin API** file watcher — see `tools/admin-api/README.md`.

### SMF — restart required (typical)

`smf.pfcp.server`, `smf.gtpc.server`, `smf.sbi.server`, metrics listen, and **any other `smf:` key not listed above**.

---

## SGWC (`/etc/open5gs/sgwc.yaml` → `sgwc:`)

### GTP-C / GTP-U scalars

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `sgwc.gtpc.echo_interval` | yes | |
| `sgwc.gtpc.server` | **no** | bind address — restart required |
| `sgwc.gtpu.force_cp_teid` / `cp_teid` | yes | |
| `sgwc.gtpu.teid_offset` | yes | |
| `sgwc.gtpu.teid_range_indication` | yes | |
| `sgwc.gtpu.teid_range` | yes | |

### PFCP / SGW-U peers

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `sgwc.pfcp.client.sgwu[]` | yes | **peer sync** |
| `sgwc.sgwu[]` (legacy top-level alias) | yes | same sync path |
| `sgwc.pfcp.send_user_id` / `send_user_id_to_sgwu` | yes | |
| `sgwc.pfcp.server` | **no** | bind address — restart required |

Removal: only when **no PFCP sessions** on that SGW-U.

### Inbound roam — `sgwc.inbound_roam.*`

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `sgwc.inbound_roam.gtpc.teid_offset` | yes | |
| `sgwc.inbound_roam.gtpc.send_recovery_on_s5_csr` / `recovery_on_s5_csr` | yes | |
| `sgwc.inbound_roam.gtpc.source_port` / `send_port` / `port` | **no** | extra S5 bind socket |
| `sgwc.inbound_roam.gtpu.*` | yes | same keys as `sgwc.gtpu.*` |
| `sgwc.inbound_roam.teid_offset` | yes | |
| `sgwc.inbound_roam.sgwu_nwi_rewrite[]` | yes | merged with top-level NWI list |

### Lists / blocks — full replace

| YAML path | SIGHUP | Notes |
|-----------|--------|-------|
| `sgwc.sgwu_nwi_rewrite[]` | yes | aliases: `nwi_rewrite`, `pfcp_nwi_rewrite` |
| `sgwc.gn.pgw[]` / `gn.smf[]` | yes | empty list rejected — previous kept |
| `sgwc.trace_imsi[]` | yes | |
| `sgwc.cdr.enabled` | yes | writer close/reopen |
| `sgwc.cdr.spool_dir` / `directory` | yes | |
| `sgwc.cdr.node_id` / `nodeid` | yes | |
| `sgwc.cdr.local_address` / `sgw_address` | yes | |
| `sgwc.cdr.interim_interval_s` / `interim_interval` | yes | |
| `sgwc.cdr.max_records` / `max_bytes` / `max_seconds` | yes | |
| `sgwc.cdr.triggers` | yes | |

### SGWC — restart required (typical)

`sgwc.gtpc.server`, `sgwc.pfcp.server`, `sgwc.metrics.server`, **`sgwc.gn.server`**, and **any other `sgwc:` key not listed above**.

---

## Quick lookup by category

| Category | MME | SMF | SGWC |
|----------|-----|-----|------|
| Timers | `mme.time.*` (wide set) | — | — |
| GTP echo interval | yes | — | yes |
| GTP-U / TEID scalars | — | — | yes (+ `inbound_roam`) |
| Session / IP pools | — | yes | — |
| PFCP peer lists | — | UPF sync | SGW-U sync |
| GTP-C peer lists | SGWC + SMF sync | — | — |
| ACL / policy lists | tai, access_control, hss_map, imsi_acl, emergency, … | — | gn.pgw |
| Trace IMSI | yes | yes | yes |
| CDR | — | yes | yes |
| RADIUS | — | yes (+ per-APN from session) | — |
| DNS | — | yes | — |
| MTU | — | yes | — |
| NWI rewrite | — | — | yes |
| Logger | yes | yes | yes |
| Bind / listen addresses | restart | restart | restart |

---

## NMS reload workflow (recommended)

1. Validate YAML syntax before push.
2. Write config to the live path (`/etc/open5gs/{mme,smf,sgwc}.yaml`).
3. Trigger reload (systemctl reload or `kill -HUP`).
4. Parse daemon log for `Configuration reloaded` and audit lines.
5. If any `… ignored (bind address)` or `Configuration reload failed` appears, mark the change as **needs restart**.
6. For peer/pool removals, confirm no `removal skipped` warnings — if present, the old entry is still active.

---

## Related docs

- Operator summary in repo root: `README.md` (Runtime config reload sections)
- **Full fictional config samples (all services):** `configs/nms/samples/README.md`
- SMF admin API (CDR/RADIUS alternative): `tools/admin-api/README.md`
