# Open5GS metrics + admin API — examples

Operator reference for every endpoint and filter exposed by the metrics
HTTP server (libmicrohttpd, default `0.0.0.0:9091` for MME; AMF/SMF use
their own ports configured under `<nf>.metrics`).

## Conventions used below

- `MME=http://10.233.65.222:9091` — replace with your daemon's metrics URL.
- `SGWC=http://10.233.65.222:9090` — SGWC metrics URL (`sgwc.metrics` in yaml).
- `AMF=http://10.233.65.222:9090`
- `SMF=http://10.233.65.222:9092`
- All endpoints accept **both** `GET` and (where mutating) `POST`. `GET` is
  the easiest to test from a browser or curl; `POST` is the one you'd wire
  into your NMS so it doesn't get accidentally cached/replayed by a proxy.
- All query parameters are optional. Omit them all to dump everything.
- Filters are **AND**-combined: passing `imsi=...&enb_id=...` returns only
  UEs that match *both* conditions.
- `enb_id`/`gnb_id` accept decimal, hex (`0x...`), or octal — the parser
  uses `strtoull(value, NULL, 0)`.
- `force=...` (admin endpoints) accepts `1`, `true`, `yes`, `on`
  (case-insensitive). Everything else means *graceful* (the default).
- **`/admin/*` endpoints** (detach, maintenance, trace, …) accept clients only
  from **local/private addresses**: IPv4 loopback (`127.0.0.0/8`), RFC1918
  (`10/8`, `172.16/12`, `192.168/16`), IPv6 loopback (`::1`), link-local, and
  unique-local. Other clients receive `403 Forbidden`. **`/metrics`**, `/ue-info`,
  `/enb-info`, `/pdu-info`, and `/` are **not** gated — firewall those if needed.

## Response envelope

Every JSON dumper (`/enb-info`, `/ue-info`, `/gnb-info`, `/pdu-info`)
returns the same envelope:

```json
{
  "items": [ /* one object per matched eNB/UE/gNB/PDU */ ],
  "pager": {
    "page": 0,
    "page_size": 100,
    "count": 1
  }
}
```

`count` is the number of items in *this* page, not the global total — if
`count == page_size` there is likely a next page. Pass `page_size` larger
than your fleet to disable paging effectively.

---

## 0. Health check

```bash
curl -i $MME/
# HTTP/1.1 200 OK
# OK
```

Returns `200 OK` with body `OK\n`. Use this for liveness probes — it does
not touch any NF state, so it's cheap to scrape every second.

---

## 1. Prometheus metrics — `/metrics`

```bash
curl -s $MME/metrics | head
# # HELP enb_gauge ...
# # TYPE enb_gauge gauge
# enb_gauge 1024
# ...
```

No filters. The MHD backend in use is logged at startup
(`metrics_server: ... backend=epoll`). If you see `backend=select` you are
running against an old/limited libmicrohttpd build that will fail at
~1000 daemon FDs (see commit notes).

---

## 2. MME — `/enb-info`

JSON dump of every attached eNB.

### Filters

| Param       | Type      | Meaning                                    |
|-------------|-----------|--------------------------------------------|
| `enb_id`    | uint32    | Match a single Global-ENB-ID (any base).   |
| `ip`        | string    | Match the eNB's SCTP source IP exactly.    |
| `page`      | uint      | Zero-based page index (default `0`).       |
| `page_size` | uint      | Items per page (default `100`, no clamp).  |

### Examples

```bash
# Default — first 100 eNBs
curl -s "$MME/enb-info" | jq '.items | length'

# Whole list (one page big enough to hold everything)
curl -s "$MME/enb-info?page_size=100000" | jq '.items | length'

# Page through 100 at a time
curl -s "$MME/enb-info?page=0&page_size=100"
curl -s "$MME/enb-info?page=1&page_size=100"

# One specific eNB by ID (decimal or hex, both accepted - the parser uses strtoull base 0)
curl -s "$MME/enb-info?enb_id=121465"
curl -s "$MME/enb-info?enb_id=0x1da59"

# All eNBs whose SCTP address is 172.22.146.6
curl -s "$MME/enb-info?ip=172.22.146.6"
```

### Sample response

```json
{
  "items": [
    {
      "enb_id": 121465,
      "plmn": "00101",
      "network": { "mme_name": "mme0" },
      "s1": {
        "sctp": {
          "peer": "172.22.146.6:36412",
          "max_out_streams": 30,
          "next_ostream_id": 3
        },
        "setup_success": true
      },
      "supported_ta_list": [
        { "tac": "661f", "plmn": "00101" }
      ],
      "num_connected_ues": 387
    }
  ],
  "pager": { "page": 0, "page_size": 100, "count": 1 }
}
```

---

## 3. MME — `/ue-info`

JSON dump of every UE (per EPS session, plus per-bearer detail).

### Filters

| Param       | Type      | Meaning                                              |
|-------------|-----------|------------------------------------------------------|
| `imsi`      | string    | Match `IMSI` exactly (15 digits, no leading `0x`).   |
| `enb_id`    | uint32    | Only UEs hosted on this Global-ENB-ID.               |
| `page`      | uint      | Zero-based page index.                               |
| `page_size` | uint      | Items per page (default `100`).                      |

### Examples

```bash
# One UE by IMSI
curl -s "$MME/ue-info?imsi=001013957864788" | jq '.'

# All UEs sitting on a specific eNB
curl -s "$MME/ue-info?enb_id=121465&page_size=10000"

# Cross-filter — UE 001013957864788 only if it's attached on eNB 121465
curl -s "$MME/ue-info?imsi=001013957864788&enb_id=121465"
```

---

## 4. AMF — `/gnb-info`

5G equivalent of MME `/enb-info`. Same filters apply, with the alias
`gnb_id` for clarity. (`enb_id` is also accepted because both NFs share
the same query parser — pick whichever reads better.)

```bash
curl -s "$AMF/gnb-info?gnb_id=100&page_size=100000"
curl -s "$AMF/gnb-info?ip=172.22.150.10"
```

---

## 5. AMF — `/ue-info`

Same shape as MME `/ue-info`, with `supi` available in addition to `imsi`.

| Param       | Type      | Meaning                                              |
|-------------|-----------|------------------------------------------------------|
| `supi`      | string    | Match SUPI exactly (`imsi-<15 digits>`).             |
| `imsi`      | string    | Match the IMSI portion (15 digits).                  |
| `gnb_id`    | uint32    | Only UEs on this gNB (alias `enb_id` works too).     |
| `page`      | uint      | Pagination.                                          |
| `page_size` | uint      | Pagination.                                          |

```bash
# One UE by SUPI
curl -s "$AMF/ue-info?supi=imsi-001010000000001" | jq '.'

# One UE by raw IMSI
curl -s "$AMF/ue-info?imsi=001010000000001" | jq '.'

# All UEs on a specific gNB
curl -s "$AMF/ue-info?gnb_id=100&page_size=10000"
```

---

## 6. SMF — `/pdu-info`

JSON dump of every active PDU session (4G PDN connection + 5G PDU
session both surface here).

### Filters

| Param       | Type      | Meaning                                              |
|-------------|-----------|------------------------------------------------------|
| `supi`      | string    | SUPI exact match (`imsi-<15 digits>`).               |
| `imsi`      | string    | Raw IMSI (15 digits).                                |
| `ue_ip`     | string    | Match the UE's IPv4 *or* IPv6 inner address.         |
| `page`      | uint      | Pagination.                                          |
| `page_size` | uint      | Pagination.                                          |

### Examples

```bash
# Everything
curl -s "$SMF/pdu-info?page_size=100000" | jq '.items | length'

# Sessions for one subscriber (SUPI form)
curl -s "$SMF/pdu-info?supi=imsi-001013957864788"

# Same subscriber, IMSI form
curl -s "$SMF/pdu-info?imsi=001013957864788"

# Find which session owns a given UE IP (works for IPv4 and IPv6)
curl -s "$SMF/pdu-info?ue_ip=10.45.0.7"
curl -s "$SMF/pdu-info?ue_ip=2001:db8:cafe::7"

# Combined: only IPv6 session of a specific IMSI
curl -s "$SMF/pdu-info?imsi=001013957864788&ue_ip=2001:db8:cafe::7"
```

### Sample response

```json
{
  "items": [
    {
      "supi": "imsi-001013957864788",
      "pdu": [
        {
          "psi": 1,
          "dnn": "internet",
          "ipv4": "10.45.0.7",
          "snssai": { "sst": 1, "sd": "ffffff" },
          "qos_flows": [ { "qfi": 1, "5qi": 9 } ],
          "n3": {
            "gnb": { "teid": 76,    "addr": "[192.168.168.100]:2152" },
            "upf": { "teid": 11426, "addr": "[192.168.168.7]:2152", "pdr_id": 2 }
          },
          "pdu_state": "inactive"
        }
      ],
      "ue_activity": "idle"
    }
  ],
  "pager": { "page": 0, "page_size": 100, "count": 1 }
}
```

LTE PDN connections appear with `ebi` + `apn` + `qos_flows: [{ebi, qci}]`
instead of the 5G `psi`/`dnn`/`snssai`/`qfi`/`5qi` keys; both shapes can
appear in the same response if SMF is serving combined-mode subscribers.

---

## 7. MME admin — `/admin/enb/detach`

Drop an eNB. Both `GET` and `POST` accepted.

### Match rules

Pass **one** of:

- `enb_id=<uint32>` — Global-ENB-ID (preferred; unique).
- `ip=<string>` — eNB SCTP source IP. If multiple eNBs share an IP only
  the first match is targeted, so prefer `enb_id` when possible.

### `force` flag

| `force`     | Behaviour                                                              |
|-------------|------------------------------------------------------------------------|
| `0` (def.)  | **Graceful (3GPP):** MME sends `S1AP Reset` (`s1_Interface`, cause `om_intervention`), waits ~2 s for the eNB to clean up, then releases the UEs via `S11 Delete-Session` and tears down SCTP. |
| `1`         | **Force:** skip the Reset PDU, release UEs and close SCTP immediately. Use only when the eNB is half-dead. |

### Examples

```bash
# Graceful detach of a specific eNB
curl -s "$MME/admin/enb/detach?enb_id=121465"
# => 200 OK: {"ok":true,"mode":"graceful","enb_id":121465}

# Force detach the same eNB
curl -s "$MME/admin/enb/detach?enb_id=121465&force=1"

# Match by IP (e.g. when you only know the eNB's address)
curl -s "$MME/admin/enb/detach?ip=172.22.146.6"

# POST form (recommended for production automation)
curl -s -X POST "$MME/admin/enb/detach?enb_id=121465"
```

### Audit log line

Every admin call is logged with the caller's address:

```text
[mme] INFO: admin: /admin/enb/detach from 10.233.65.10:54321 (force=0)
[mme] INFO: admin enb detach enb_id=121465 mode=graceful
```

---

## 8. MME admin — `/admin/ue/detach`

Detach a UE.

### Match rule

`imsi=<15 digits>` is required.

### `force` flag

| `force`    | Behaviour                                                                              |
|------------|----------------------------------------------------------------------------------------|
| `0` (def.) | **Graceful (3GPP TS 23.401 §5.3.8.3):** if UE is ECM-CONNECTED, MME sends NAS Detach Request and waits for Detach Accept. If ECM-IDLE, MME pages the UE first (paging type = `DETACH_TO_UE`) and then runs the connected flow. SGW/PGW are torn down via the standard cascade. |
| `1`        | **Implicit detach:** UE is not notified over the air. SGW/SMF/PGW are still cleaned up. The UE only finds out at next interaction. |

### Examples

```bash
# Graceful detach by IMSI
curl -s "$MME/admin/ue/detach?imsi=001013957864788"
# => 200 OK: {"ok":true,"mode":"graceful","imsi":"001013957864788"}

# Implicit detach (no air-interface notification)
curl -s "$MME/admin/ue/detach?imsi=001013957864788&force=1"

# POST form
curl -s -X POST "$MME/admin/ue/detach?imsi=001013957864788"
```

### Audit log line

```text
[mme] INFO: admin: /admin/ue/detach from 10.233.65.10:54322 (force=0)
[mme] INFO: admin ue detach imsi=001013957864788 mode=graceful
```

### Do I also need to call SGW / SMF / PGW?

**No.** MME-initiated detach cascades automatically:

- Graceful path: MME sends NAS Detach to UE *and* `Delete-Session` to SGW.
  SGW propagates to PGW/SMF. SMF tears down the PDU session and releases
  the UE IP. UPF rules are removed. Charging records flush.
- Force path: MME calls `mme_gtp_send_delete_all_sessions(..., OGS_GTP_DELETE_NO_ACTION)`
  which produces the same downstream cascade, just without notifying the UE.

You only need to call `/admin/ue/detach` on the MME.

---

## 9. Maintenance mode — MME, SGWC, SMF (`/admin/maintenance`)

Block **new** registrations while you drain existing subscribers for a planned
upgrade or restart. Available on the MME, SGWC, and SMF metrics HTTP servers
(same port and firewall rules as the other `/admin/*` endpoints).

While maintenance is enabled:

| NF    | Blocks |
|-------|--------|
| MME   | New EPS attach and additional PDN connectivity (EMM #22 congestion) |
| SGWC  | New S11 Create Session (GTPv2 cause #73 no resources) |
| SMF   | New S5 Create Session (GTPv2 cause #73 no resources) |

Drain tears down existing state with standard signalling (graceful by default).
On the MME that is the same path as `/admin/ue/detach` for every UE (NAS Detach
+ S11 Delete Session, which cascades to SGWC/SMF). SGWC drain sends PFCP
session deletion to SGW-U and Delete Session on S5. SMF drain sends best-effort
PFCP session deletion to the UPF.

### Endpoints (each NF)

| Method | Path | Meaning |
|--------|------|---------|
| `GET`  | `/admin/maintenance` | JSON status (`maintenance` flag + count) — alias |
| `GET`  | `/admin/maintenance/status` | Same JSON status (preferred admin route) |
| `POST` | `/admin/maintenance/enable` | Turn maintenance on (reject new sessions) |
| `POST` | `/admin/maintenance/disable` | Turn maintenance off (normal operation) |
| `GET`/`POST` | `/admin/maintenance/drain[?force=1]` | Enable maintenance **and** start draining all UEs/sessions |

Status response shapes:

```json
{"maintenance":false,"ue_count":42}          // MME
{"maintenance":false,"session_count":42}     // SGWC, SMF
```

### `force` on drain

| `force`    | MME drain | SGWC / SMF drain |
|------------|-----------|------------------|
| `0` (def.) | MME-initiated explicit detach per UE (NAS + S1 release) | PFCP/GTP delete signalling; contexts removed when peers respond |
| `1`        | Implicit detach (no NAS to UE); SGW/SMF still cleaned up | Immediate local session/UE context purge after starting delete |

### Planned maintenance workflow

Run on all three NFs before restarting daemons. **Enable maintenance first**
so new attaches are rejected while the drain runs.

```bash
MME=http://10.233.65.222:9091
SGWC=http://10.233.65.222:9090
SMF=http://10.233.65.222:9092

# 1. Block new users
curl -s -X POST "$MME/admin/maintenance/enable"
curl -s -X POST "$SGWC/admin/maintenance/enable"
curl -s -X POST "$SMF/admin/maintenance/enable"

# 2. Graceful drain — start with MME (cascades Delete Session to SGW/SMF)
curl -s -X POST "$MME/admin/maintenance/drain"

# 3. Wait until counts reach zero (idle UEs may need paging — allow a few minutes)
watch -n5 'curl -s $MME/admin/maintenance/status; echo; curl -s $SGWC/admin/maintenance/status; echo; curl -s $SMF/admin/maintenance/status'

# 4. Clean up any stragglers on SGW/SMF
curl -s -X POST "$SGWC/admin/maintenance/drain"
curl -s -X POST "$SMF/admin/maintenance/drain"

# 5. Restart daemons, then re-open for service
sudo systemctl restart open5gs-mmed open5gs-sgwcd open5gs-smfd
curl -s -X POST "$MME/admin/maintenance/disable"
curl -s -X POST "$SGWC/admin/maintenance/disable"
curl -s -X POST "$SMF/admin/maintenance/disable"
```

Hard cutoff (no NAS notification to handsets):

```bash
curl -s -X POST "$MME/admin/maintenance/drain?force=1"
```

### Audit log lines

```text
[mme]  INFO: admin maintenance: enabled
[mme]  INFO: admin maintenance drain: mode=graceful
[mme]  INFO: admin maintenance drain: queued detach for 42 UEs
[sgwc] INFO: admin maintenance drain: initiated for 38 sessions
[smf]  INFO: admin maintenance drain: initiated for 38 sessions
```

---

## 10. Server tunables (env vars)

Set on the MME/AMF/SMF systemd unit (`Environment=KEY=val`) or
`/etc/default/open5gs-mmed`. Defaults are sized for thousands of peers.

| Variable                          | Default | Meaning                                                                 |
|-----------------------------------|---------|-------------------------------------------------------------------------|
| `OGS_METRICS_THREAD_POOL_SIZE`    | `8`     | MHD worker threads (each with its own listen socket via SO_REUSEPORT).  |
| `OGS_METRICS_CONNECTION_LIMIT`    | `8192`  | Max concurrent HTTP connections held by MHD.                            |
| `OGS_METRICS_LISTEN_BACKLOG`      | `4096`  | TCP listen backlog. Silently capped by `net.core.somaxconn`.            |
| `OGS_METRICS_CONNECTION_TIMEOUT`  | `30`    | Idle HTTP connection timeout (seconds).                                 |

Set higher if you have many Prometheus scrapers or NMS clients hitting
the admin endpoints simultaneously. The startup log line shows the
applied values:

```text
[metrics] INFO: metrics_server: pool=8 conn_limit=8192 backlog=4096 timeout=30s backend=epoll (override via OGS_METRICS_* env vars)
```

---

## 11. Quick recipes

### "Which eNB owns IMSI X?"

```bash
curl -s "$MME/ue-info?imsi=001013957864788" \
  | jq '.items[0]'
```

### "List every UE on eNB Y in CSV form"

```bash
curl -s "$MME/ue-info?enb_id=121465&page_size=100000" \
  | jq -r '.items[] | [.imsi, .mme_ue_s1ap_id // empty, .tac // empty] | @csv'
```

### "Detach everyone on a misbehaving eNB then drop the eNB"

```bash
ENB=121465
# Graceful eNB detach is enough — it releases every UE on that eNB for you.
curl -s "$MME/admin/enb/detach?enb_id=$ENB"
```

### "Drain all subscribers before an upgrade (maintenance window)"

See **§9** for the full MME → SGWC → SMF sequence. Short form:

```bash
for url in $MME $SGWC $SMF; do curl -s -X POST "$url/admin/maintenance/enable"; done
curl -s -X POST "$MME/admin/maintenance/drain"
# poll /admin/maintenance on each NF until counts are 0, then restart daemons
```

### "Find which SMF holds the session with UE IP X"

If you have multiple SMFs:

```bash
for smf in $SMF1 $SMF2 $SMF3; do
  hit=$(curl -s "$smf/pdu-info?ue_ip=10.45.0.7" | jq -r '.items | length')
  echo "$smf: $hit"
done
```

### "Is `/metrics` healthy under load?"

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} %{size_download}\n" $MME/metrics
done | sort | uniq -c
# Expected: 100  200 <large number>
# Bad:      mixed 200 / 000 0 — backend is select() with FD>1023 (rebuild MHD).
```
