# Open5GS Admin API

Append-only HTTP/JSON admin service for managing **hot-addable** Open5GS
configuration (PLMNs, TACs, DNNs, UPF peers, IP subnets) backed by MongoDB.

Designed to satisfy the constraints the operator set out:

1. **Hot-add only** — adds are applied by the NFs on the next tick; nothing
   is destructively reconfigured.
2. **Delete = forget** — deletes only remove the config row. In-flight UEs,
   eNBs, and gNBs are untouched. Operator-driven drain, if wanted, is a
   separate concern.
3. **Idempotent** — POSTing the same natural key twice is a no-op and does
   not bump the global revision.
4. **Capacity-aware** — caps from `lib/proto/types.h` and
   `lib/pfcp/context.h` are mirrored in `Infrastructure/ConfigLimits.cs` and
   checked before accepting a POST, so an NF cannot overflow a static array
   at apply time.

## Runtime layout

```
tools/admin-api/
├── docs/
│   ├── openapi.yaml            # full OpenAPI 3.0 spec
│   └── schema.md               # Mongo collection/index documentation
├── src/Open5gs.AdminApi/       # ASP.NET Core 9 minimal API
└── Dockerfile                  # self-contained linux-x64 image
```

## Build

Requires .NET 9 SDK.

```powershell
cd tools/admin-api
dotnet build Open5gs.AdminApi.sln -c Release
```

Produces `src/Open5gs.AdminApi/bin/Release/net9.0/<rid>/open5gs-admin-api`.

### Self-contained single-file binary

```powershell
dotnet publish src/Open5gs.AdminApi/Open5gs.AdminApi.csproj `
    -c Release -r linux-x64 --self-contained true `
    -p:PublishSingleFile=true -o dist
```

## Configuration

`src/Open5gs.AdminApi/appsettings.json` is the baseline. All keys can be
overridden by environment variables using standard ASP.NET Core mapping
(`__` as section separator).

| Setting                 | Env var                          | Default                         |
|-------------------------|----------------------------------|---------------------------------|
| `Mongo:ConnectionString`| `Mongo__ConnectionString`        | `mongodb://127.0.0.1:27017`     |
| `Mongo:Database`        | `Mongo__Database`                | `open5gs_admin`                 |
| `Auth:TokenEnvVar`      | `Auth__TokenEnvVar`              | `OPEN5GS_ADMIN_TOKEN`           |
| *(the bearer token)*    | `OPEN5GS_ADMIN_TOKEN`            | *(unset — anonymous allowed)*   |
| `Kestrel:Endpoints:Http:Url` | `ASPNETCORE_URLS`           | `http://0.0.0.0:9998`           |

If `OPEN5GS_ADMIN_TOKEN` is unset, the service **accepts every request
without auth** and logs a warning. That mode is intended for loopback dev
only.

## Run

```powershell
$env:OPEN5GS_ADMIN_TOKEN = "s3cret"
dotnet run --project src/Open5gs.AdminApi/Open5gs.AdminApi.csproj
```

Then:

* Swagger UI: http://localhost:9998/swagger
* OpenAPI JSON: http://localhost:9998/swagger/v1/swagger.json
* Liveness: http://localhost:9998/healthz

### Quick smoke

```powershell
$h = @{ Authorization = "Bearer s3cret" }

# add a PLMN (201 first time, 200 on re-POST)
Invoke-RestMethod -Uri http://localhost:9998/api/v1/plmns -Method Post `
    -Headers $h -ContentType application/json `
    -Body '{"mcc":"001","mnc":"01","label":"lab"}'

# add a TAC under it
Invoke-RestMethod -Uri http://localhost:9998/api/v1/tacs -Method Post `
    -Headers $h -ContentType application/json `
    -Body '{"mcc":"001","mnc":"01","tac":7,"label":"site-a"}'

# see what's there
Invoke-RestMethod -Uri http://localhost:9998/api/v1/tacs -Headers $h

# check current global revision + per-NF lag
Invoke-RestMethod -Uri http://localhost:9998/api/v1/apply-status -Headers $h
```

## systemd service (Linux deploy)

A unit template ships at `configs/systemd/open5gs-admin-api.service.in`
and is installed by `meson install` into `/lib/systemd/system/` alongside
`open5gs-cgfd.service`. An environment-file template is installed to
`/usr/share/open5gs/admin-api/open5gs-admin-api.env.example` — copy it
to `/etc/open5gs/admin-api.env` and set `OPEN5GS_ADMIN_TOKEN`.

Two helper scripts automate the full pipeline:

```
tools/admin-api/scripts/publish-linux.sh   # build   (any host with .NET 9 SDK)
tools/admin-api/scripts/install-linux.sh   # deploy  (run as root on target)
```

### 1. Build the self-contained binary

Run from the repo root on any machine that has the .NET 9 SDK (Windows,
Linux, WSL, macOS all fine — publish cross-compiles):

```bash
tools/admin-api/scripts/publish-linux.sh
# override the RID for ARM gateways:
RID=linux-arm64 tools/admin-api/scripts/publish-linux.sh
```

Output lands in `tools/admin-api/dist/admin-api/`:

```
open5gs-admin-api        # single-file ELF, bundles the .NET runtime
appsettings.json         # baseline config
*.pdb                    # symbols for readable stack traces
```

### 2. Deploy to the service path

Copy the `dist/admin-api/` directory to the target, then:

```bash
# On the target host, as root:
sudo PUBLISH_DIR=/path/to/dist/admin-api \
     /path/to/open5gs/tools/admin-api/scripts/install-linux.sh
```

The install script:

* creates the `open5gs` system user/group if missing,
* copies the binary + `appsettings.json` into `/opt/open5gs/admin-api/`
  owned by `open5gs:open5gs`,
* seeds `/etc/open5gs/admin-api.env` from the shipped example on
  first run (mode 0640 root:open5gs) and leaves it untouched on
  subsequent runs — your token survives upgrades,
* installs the systemd unit if `meson install` hasn't already,
* refuses to start the service while the env file still contains the
  placeholder token, so an unauthenticated API never hits the LAN.

Set `NO_RESTART=1` to stop before `systemctl`, edit the env file, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now open5gs-admin-api.service
sudo systemctl status open5gs-admin-api.service
journalctl -u open5gs-admin-api.service -f
```

The unit binds to `http://0.0.0.0:9998` (matching the watcher default
used by every NF). Override `ASPNETCORE_URLS` in
`/etc/open5gs/admin-api.env` if you want to restrict it to localhost or
add a TLS-terminating proxy in front.

## Docker

```bash
docker build -t open5gs/admin-api:0.1.0 .
docker run --rm -p 9998:9998 \
    -e Mongo__ConnectionString=mongodb://host.docker.internal:27017 \
    -e OPEN5GS_ADMIN_TOKEN=s3cret \
    open5gs/admin-api:0.1.0
```

## How NFs consume this

Each NF (MME, SMF, UPF) runs a small **config watcher** that:

1. Polls (or tails via change streams) the Mongo collections it cares about.
2. On detecting entries newer than its locally-applied revision, appends
   them to its in-memory state (never touches or rebuilds existing entries).
3. POSTs `/api/v1/apply-status/heartbeat` with the highest revision it has
   successfully applied and any error string from the last tick.

The reference watcher skeleton (C, using libogs timers) lives next to this
service under `tools/admin-api/watcher-c/` (to be landed in a follow-up
commit) and is wired into the MME first as the proof.

## Two resource classes

The API distinguishes two kinds of resource, which have different update
semantics:

| Class      | Examples                                   | Write verb | Semantics                 |
|------------|--------------------------------------------|-----------:|---------------------------|
| **list**   | plmn, tac, dnn, upf-peer, subnet           | `POST`     | append-only, idempotent; `DELETE` = forget |
| **settings** | `smf/cdr`, `smf/radius`, `cgfd/gtpp`     | `PUT`      | last-write-wins singleton; `DELETE` = clear (NF reverts to file/defaults) |

A `PUT` on a settings row that is byte-identical to the current payload
is a no-op and does **not** bump the global revision — same "don't flood
watchers with idempotent writes" principle the list-class uses for
`POST`.

### `smf/cdr` — Ga interface CDR writer

Mirrors `smf_cdr_config_t` in `src/smf/context.h`. Picked up by the SMF
admin watcher, which calls `smf_ga_writer_apply_runtime()` on the main
thread (so the active spool file is cleanly rotated before the directory
moves).

```bash
curl -XPUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://admin:9998/api/v1/settings/smf/cdr -d '{
  "enabled":        true,
  "spool_dir":      "/var/spool/open5gs/cdr",
  "node_id":        "open5gs-smf-1",
  "local_address":  "10.0.0.1",
  "max_records":    100,
  "max_bytes":      65536,
  "max_seconds":    30,
  "triggers":       ["start", "interim", "stop"]
}'
```

`triggers` accepts three forms: the raw uint32 bitmask (as it appears on
the wire), a comma-separated string (`"start,interim,stop"`), or an array
of strings. The API normalizes everything to the bitmask before storing
and hashing, so a `PUT` in any form will re-idempotize with a PUT in any
other form.

Retrieve the current setting:

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://admin:9998/api/v1/settings/smf/cdr
```

Clear it (SMF disables the CDR writer at the next tick; existing spool
files are rotated into `ready/` first):

```bash
curl -XDELETE -H "Authorization: Bearer $TOKEN" \
     http://admin:9998/api/v1/settings/smf/cdr
```

### `smf/radius` — RADIUS client farm + PoD listener

Mirrors `smf_radius_config_t` in `src/smf/context.h`. Picked up by the
SMF admin watcher, which calls `smf_radius_apply_runtime()` on the main
thread. Existing sessions pinned to a server keep their affinity; new
and interim requests use the new server list. The PoD listener is
bounced only if `pod_enabled`, `pod_bind`, or `pod_port` change.

```bash
curl -XPUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://admin:9998/api/v1/settings/smf/radius -d '{
  "enabled":        true,
  "select_mode":    "primary_failover",
  "nas_identifier": "open5gs-smf",
  "nas_ip":         "10.0.0.1",
  "timeout_ms":     3000,
  "retry":          3,
  "acct_interim_interval": 300,
  "pod_enabled":    true,
  "pod_bind":       "0.0.0.0",
  "pod_port":       3799,
  "pod_secret":     "pod-secret",
  "pod_teardown_timeout_ms": 5000,
  "servers": [
    { "host":"10.0.0.10","auth_port":1812,"acct_port":1813,"secret":"s1","role":"primary"   },
    { "host":"10.0.0.11","auth_port":1812,"acct_port":1813,"secret":"s2","role":"secondary" }
  ]
}'
```

`select_mode` is `primary_failover` (default) or `hash_imsi`. At least
one server must have `role: primary`. Each server carries its own
shared secret; PoD accepts a request signed with any configured secret
(`pod_secret`, any `servers[].secret`, or the legacy flat `secret`).
Sessions remember which server accepted Access-Request so subsequent
Interim / Stop packets for that session go to the same AAA.

### `cgfd/gtpp` — CGF GTP' peer list + timers

Mirrors the `cgf:` block in `cgf.yaml.in` (peer list + timers + batch).
Picked up by the CGF daemon's admin watcher, which calls
`cgf_gtpp_apply_runtime()` on the main thread. Peers that appear in
both the old and new config (matched by host+port) keep their live
sockets / echo state / pending xacts; new peers are dialed; removed
peers are closed. Tunables (echo_interval_s, request_rto_ms, retries,
failover_after_missed_echoes, batch limits) are replaced wholesale.

```bash
curl -XPUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://admin:9998/api/v1/settings/cgfd/gtpp -d '{
  "peers": [
    { "host":"10.0.0.50","port":3386,"role":"primary"   },
    { "host":"10.0.0.51","port":3386,"role":"secondary" }
  ],
  "echo_interval_s":            60,
  "request_rto_ms":             3000,
  "request_retries":            4,
  "failover_after_missed_echoes": 3,
  "max_records_per_packet":     5,
  "max_bytes_per_packet":       1300,
  "purge_on_success":           true
}'
```

`purge_on_success` is tri-state: omit it to leave the daemon's existing
retention policy untouched; send `true` to `unlink(2)` fully-acked files
instead of moving them to `done/` (recommended when the remote CGF is
the system of record); send `false` to go back to the `done/` archive.
Failed files are always moved to `failed/` regardless.

## What this service deliberately does **not** do

- **No "update" on list resources.** PLMN/TAC/DNN/UPF-peer/subnet rows
  are immutable once added; mistakes get deleted and re-added. This
  keeps the revision stream strictly monotonic and trivial for NFs to
  replay. Settings rows are the one exception — see above.
- **No cascading deletes.** Deleting a PLMN does not delete TACs underneath
  it. The operator is expected to delete dependents explicitly if they
  care.
- **No draining or forced UE release.** Delete-then-live-UE is fine and
  deliberate per the requirement.
- **No NF-side push.** The service stores; NFs pull. That keeps the
  service stateless WRT NF availability.

## Observability

### Health

`GET /healthz` returns 200 when Mongo is reachable, 503 otherwise. No auth.

### Prometheus

`GET /metrics` serves OpenMetrics 0.0.4 text format, no auth (protect via
network ACL or reverse-proxy). Metrics:

| Name                                        | Type    | Labels                  |
|---------------------------------------------|---------|-------------------------|
| `open5gs_admin_revision_current`            | counter | —                       |
| `open5gs_admin_resources`                   | gauge   | `kind` ∈ {plmn,tac,...} |
| `open5gs_admin_audit_entries_total`         | counter | —                       |
| `open5gs_admin_nf_applied_revision`         | gauge   | `nf_id`, `nf_type`      |
| `open5gs_admin_nf_revision_lag`             | gauge   | `nf_id`, `nf_type`      |
| `open5gs_admin_nf_heartbeat_age_seconds`    | gauge   | `nf_id`, `nf_type`      |

The lag and heartbeat-age gauges give you an instantly usable alert source:
"any NF that has revision lag > 0 for more than 2× poll interval" catches
both stuck and dead watchers.

## Component status

| Component                                       | Status   |
|-------------------------------------------------|----------|
| C# admin API                                    | landed   |
| C watcher library (`tools/admin-api/watcher-c`) | landed   |
| MME integration (TAC hot-add)                   | landed   |
| SMF integration (UPF-peer + subnet hot-add)     | landed   |
| SMF integration (Ga/CDR settings hot-reload)    | landed   |
| SMF integration (RADIUS farm + PoD hot-reload)  | landed   |
| CGFD integration (GTP' peers hot-reload)        | landed   |
| UPF integration (subnet hot-add)                | landed   |
| Prometheus `/metrics`                           | landed   |
| Mongo change-streams                            | declined |

**On change-streams.** Mongo change-streams require a replica set, which is
a non-trivial operational requirement for many small Open5GS deployments.
The current 5 s NF poll plus 1 s main-thread drain gives ~6 s worst-case
add-to-apply latency, which is comfortably below the human feedback loop
for adding a TAC / IP pool / UPF peer. If you need faster propagation, run
Mongo as a replica set and drop `poll_interval_ms` in each watcher — no
code changes are needed.
