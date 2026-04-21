# Open5GS Admin API — MongoDB Schema

Database name (default): **`open5gs_admin`** (reuses the existing Open5GS
Mongo instance; operators can change it via `Mongo:Database` in
`appsettings.json`).

All timestamps are UTC (`DateTime`). Every resource collection carries a
monotonically-increasing `revision` field assigned at write time from the
global counter. Revisions never decrease and never wrap in any realistic
lifetime (int64).

## Collections

### `plmns`

| Field        | Type     | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `_id`        | ObjectId | auto                                               |
| `mcc`        | string   | 3 digits                                           |
| `mnc`        | string   | 2–3 digits                                         |
| `label`      | string?  | free-form operator label                            |
| `revision`   | long     | global revision at write                           |
| `createdAt`  | date     | UTC                                                |
| `updatedAt`  | date     | UTC                                                |

Unique index: **`(mcc, mnc)`** — `uq_plmn`.

### `tacs`

| Field        | Type     | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `_id`        | ObjectId | auto                                               |
| `mcc`        | string   |                                                    |
| `mnc`        | string   |                                                    |
| `tacValue`   | int      | 0..16777215 (supports TAC-16 and TAC-24)           |
| `label`      | string?  |                                                    |
| `revision`   | long     |                                                    |

Unique index: **`(mcc, mnc, tacValue)`** — `uq_tac`.

### `dnns`

| Field        | Type     | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `_id`        | ObjectId | auto                                               |
| `name`       | string   | lowercased, `^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,62}$`    |
| `dns1`       | string?  | IPv4/IPv6                                          |
| `dns2`       | string?  |                                                    |
| `mtu`        | int?     | 576..9216                                          |
| `sliceSst`   | int?     | 1..255 (5GS only)                                  |
| `sliceSd`    | string?  | 6 hex digits (5GS only)                            |
| `label`      | string?  |                                                    |
| `revision`   | long     |                                                    |

Unique index: **`name`** — `uq_dnn`.

### `upf_peers`  *(consumed by SMF)*

| Field        | Type     | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `_id`        | ObjectId | auto                                               |
| `host`       | string   | IP literal or DNS                                  |
| `port`       | int      | default 8805                                       |
| `dnns`       | string[] | DNNs this UPF is authoritative for; empty = any    |
| `label`      | string?  |                                                    |
| `revision`   | long     |                                                    |

Unique index: **`(host, port)`** — `uq_upf_peer`.

### `subnets`  *(consumed by SMF + UPF)*

| Field        | Type     | Notes                                              |
|--------------|----------|----------------------------------------------------|
| `_id`        | ObjectId | auto                                               |
| `cidr`       | string   | IPv4 or IPv6 CIDR                                  |
| `dnn`        | string   | lowercased                                         |
| `dev`        | string?  | tun/dev device on UPF host (e.g. `ogstun`)         |
| `gateway`    | string?  | UPF-side gateway                                   |
| `label`      | string?  |                                                    |
| `revision`   | long     |                                                    |

Unique index: **`(cidr, dnn)`** — `uq_subnet`.

### `audit_log`

| Field        | Type       | Notes                                            |
|--------------|------------|--------------------------------------------------|
| `_id`        | ObjectId   |                                                  |
| `at`         | date       |                                                  |
| `actor`      | string?    | auth principal name, or `anonymous`              |
| `op`         | string     | `"add"` or `"delete"`                            |
| `kind`       | string     | `"plmn"`, `"tac"`, `"dnn"`, `"upf_peer"`, `"subnet"` |
| `revision`   | long       | revision at which the op happened                |
| `before`     | document?  | resource state before op (delete)                |
| `after`      | document?  | resource state after op (add)                    |

Index: `at` descending — `ix_audit_at`. No TTL by default; ops team decides.

### `revision`

Single-document counter.

```json
{ "_id": "global", "value": 42 }
```

Bumped with `$inc` inside `findOneAndUpdate` so the counter is read-modify-
write safe under contention.

### `nf_heartbeats`

| Field              | Type     | Notes                                       |
|--------------------|----------|---------------------------------------------|
| `_id`              | ObjectId |                                             |
| `nfId`             | string   | NF instance id (e.g. hostname + pid)        |
| `nfType`           | string   | `"mme"`, `"smf"`, `"upf"`, …                |
| `appliedRevision`  | long     | last revision the watcher has applied       |
| `updatedAt`        | date     |                                             |
| `lastError`        | string?  | last error on apply, or null                |
| `version`          | string?  | NF build / git sha                          |

Unique index: **`(nfId)`** — `uq_nf`. (`nfType` is informational.)

## Indexing notes for large deployments

- For clusters with many NFs, change `uq_nf` to compound `(nfType, nfId)` if
  you expect collisions across NF types. The current scheme assumes nfId
  (`hostname#pid`) is globally unique.
- If audit grows large, add a TTL index on `at`:

  ```js
  db.audit_log.createIndex(
      { at: 1 },
      { expireAfterSeconds: 60 * 60 * 24 * 90 } // 90 days
  );
  ```
