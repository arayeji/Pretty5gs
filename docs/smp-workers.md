# Pretty5GS SMP workers (`feature/smp-workers`)

Multi-core scaling for single-threaded NFs by sharding UEs/sessions
across N worker threads. SGW-C first, MME next. **Default off**
(`workers: 0`) — with workers disabled every code path is identical to
the single-threaded daemon.

## Invariants (the five rules)

1. **Share nothing.** State owned by a worker (UE, session, bearer,
   xact, timer, hash entry) is touched only on that worker's thread.
   There are exactly three sanctioned shared structures: the GTP/PFCP
   node (peer) tables (mutex on mutation — TODO 4), the metrics
   registry (prom lib has its own locks), and the talloc allocator
   (already mutex-serialized in `lib/core/ogs-memory.c`).
2. **Everything crosses on a queue.** `ogs_worker_post()` /
   `sgwc_event_push_local()`. Never call into another shard's state.
3. **Ownership is visible in the ID.** Every locally-allocated
   protocol identifier carries the owner's worker id in its top
   `OGS_WORKER_ID_BITS` (=3) bits:
   | space | width | shard bits | helper |
   |---|---|---|---|
   | GTPv2 xid | 23 (of 24-bit SQN, bit 23 = CMD) | 22..20 | `xact_next_xid()` lib/gtp/xact.c |
   | GTPv1 SQN | 16 | 15..13 | same |
   | PFCP xid/SQN | 23 | 22..20 | `xact_next_xid()` lib/pfcp/xact.c |
   | S11/S5C TEID | 32 | 31..29 | `sgwc_shard_compose()` src/sgwc/context.c |
   | Sx SEID | 64 (values < 2^32) | 31..29 | same (equals S5C TEID) |
   Raw values must stay below 2^29 (asserted only when sharding is
   enabled); the inbound-roam TEID offset is applied *before* shard
   composition — validate `offset + pool size < 2^29` at config parse
   before enabling shard workers.

   **Router mask rule (GTPv2/PFCP):** shard bits sit at 22..20, BELOW
   the CMD bit (23). Owner extraction is `(xid >> 20) & 7` — the `& 7`
   is mandatory or Command-triggered transactions route to the wrong
   worker (audit F5).

   **Sharding is opt-in (audit F1):** id-space partitioning activates
   only after `ogs_worker_shards_enable()`, which only an NF running
   real protocol shard workers calls. Helper workers (MME S1AP RX
   decode offload) never shrink the GTP/PFCP xid spaces.
4. **The main thread is the router + housekeeper.** It owns all
   sockets' RX, the PFCP association/heartbeat FSM, metrics HTTP,
   admin API, and config reload fan-out. It holds no UE/session state
   when workers are active.
5. **Buffers may cross threads** (talloc is mutexed) but each object is
   freed by the thread that owns it at that point in its life; events
   and their pkbufs are handed off, never shared.

## Done (compiles clean, default-off)

- `lib/core/ogs-worker.[ch]` — worker runtime: own pollset/timer
  mgr/queue, canonical loop, TLS `ogs_worker_self()`, ready-barrier in
  `ogs_worker_start()`, `ogs_worker_timer_mgr(fallback)` shim.
- `lib/gtp/xact.c`, `lib/pfcp/xact.c` — pools/xid/init flags
  thread-local; timers on the calling worker's mgr; per-shard
  local/remote xact lists on the shared node
  (`local_list[OGS_MAX_WORKERS]`); shard-partitioned xid allocation
  (only when `ogs_worker_active()`).
- `src/sgwc/context.c` — context + pools thread-local;
  `sgwc_shard_compose()` on S11 TEID / S5C TEID / Sx SEID (incl. the
  inbound-roam path); atomic session counter.
- `src/sgwc/event.c` — events via mutexed talloc (cross-thread safe);
  `sgwc_event_push_local()`.
- **MME S1AP RX decode offload** (`mme.s1ap_rx_workers: N`, default 0):
  `src/mme/s1ap-rx.[ch]` — accepted eNB sockets assigned round-robin to
  RX workers that poll + APER-decode and post pre-decoded
  `MME_EVENT_S1AP_MESSAGE`s (`e->s1ap_rx_decoded`). Two-phase socket
  teardown via `MME_EVENT_S1AP_RX_SOCK_CLOSED`; main loop drops (not
  asserts) messages for removed eNBs; worker pushes wake the main
  pollset; worker-side error paths skip main-thread hashes.

## Done (SGW-C shards)

1. **`src/sgwc/sgwc-workers.c` + `init.c`** — parse `sgwc.workers`
   (0..8, default 0); `ogs_worker_shards_enable()`; per-shard pools;
   worker FSM = `sgwc_state_operational`.
2. **GTP / PFCP RX routers** — TEID/SEID/IMSI/SQN shard steering;
   Echo + PFCP association stay on main.
3. **Shared GTP peer lists** (`sgwc_mme_s11_list` etc.) + mutex;
   PFCP peer list mutex in `lib/pfcp/context.c`.
4. **Admin / SIGHUP / drain / orphan purge** fan-out to every shard.

## Remaining

1. **Metrics** — per-PLMN/per-PGW gauges from workers: label by shard
   or aggregate via atomics (prom counters already locked).
2. **Tests** — attach/VoLTE with `workers: 2`; optional TSAN job.
3. **Admin session list dump** — still walks the calling thread's UE
   list; use IMSI-routed detach / atomic `sgwc_session_count()` for ops.
4. **MME Stage C** — full UE sharding (S1AP RX offload already exists).
   Do not enable MME UE shards before SGW-C soaks in production.

## Audit follow-ups (2026-07-16 review)

- **F1 fixed**: `ogs_worker_shards_active()` (opt-in) now gates xid
  partitioning and `sgwc_shard_compose`; RX helper workers no longer
  affect protocol id spaces.
- **F3 fixed**: `sgwc_shard_compose` is a strict no-op (no assert)
  when sharding is off; roam-offset validation moves to config parse
  when SGW-C workers land.
- **F4 picked**: `fix(sgwc): skip PFCP restoration during maintenance
  drain` cherry-picked onto this branch.
- **F5**: allocation already keeps shard bits below the CMD bit;
  routers mask with `& 7` in `sgwc_shard_from_teid/xid`.
- **F2/F6 closed**: SGW-C workers, RX routers, shared peer lists and
  drain/admin fan-out are implemented. Keep `sgwc.workers: 0` in
  production until staging soak.
- **F7 open**: `ogs_worker_post()` is a blocking push; switch to
  trypush + drop metric under sustained overload.
- **F8 open**: RX offload is wired for the lksctp `SOCK_STREAM` path
  only; with usrsctp (`SOCK_SEQPACKET` upcalls) the knob is a no-op.

## Deployment

- Ship with all knobs 0/off first (bit-identical behavior).
- MME: after F1 fix verification, trial on staging:

  ```yaml
  mme:
    s1ap_rx_workers: 2   # 0 = off (default); max 8
  ```

  Watch main-thread CPU (`rate(process_cpu_seconds_total[5m])`), GTP
  xact timeout counters, and S1 setup churn during an eNB flap storm.
- SGW-C staging trial:

  ```yaml
  sgwc:
    workers: 2   # 0 = off (default); max 8
  ```

  Watch main vs worker CPU, GTP/PFCP xact timeouts, and drain/SIGHUP.
  `inbound_roam.gtpc.teid_offset` must stay below 2^29 when workers > 0.
- Then production during a night window with a rollback binary staged.
