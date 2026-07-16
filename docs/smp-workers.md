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
   Raw values must stay below 2^29 (asserted); the inbound-roam TEID
   offset is applied *before* shard composition.
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

## Remaining (in order)

1. **`src/sgwc/init.c` — worker bring-up.** Parse `sgwc.workers`
   (int, 0..8, default 0). If >0: after main context init, create
   workers with `event_capacity = ogs_app()->pool.event`,
   `timer_capacity = ogs_app()->pool.timer`, `poll_capacity = 64`.
   `thread_init` hook: `sgwc_context_init(); sgwc_context_parse_config();
   ogs_gtp_xact_init(); ogs_pfcp_xact_init(); ogs_fsm_init(worker FSM)`.
   Worker FSM = `sgwc_state_operational` only (association FSM stays on
   main). `dispatch` = `ogs_fsm_dispatch` + `sgwc_event_free`.
   `thread_fini` mirrors. Divide per-worker pool sizes:
   `max.ue / workers`, `pool.sess / workers` (override before
   context_init via a setter, don't mutate shared conf).
2. **`src/sgwc/gtp-path.c` — S11/S5/Gn RX router.** In the recv cbs,
   when workers active: parse only the GTPv2 header
   (`ogs_gtp2_header_t`): `teid_presence && teid != 0` →
   `wid = teid >> 29`. `teid == 0`: Echo → handle on main;
   Create Session Request → scan TLVs for IMSI IE (type 1, instance 0)
   → `wid = imsi_bcd_hash % workers` (re-attach lands on the owner);
   anything else teid-0 → main (log). Post the existing event types to
   the worker. GTPv1 (Gn): same via 16-bit SQN top bits for responses,
   TEID for the rest.
3. **`src/sgwc/pfcp-path.c` — Sx RX router.** Header `SEID != 0` →
   `wid = (seid >> 29) & 7`. `SEID == 0`: node-related
   (assoc/heartbeat/report with SEID 0) → main; responses with SEID 0
   → route by SQN top bits (xid partition). Association FSM, heartbeat
   timers stay main-only.
4. **`lib/gtp/context.c`, `lib/pfcp/context.c`** — mutex around node
   add/remove/find (peers are few and long-lived; a plain mutex is
   fine). Workers may look up nodes concurrently with a rare add.
5. **Metrics** — `sgwc_metrics` gauges written from workers: make the
   per-PLMN/per-PGW gauges per-worker-labeled or aggregate via
   atomics; prom counters are already lock-protected internally.
6. **Admin API / SIGHUP** — fan the event out: allocate one event per
   worker and `ogs_worker_post` each; drain/maintenance must run on
   every shard.
7. **Tests** — `tests/` attach/volte flows with `workers: 2`; a TSAN
   job: `meson setup tsan -Db_sanitize=thread -Dbuildtype=debugoptimized`.
8. **MME (Stage C)** — first increment: S1AP RX decode offload (per
   S6a pattern: decode in RX threads, post decoded events); then shard
   by `MME_UE_S1AP_ID` top bits + `imsi→shard` map, per
   `docs/` discussion. Do not start before SGW-C soaks.

## Deployment

- Ship with `workers: 0` everywhere first (bit-identical behavior).
- Enable `workers: 2` on a staging SGW-C; watch
  `sgwc_pfcp_peers_active`, xact timeout counters, and TEID hash
  misses; then production during a night window.
