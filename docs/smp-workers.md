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
   `OGS_WORKER_ID_BITS` (=4 since Jul 2026; was 3) bits:
   | space | width | shard bits | helper |
   |---|---|---|---|
   | GTPv2 xid | 23 (of 24-bit SQN, bit 23 = CMD) | 22..19 | `xact_next_xid()` lib/gtp/xact.c |
   | GTPv1 SQN | 16 | 15..12 | same |
   | PFCP xid/SQN | 23 | 22..19 | `xact_next_xid()` lib/pfcp/xact.c |
   | S11/S5C TEID | 32 | 31..28 | `sgwc_shard_compose()` src/sgwc/context.c |
   | Sx SEID | 64 (values < 2^32) | 31..28 | same (equals S5C TEID) |
   Raw values must stay below 2^28 (asserted only when sharding is
   enabled); the inbound-roam TEID offset is applied *before* shard
   composition — validate `offset + pool size < 2^28` at config parse
   before enabling shard workers.

   **Router mask rule (GTPv2/PFCP):** shard bits sit at 22..19, BELOW
   the CMD bit (23). Owner extraction is `(xid >> 19) & 15` — the mask
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
- `src/sgwc/context.c` — **process-global** `sgwc_context_t` + shared
  pools/hashes (never thread-local — TLS `self` caused init vs
  event-loop split-brain). Container mutation under `sgwc_ctx_lock`;
  `sgwc_shard_compose()` on S11/S5C TEID / Sx SEID; atomic session
  counter. Per-UE state is owner-thread only.
- `src/sgwc/event.c` — events via mutexed talloc (cross-thread safe);
  `sgwc_event_push_local()`.
- **MME S1AP RX decode offload** (`mme.s1ap_rx_workers: N`, default 0):
  `src/mme/s1ap-rx.[ch]` — accepted eNB sockets assigned round-robin to
  RX workers that poll + APER-decode and post pre-decoded
  `MME_EVENT_S1AP_MESSAGE`s (`e->s1ap_rx_decoded`). Two-phase socket
  teardown via `MME_EVENT_S1AP_RX_SOCK_CLOSED`; main loop drops (not
  asserts) messages for removed eNBs; worker pushes wake the main
  pollset; worker-side error paths skip main-thread hashes.

## Done (AMF NGAP transport offload, phase 1)

Ports of the MME S1AP helpers to NGAP. All knobs default to 0 (off);
with every knob off the AMF behaves like the single-threaded daemon.

```yaml
amf:
  ngap_rx_workers: 2           # 0..15: SCTP recv + APER decode threads
  ngap_io_thread: 2            # 0..4: SCTP send threads (sticky per socket)
  ngap_io_write_queue_max: 10240     # per-socket send FIFO, 0 = default
  ngap_io_stall_teardown_sec: 10     # <0 disables stall teardown
  pkbuf_thread_pool: 256       # per-thread pkbuf pool (no-op on talloc builds)
```

- `src/amf/ngap-rx.[ch]` (`ngap-rx%d`) — port of `s1ap-rx`: accepted
  gNB sockets go to RX workers that drain + decode and post
  pre-decoded `AMF_EVENT_NGAP_MESSAGE`s; WATCH/UNWATCH and
  `AMF_EVENT_NGAP_RX_SOCK_CLOSED` / `_RX_WATCH_FAILED`.
- `src/amf/ngap-io.[ch]` (`ngap-io%d`) — port of `s1ap-io` without the
  congestion heartbeat: per-socket FIFO, non-blocking `sendmsg` +
  POLLOUT, EPIPE marks send-dead, ETIMEDOUT/stall pushes CONNREFUSED.
  Owns the two-phase socket close registry (RX + IO confirms).
- `src/amf/ngap-free.[ch]` (`ngap-free`) — deferred ASN.1/pkbuf free.
- `src/amf/event.c` — `amf_queue_push_main()` never blocks main;
  CONNREFUSED side queue (coalesced per socket); must-deliver close
  confirms retry then force-confirm; main batch cap 128.
- Accepted SCTP sockets are now non-blocking with the event
  subscription (`ogs_sctp_tune_connected`), and the 444
  `ogs_assert(r != OGS_ERROR)` send-path aborts are `ogs_expect`.
- **Ordering** (both found by `tests/registration`): on main the
  recv handler reads one message per wakeup (level-triggered poll), and
  events a dispatch pushes for itself (NGAP -> 5GMM/5GSM hand-off) run
  right after it, ahead of the queue. Without the latter, two queued
  InitialUEMessages for one UE ran as NGAP1 NGAP2 NAS1 NAS2.
- Deliberate deviations from MME: no NGAP TX encode offload
  (`s1ap_tx_workers` analog), no IO congestion heartbeat / overload
  control, no SIGHUP reload.
- Tests: `tests/load5gc` (`load5gc.yaml`, knobs on): NG-Setup churn,
  4 gNBs x 12 UEs parallel registration/PDU session/dereg, 4 x 4
  idle/service request. `tests/core` `worker-test`: FIFO dispatch,
  non-blocking full-queue post, startup barrier, cross-thread pkbufs,
  multi-producer.

**Phase 2 (not started): AMF UE shards (`amf.workers`).** Needs
`amf_ctx_lock` over pools/hashes/lists, shard bits in
AMF_UE_NGAP_ID, `being_removed` exactly-once removal, an opt-in
recursive lock for the process-global `lib/sbi` state (client/server
pools, `xact_list`, NF instances) with pollset dispatch hooks in
`lib/core`, per-worker UE timers, NGAP/SBI routing + rehome and gNB
fan-out to owners.

## Done (SGW-C shards)

1. **`src/sgwc/sgwc-workers.c` + `init.c`** — parse `sgwc.workers`
   (0..15 / `OGS_MAX_WORKERS-1`, default 0); `ogs_worker_shards_enable()`;
   per-shard pools; worker FSM = `sgwc_state_operational`.
2. **GTP / PFCP RX routers** — TEID/SEID/IMSI/SQN shard steering;
   Echo + PFCP association stay on main. Optional
   `sgwc.gtpc_rx_thread` / `sgwc.pfcp_rx_thread` move socket recv off
   `sgwc-main` onto helper threads (default off).
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
- **F7 closed** (lib): `ogs_worker_post()` is non-blocking
  (`ogs_queue_trypush_hint`); SGW-C RX paths count drops via
  `/admin/queues` (`gtpc_rx_drops` / `pfcp_rx_drops`).
- **F8 open**: MME S1AP RX offload is wired for the lksctp
  `SOCK_STREAM` path only; with usrsctp (`SOCK_SEQPACKET` upcalls)
  the knob is a no-op.

## Deployment

- Ship with all knobs 0/off first (bit-identical behavior).
- MME: after F1 fix verification, trial on staging:

  ```yaml
  mme:
    s1ap_rx_workers: 4   # 0 = off (default); prefer 4–6 in prod (8 adds
                         # lock contenders with little extra throughput)
    stage_c: 1           # needs workers > 0
    s1ap_tx_direct: 1    # needs s1ap_tx_workers + s1ap_io_thread
  ```

  Watch main-thread CPU (`rate(process_cpu_seconds_total[5m])`), GTP
  xact timeout counters, and S1 setup churn during an eNB flap storm.
  After deploy, re-profile `comm: mme-main` (see `docs/mme-smp-todo.md`
  §7) — expect lower futex share from pkbuf `calloc` + `s1ap-free`.
- SGW-C staging trial:

  ```yaml
  sgwc:
    workers: 15          # 0 = off (default); max 15 (4-bit shard ids)
    gtpc_rx_thread: 1    # offload GTP-C/Gn recv from main
    pfcp_rx_thread: 1    # offload PFCP recv/parse from main
  ```

  Watch main vs `gtpc-rx`/`pfcp-rx`/`sgwc-w*` CPU, GTP/PFCP xact
  timeouts, and drain/SIGHUP. `inbound_roam.gtpc.teid_offset` must
  stay below 2^28 when workers > 0.
- Then production during a night window with a rollback binary staged.
