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

## Done (SMF shards, EPC)

Same model as SGW-C: one process-global context, UEs owned by shards
(0 = `smf-main`, 1..N = `smf-w0..`), owner in the top 4 bits of every
local TEID / SEID and in the xid window of every GTP / PFCP request.

1. **`src/smf/smf-workers.c`** — `smf.workers` (0..15), worker FSM =
   `smf_state_operational`, per-shard xact pools and timer managers,
   `smf_event_push_shard` / `fanout` / `fanout_others`. Pure routing
   math and raw IMSI peeks live in `smf-shard.c` (unit-tested).
2. **RX routers** (`smf_gtp_route`, `smf_pfcp_route`) — replies by xid
   window, requests by TEID / SEID, new UEs by IMSI (existing owner
   first, else hash); Echo, PFCP association / heartbeat / node report
   and PFD stay on main. `smf.gtpc_rx_thread` / `smf.pfcp_rx_thread`
   move recv off `smf-main` (`smf-gtpc-rx` / `smf-pfcp-rx`).
3. **Rehome guard** after parse and before `xact_receive`: a message the
   router misplaced is re-posted to the owner, never handled locally.
   Create Session with a static IP held by another shard runs the
   **cross-shard collision handshake**: the IP owner releases (graceful
   replace or hard remove) and bounces the CSR back with `xshard_done`.
4. **PFCP session messages** leave the node FSM: session establishment /
   modification / deletion / report run on the session owner;
   restoration and UPF reselection fan out (`SMF_EVT_N4_RESTORE`).
5. **Diameter** Gx / Gy / S6b answers and RARs go straight from the
   freeDiameter thread to the session owner
   (`smf_event_post_to_sess_owner`); Gx peer reconnect fans out
   `SMF_EVT_GX_RESTORE`.
6. **RADIUS** — per-thread UDP transports (blocking exchanges never share
   a socket), config under a writer-preferring rwlock for hot reload,
   PoD verified and ACKed on main, teardown on the owner
   (`SMF_EVT_RADIUS_POD`, watchdog on the owner's timer manager).
7. **Fan-outs** — SGW restart purge (cutoff protects fresh sessions and
   pending collision replaces), orphan sweep (per-shard gauge slots),
   maintenance drain (per-shard batches, aggregated status).
8. **Shared state** — context lock (`ogs_metrics_dump_lock`, recursive)
   around UE/session hashes and `acct_session_id`; peers lock for gnode
   lookup / recovery; metrics get-or-create, CDR writer, LI targets each
   serialized.
9. **`/admin/queues`** — main + shard depths, RX drops, event lag,
   kernel RX backlog, verdict.
10. **Tests** — `tests/unit/smf-shard-test.c`; `configs/load.yaml.in`
    runs the EPC load test with `smf.workers: 4` and both RX threads.

11. **5GC relay** (`src/smf/sbi-relay.c`) — SBI sockets, clients, xacts
    and their timers stay on `smf-main`; 5G sessions are sharded like
    EPC ones (new UE by SUPI hash, IMSI SUPIs hash like an EPC attach,
    an existing UE keeps its owner, so EPC interworking lands on the
    same shard).
    - Server requests: main parses, picks the owner (SM context /
      PDU session create by SUPI, modify / release / SM policy notify
      by ref) and posts a copy (`ogs_sbi_request_copy`). The worker's
      response goes back through `ogs_sbi_server_set_send_hook`
      (`SMF_EVT_SBI_SEND`); main sends it if the stream (id + pointer)
      still exists.
    - Client responses: main finishes the xact, then moves the response
      to the owner, which parses it again.
    - Worker → main: `smf_main_call()` runs xact create / discover /
      send, N1N2 transfer, pending modification, status notify, client
      setup and SBI teardown synchronously on main (abandoned cleanly
      on shutdown).
    - 5GSM / NGAP / session release events are rehomed to the owner.
    - `lib/sbi` request / response, nghttp2 stream and MHD session pools
      are mutex-protected.
12. **Thread-safety follow-ups** — trace binding is captured with every
    cross-shard event and restored on the receiving thread; P-CSCF
    round-robin index is atomic; subnets added at reload / by the admin
    watcher get their UE IP pool generated; a RADIUS reload is installed
    with `trywrlock` and retried from a main timer while shards back off
    new reads, so main never blocks waiting for in-flight exchanges.

Verified on WSL with `smf.workers: 2`: registration, slice, handover,
transfer, VoNR and VoLTE (minus `rx-test`, which hangs without workers
too) suites, plus the EPC load test with `workers: 4`.

## Remaining

1. **Metrics** — per-PLMN/per-PGW gauges from workers: label by shard
   or aggregate via atomics (prom counters already locked).
2. **Tests** — optional TSAN job.
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
- SMF staging trial (after SGW-C soaks):

  ```yaml
  smf:
    workers: 4           # 0 = off (default); max 15
    gtpc_rx_thread: true
    pfcp_rx_thread: true
  ```

  Watch `smf-main` vs `smf-gtpc-rx`/`smf-pfcp-rx`/`smf-w*` CPU,
  `/admin/queues`, GTP/PFCP xact timeouts, Gx CCA latency, RADIUS
  accounting, and a UPF / SGW restart (restoration + purge fan-outs).
- Then production during a night window with a rollback binary staged.
