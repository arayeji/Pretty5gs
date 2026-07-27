# MME SMP / offload TODO

Follow-ups after S1AP RX decode offload (`mme.s1ap_rx_workers`) and the
epoll map self-heal. Keep `workers`-style knobs **default off** until each
stage soaks. Do not reintroduce thread-local `mme_self()` / context.

Invariants (same as `docs/smp-workers.md`):

- Context and UE pools stay process-global until Stage C ownership is real.
- Sockets: main (or a dedicated IO thread) owns `sctp_send` / accept.
- One UE → one owner thread; never share mutable UE state across workers.
- `s1ap_rx_workers: 0` and any new knobs at 0 remain bit-identical to today.

---

## Done (baseline)

- [x] S1AP RX + APER decode offload (`mme.s1ap_rx_workers`)
- [x] Epoll fd-map self-heal (`lib/core/ogs-epoll.c`) — stops WATCH-failed storm
- [x] SGW-C session shard workers (`sgwc.workers`) — soak before MME Stage C
- [x] `mme_find_served_tai` PLMN+TAC hash (lazy rebuild; list1 ranges stay linear)
- [x] S1AP TX encode offload — **DownlinkNASTransport wedge** (`mme.s1ap_tx_workers`, default 0)
- [x] Demote race/late teardown logs to WARN + merge SCTP/HO double logs

---

## Perf snapshot (post TAI + TX workers=4)

60s @ 199Hz, ~3.8k samples; config `s1ap_rx_workers: 4`, `s1ap_tx_workers: 4`.

| Item | Result |
|---|---|
| `mme_main` (children) | ~40% (was ~51% → ~45% after TAI alone) |
| `mme_find_served_tai` | gone (~0 samples) |
| TX offload | live (`s1ap_tx_*` in profile) |
| Remaining wedge | FSM on `mme_main` + **main-thread SCTP send** (~6.5% `sctp_write_callback`) |
| Other | Diameter `search_avp` ~4%, pkbuf/`memset` ~3.5%, `__vfprintf` ~3.3% |

---

## 1. `mme_find_served_tai` — hash / index — DONE

Confirmed in prod perf: self overhead gone. list1 ranges still linear.

---

## 2. S1AP encode + TX queue — DONE (DLNAS wedge); soak / Stage 2b open

| | |
|---|---|
| **Goal** | Worker builds+encodes DLNAS; main only `sctp_send` |
| **Benefit** | Moves high-volume DownlinkNASTransport APER off `mme_main` |
| **Effort** | Medium |
| **Risk** | Medium — per-assoc order via `s1ap_tx_pending` + hold list |
| **Knob** | `mme.s1ap_tx_workers` (default `0`) |

### Done

- [x] Inventory / funnel through `s1ap_send_to_enb`
- [x] Sticky worker per eNB (`enb->id % N`); FIFO jobs
- [x] `s1ap_tx_post_dlnas` from `nas_eps_send_to_downlink_nas_transport`
- [x] Hold sync sends while `s1ap_tx_pending > 0`; flush on TX_READY
- [x] Wire meson + `mme-init` start/stop + `MME_EVENT_S1AP_TX_READY` in `mme-sm`
- [x] Prod soak with `s1ap_rx_workers: 4` + `s1ap_tx_workers: 4` (ongoing)
- [x] Perf: DLNAS encode partly off `mme_main`; `s1ap_tx_ready_handle` ~1%

### Still open (Stage 2b)

- [ ] Offload ICSR / E-RAB / HO / paging builders (need larger snapshots)
- [x] **Dedicated S1AP SCTP send thread** (`mme.s1ap_io_thread: 1`, default 0) —
      `s1ap-io.c`: single IO thread owns every eNB socket's write side
      (per-sock FIFO, non-blocking sendmsg, POLLOUT on its own pollset).
      Socket destroy now waits for BOTH RX-unwatch and IO-drain confirms
      (close registry). Removes `sctp_write_callback` (~6.5%) from `mme_main`.
- [ ] Soak `s1ap_io_thread: 1` in prod; re-perf (expect `mme_main` ~40%→~34%)
- [ ] Longer soak: no S1 flaps / order bugs under attach churn

---

## 3. NAS integrity / cipher with key snapshot

| | |
|---|---|
| **Goal** | Run NAS security encode/decode off `mme_main` using a frozen key+count snapshot |
| **Benefit** | Moderate on attach / TAU / service request (next after Stage 2b send path) |
| **Effort** | Medium |
| **Risk** | Medium — **DL/UL count and key lifetime must stay correct** |
| **Knob** | e.g. `mme.nas_sec_workers` (default `0`) or fold into TX/RX workers |

### Tasks

- [ ] Define snapshot: K_NAS_enc/int, algos, UL/DL counts, direction
- [ ] Encode path: main prepares plaintext + snapshot → worker → ciphertext pkbuf back
- [ ] Decode path: careful with count updates (only owner commits new counts)
- [ ] No worker mutation of `mme_ue_t` security state without returning to owner
- [ ] Handle rekey / SMC / concurrent HO edge cases
- [ ] Default-off; test attach, TAU, service request, reject paths
- [ ] Perf under attach/TAU load

---

## 4. Full UE shard workers (Stage C)

| | |
|---|---|
| **Goal** | Per-UE ownership on workers (EMM/ESM/S11/S6a xacts for that UE) |
| **Benefit** | Biggest multi-core win for MME (`mme_main` FSM ~40% still) |
| **Effort** | Large |
| **Risk** | Large — same rules as SGW-C; **do not rush** |
| **Knob** | `mme.workers` (default `0`); requires `ogs_worker_shards_enable()` |

### Stage A — bounce router — LANDED (default off)

- [x] Knob `mme.workers` (0..15 since OGS_WORKER_ID_BITS=4; was 0..7); `ogs_worker_shards_enable()` before any helper worker
- [x] Sticky shard bits in MME S11 TEID + `MME_UE_S1AP_ID`
- [x] Bounce EMM/ESM/S11/S6a/timers/admin-UE to owner; eNB/SCTP/Echo stay on main
- [x] Worker dispatch = UE cases of `mme_state_operational`; narrow `mme_ctx_lock` on hash add/remove
- [x] `tools/tsan-mme.sh` injects `mme.workers: 4` (+ rx/tx/io knobs)
- [ ] TSAN soak: attach / volte / handover / transfer green, no data races
- [ ] Production YAML stays `workers: 0` until soak

### TSAN lab findings (Jul 2026, workers:4 rx:4 tx:4 io:1)

Fixed:

- [x] `s1ap-io.c` close registry + `s1ap-rx.c` owner/poll hashes: dangling
      hash keys (key memory freed while still hashed) → stable heap entries
- [x] `ogs-trace.c` / `s1ap-io.c` lazy mutex init race → explicit init
      during single-threaded startup
- [x] `ogs-queue.c`: `terminated` read outside mutex in push/pop
- [x] `enb->s1ap_tx_pending`: shard-worker increment vs main decrement →
      `__atomic` builtins
- [x] `mme_ue_set_imsi` merge: session array UAF after old-UE removal
- [x] **timer rbtree races**: UE timers started/stopped on shard workers
      while owner thread walks tree → per-manager mutex in `ogs-timer.c`;
      `ogs_timer_mgr_expire` detaches under lock, callbacks outside
- [x] **cross-shard EMM dispatch**: re-attach creates a new `enb_ue` that
      hashes to a different shard than the existing `mme_ue` (found via
      GUTI/S-TMSI/`mme_ue_find_by_message`) → two workers mutating the
      same UE (`emm_state_exception` race). Fix: `mme_worker_rehome_emm()`
      re-posts the EMM event to the owner shard before touching UE state.
- [x] **UE location update on main**: `s1ap_handle_uplink_nas_transport`
      wrote `mme_ue->tai/e_cgi` while the owner shard ran
      `emm_handle_attach_request`. Fix: TAI/E-CGI snapshot in the EMM
      event (taken on main from `enb_ue->saved`); owner applies it in
      `mme-sm.c`; attach/TAU/ext-service handlers skip the re-read of
      `enb_ue->saved` when workers are on.

**Status (Jul 19 2026): attach suite runs with zero MME TSAN reports**
(workers:4 rx:4 tx:4 io:1). The suite's remaining functional failure
(guti-test, `Line 1445`) reproduces identically with ALL knobs at 0 on
both the TSAN and regular builds → pre-existing fork/testsuite issue,
not an SMP regression. Track separately before enabling `workers` in
production; volte/csfb/handover/transfer suites still need TSAN soak.

Known remaining (accepted / TODO):

- [ ] Main thread still *reads* shard-owned `mme_ue` state in S1AP
      handlers (e.g. S-TMSI lookup + `mme_ue_is_valid_for_s1` in
      InitialUEMessage). Read-mostly; needs Stage B/C ownership handoff.
- [x] Handover paths (`path switch request`, `handover notify`):
      the tail (location write, NH chain, S11 Modify Bearer / Create
      Session) is now deferred to the UE owner shard via
      `MME_EVENT_S1AP_HO_TAIL` (`s1ap_*_complete()` split). This also
      puts the S11 GTP xact in the shard the response routes to, and
      the MBR ULI carries the new location.
- [ ] Test-harness noise: `tests/common/application.c` `test_child_create`
      races (harness, not MME) and FreeDiameter internals.

### Prerequisites (Stage C-full)

- [ ] SGW-C `workers: N` soaked in production (stable PFCP, no split-brain)
- [ ] Items 1–2 (and ideally 3) done or explicitly deferred with reason
- [ ] Stage A TSAN soak green

### Design checklist (remaining for Stage C-full)

- [x] Process-global context; **never** TLS `mme_self()`
- [ ] Shared: eNB table, config, served-TAI, IMSI→worker map (rwlock/RCU)
- [ ] Sharded: `mme_ue`, `enb_ue`, sessions, bearers, timers, S11/S6a xacts
- [x] Route after Initial UE: S1AP-id / S11 TEID bits (+ IMSI peek for TEID=0)
- [x] Embed worker id in MME_UE_S1AP_ID, S11 TEID (Diameter session id later)
- [ ] Stable `N` across restart or map + `% N` fallback for old GUTIs
- [ ] eNB-scoped events (S1 Setup, Reset, Paging): main or fan-out
- [x] All SCTP TX serialized on main/IO (`s1ap_io` / `s1ap_send_to_enb`)
- [x] Stage landing: (A) bounce router only → (B) NAS crypto → (C) full UE ownership

### Explicit non-goals until ready

- [ ] No production enable before TSAN soak
- [ ] No deploy of Stage C as a big-bang with SGWC SMP unproven
- [ ] Stage A does **not** claim “main holds no UE state” (create path still on main)

---

## 5. Per-thread pkbuf pools — LANDED (default off)

Prod perf with workers:7 rx:4 tx:4 io:1 (Jul 26): load spreads well
(mme_main ~22% of a core, shards ~6% each) but `__lll_lock_wait` is
~7% of mme_main children — every alloc/free/copy from every thread
takes the ONE default pkbuf-pool mutex.

- [x] `ogs_pkbuf_thread_pool_set()` (lib/core): opt-in TLS pool tried
      before default_pool on `ogs_pkbuf_alloc(NULL, ...)`; frees route
      via `pkbuf->pool` (cross-thread safe); exhaustion falls back
      silently to the default pool. Fixed cluster-meta leak on the
      exhaustion path; pkbuf field init moved outside the pool mutex.
- [x] Knob `mme.pkbuf_thread_pool: N` (0 = off, startup-only): attach
      in mme_main + shard/RX/TX/IO thread_init; pools destroyed LAST in
      mme_terminate (buffers cross threads, pools must outlive them).
- [ ] Prod soak with `pkbuf_thread_pool: 2048`; re-perf lll_lock_wait

---

## 6. Stage C RX→shard routing + direct TX send + multi-IO — LANDED (default off)

Feature branch `feature/stage-c-sharding`. Three knobs, all startup-only,
all default 0 (bit-identical to before when off):

- [x] `mme.stage_c` (needs `workers > 0`): RX workers classify decoded
      PDUs (`s1ap-shard.c`) — UplinkNASTransport, UECapabilityInfo,
      InitialContextSetup/UEContextModification/E-RAB-Setup responses
      carrying a valid shard prefix in MME_UE_S1AP_ID go straight to the
      owning UE shard worker; everything else (and any miss: unknown UE,
      eNB not set up, queue full) bounces to main exactly as before.
      `enb->state.s1_setup_success` reads/writes are atomic now.
- [x] `mme.s1ap_tx_direct` (needs `s1ap_tx_workers > 0` and
      `s1ap_io_thread >= 1`): TX workers post encoded DLNAS PDUs to the
      IO thread themselves (`tx_complete_direct` under `mme_ctx_lock`,
      which also flushes the per-eNB hold list) instead of round-tripping
      through main's TX_READY.
- [x] `mme.s1ap_io_thread: 0..4` (was 0/1): N send threads; sockets are
      sticky per thread (pointer hash) so per-association order holds.
- [x] Load test `tests/load` + `configs/load.yaml.in` — runs the whole
      EPC with workers:4 stage_c:1 rx:2 tx:2 tx_direct:1 io:2
      pkbuf_thread_pool:256. Scenarios: S1-Setup churn, 4-eNB parallel
      mass attach/detach (24 UEs), parallel idle/service-request/TAU,
      paging, cross-eNB idle TAU (shard rehome). eNB threads record
      failures and main asserts after join (ABTS is not thread-safe).
- [ ] Prod soak stage_c + tx_direct after test-rig green

---

## Suggested order (current)

1. ~~`mme_find_served_tai`~~ — done / confirmed in perf  
2. ~~S1AP TX DLNAS wedge~~ — landed; **finish Stage 2b** (more builders + SCTP send placement)  
3. **NAS sec snapshot** — optional; pairs with TX if already queuing NAS  
4. **Stage C UE shards** — only after SGWC soak + test rig (attacks remaining `mme_main` FSM)

## Deployment reminder

After each land: push → `git pull` on server → rebuild/install → restart **`open5gs-mmed`** (and SGWC only if shared libs/`ogs-epoll` changed).
