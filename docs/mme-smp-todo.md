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

---

## 1. `mme_find_served_tai` — hash / index — DONE

Landed: process-global PLMN+TAC hash; writers invalidate; list1 ranges
still scanned with lowest-entry-index-wins. Re-perf after install to
confirm ~2.6% self is gone.

---

## 2. S1AP encode + TX queue — DONE (DLNAS wedge)

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

### Still open (Stage 2b)

- [ ] Offload ICSR / E-RAB / HO / paging builders (need larger snapshots)
- [ ] Soak with `s1ap_rx_workers` + `s1ap_tx_workers` both > 0
- [ ] Perf: confirm DLNAS `ogs_asn_encode` leaves `mme_main`

---

## 3. NAS integrity / cipher with key snapshot

| | |
|---|---|
| **Goal** | Run NAS security encode/decode off `mme_main` using a frozen key+count snapshot |
| **Benefit** | Moderate on attach / TAU / service request |
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
| **Benefit** | Biggest multi-core win for MME |
| **Effort** | Large |
| **Risk** | Large — same rules as SGW-C; **do not rush** |
| **Knob** | e.g. `mme.workers` (default `0`); requires `ogs_worker_shards_enable()` |

### Prerequisites

- [ ] SGW-C `workers: N` soaked in production (stable PFCP, no split-brain)
- [ ] Items 1–2 (and ideally 3) done or explicitly deferred with reason
- [ ] Test rig: `tests/` green with `mme.workers: 2` under **TSAN** (and ASAN)

### Design checklist

- [ ] Process-global context; **never** TLS `mme_self()`
- [ ] Shared: eNB table, config, served-TAI, IMSI→worker map (rwlock/RCU)
- [ ] Sharded: `mme_ue`, `enb_ue`, sessions, bearers, timers, S11/S6a xacts
- [ ] Route after Initial UE: `hash(IMSI)` / M-TMSI worker bits / `MME_UE_S1AP_ID` bits
- [ ] Embed worker id in MME_UE_S1AP_ID, S11 TEID, Diameter session id (bit plan vs 3GPP reserved bits)
- [ ] Stable `N` across restart or map + `% N` fallback for old GUTIs
- [ ] eNB-scoped events (S1 Setup, Reset, Paging): main or fan-out
- [ ] All SCTP TX serialized on main/IO
- [ ] Stage landing: (A) bounce router only → (B) NAS crypto → (C) full UE ownership

### Explicit non-goals until ready

- [ ] No production enable before TSAN soak
- [ ] No deploy of Stage C as a big-bang with SGWC SMP unproven

---

## Suggested order

1. **`mme_find_served_tai`** — small, measurable, no new threads  
2. **S1AP encode + TX queue** — pairs with existing RX offload  
3. **NAS sec snapshot** — optional; can merge with (2) if TX path already queues NAS  
4. **Stage C UE shards** — only after SGWC soak + test rig  

## Deployment reminder

After each land: push → `git pull` on server → rebuild/install → restart **`open5gs-mmed`** (and SGWC only if shared libs/`ogs-epoll` changed).
