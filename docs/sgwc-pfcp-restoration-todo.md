# SGW-C PFCP / SGW-U restart restoration TODO

Follow-ups from the Pretty5GS SGW-C audit against TS 23.007 / TS 29.244
(SGW-U restart while SGW-C survives).

Standards caveats:

- 3GPP does **not** require every SGW-C to implement PFCP session restoration.
  When restoration **is** implemented, follow 23.007 16.1A.4 / 29.244 RESTI rules.
- Peer cleanup after restore failure (Delete Bearer / Delete Session) is
  **design hardening** for consistent CP state, not a hard “shall”.

---

## Priority order

1. RESTI on the wire (FTUP compliance)
2. Restart vs heartbeat-timeout separation
3. Association Setup RTS alignment (23.007 19A)
4. Pacing / retry / backoff
5. Restore response validation
6. Post-failure cleanup policy
7. Metrics / logging
8. Tests

---

## 1. RESTI on the wire — compliance

| | |
|---|---|
| **Goal** | Encode `PFCPSEReq-Flags.RESTI` when restoring FTUP sessions |
| **Why** | Internal `OGS_PFCP_CREATE_RESTORATION_INDICATION` is set, but Sxa builder never puts RESTI on the wire; SGW-U skips TEID swap / restore path |
| **Ref** | TS 23.007 16.1A.4; TS 29.244 7.5.2.1 / 8.2.136 |
| **Effort** | Small |
| **Risk** | Low — mirror SMF `n4-build.c` |

- [ ] Pass `xact` (or flags) into `sgwc_sxa_build_session_establishment_request()`
- [ ] Set `pfcpsereq_flags.restoration_indication = 1` when
      `OGS_PFCP_CREATE_RESTORATION_INDICATION` is set (same pattern as
      `src/smf/n4-build.c`)
- [ ] Confirm SGW-U takes `ogs_pfcp_pdr_swap_teid` / restoration TEID hash path
- [ ] Verify existing S1-U / S5-U F-TEIDs are reused (no peer GTP update needed)

---

## 2. Restart detection vs temporary PFCP loss

| | |
|---|---|
| **Goal** | Do not treat heartbeat timeout alone as confirmed SGW-U restart |
| **Why** | Re-association without Session Retention deletes UP sessions (29.244 6.2.6.2.2) even if UP state was intact |
| **Effort** | Medium |
| **Risk** | Medium — behaviour change on path flaps |

- [ ] Confirmed restart: Recovery Time Stamp **increase** on Heartbeat
- [ ] Heartbeat timeout / path loss: suspect / retry path only; do not set
      `restoration_required` until RTS advances (or explicit policy)
- [ ] Document operator policy if forced re-assoc without confirmed restart

---

## 3. Association Setup RTS (TS 23.007 19A)

| | |
|---|---|
| **Goal** | Align with “shall ignore Recovery Timestamp in Assoc Setup Req/Rsp” |
| **Why** | Open5GS currently updates RTS from Association Setup and can set
      `restoration_required` |
| **Effort** | Small |
| **Risk** | Low–medium — rely on Heartbeat for restart detection |

- [ ] Store Assoc Setup RTS if empty / for display, but do not drive
      `restoration_required` from it
- [ ] Keep Heartbeat (and Session Est. if used) as the restart signal

---

## 4. Restoration pacing / retry / backoff

| | |
|---|---|
| **Goal** | Avoid PFCP restore storms after SGW-U recovery |
| **Why** | Current path fans out Session Establishment for every owned session
      with no batching |
| **Effort** | Medium |
| **Risk** | Medium — restore latency vs overload trade-off |

- [ ] Per-UP restore state: `idle | reassociating | restoring | degraded`
- [ ] Batch size + inter-batch delay
- [ ] Per-session retry with backoff and max attempts
- [ ] Skip restore under maintenance/drain (already present — keep)

---

## 5. Restore response validation

| | |
|---|---|
| **Goal** | Explicitly handle accept / reject / timeout on restore Establishment |
| **Why** | Restore path today mainly stores new UP F-SEID; weak cause / TEID checks |
| **Effort** | Medium |
| **Risk** | Low |

- [ ] Check PFCP cause on restore response
- [ ] Confirm TEID consistency (no silent new TEID without peer update)
- [ ] Map reject (e.g. restoration resource unavailable) to retry then fail path

---

## 6. Post-failure cleanup policy — hardening

| | |
|---|---|
| **Goal** | Avoid blackholed S11/S5 contexts when restore cannot complete |
| **Why** | Not a 3GPP shall; needed for consistent control-plane state |
| **Effort** | Medium |
| **Risk** | Medium — may trigger UE reattach |

- [ ] Define policy after max restore attempts (timeout / reject)
- [ ] Optional: Delete Bearer toward MME; Delete Session toward PGW if needed
- [ ] Local UE / bearer / PFCP context purge
- [ ] Reuse patterns from `sgwc_peer_restart_purge_owned` where appropriate

---

## 7. Metrics and logging

- [ ] RTS old → new on peer restart
- [ ] RESTI sent count
- [ ] Restore started / success / fail / timeout
- [ ] Batch progress (pending / done / failed per UP)

---

## 8. Tests

- [ ] Unit: RTS compare; RESTI IE encoding; idle FAR BUFF→DROP prep; batch scheduler
- [ ] Integration: kill SGW-U → new RTS → Assoc → Session Est. with RESTI →
      same TEIDs → UL/DL without reattach
- [ ] Failure injection: restore reject; restore timeout; HB loss with same RTS;
      mid-Modify restart; large-session storm

---

## Key code pointers

| Area | Path |
|---|---|
| RTS compare | `lib/pfcp/handler.c` (`ogs_pfcp_cp_update_recovery_time_stamp`) |
| SGW-C PFCP FSM | `src/sgwc/pfcp-sm.c` |
| Restore loop | `src/sgwc/context.c` (`sgwc_pfcp_restoration_owned`) |
| Establish send | `src/sgwc/pfcp-path.c` |
| Sxa builder (RESTI missing) | `src/sgwc/sxa-build.c` |
| SMF RESTI reference | `src/smf/n4-build.c` |
| SGW-U RESTI accept | `src/sgwu/sxa-handler.c` |
