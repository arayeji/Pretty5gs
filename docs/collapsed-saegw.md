# Collapsed SAEGW-C (MME S11 directly to SMF)

Running the EPC without SGW-C/SGW-U: the SMF terminates the S11 interface
from the MME and acts as the combined SGW-C + PGW-C (collapsed SAEGW-C).
The UPF terminates S1-U from the eNB directly, so `open5gs-sgwcd` and
`open5gs-sgwud` are not needed. No MME code changes are required - the MME
still "selects an SGW", it just happens to be the SMF.

* **Phase 1**: local subscribers (SMF anchors the PDN connection).
* **Phase 2**: home-routed roamers (SMF plays the SGW-C role and relays
  S5/S8 to the home PGW), dedicated bearers over S11, and TAU re-anchor
  adoption.

## Configuration

SMF (`smf.yaml`):

```yaml
smf:
  collapsed: true      # accept S11 on the smf.gtpc address (default: false)
  gtpc:
    server:
      - address: 10.0.0.4
```

MME (`mme.yaml`) - point the SGW client list at the SMF GTP-C address:

```yaml
mme:
  gtpc:
    client:
      sgwc:
        - address: 10.0.0.4   # the SMF
      smf:
        - address: 10.0.0.4
```

Restart `open5gs-smfd` after changing `smf.collapsed` (not SIGHUP-reloadable).

## How it works

* **Classification**: a Create Session Request whose Sender F-TEID has
  interface type "S11 MME GTP-C" is treated as an S11 session
  (`sess->s11`). S5/S8 CSRs from a real SGW-C keep working unchanged, so
  mixed operation (some MMEs via SGW-C, some direct) is fine.
* **Per-session role decision**: the PGW S5/S8 address the MME selected is
  compared against the SMF's own (advertised) GTP-C address. Local -> the
  SMF anchors the session (PGW role). Not local -> home-routed roaming:
  the SMF plays the SGW-C role and relays to the home PGW (S8 relay,
  `sess->s11_relay`).
* **Create Session Response** carries the SMF's S11/S4 SGW F-TEID as
  sender and the UPF's S1-U F-TEID in the bearer context (S1-U SGW GTP-U
  interface type), so the eNB sends S1-U straight to the UPF.
* **Attach** (no eNB F-TEID yet): the DL FAR starts in BUFF|NOCP, exactly
  like the 5GC idle state. The Modify Bearer Request from the MME (Initial
  Context Setup / Service Request / TAU) carries the eNB F-TEID and flips
  the FAR to FORW.
* **S11 TEID quirk**: the MME uses one SGW S11 TEID per UE (not per PDN
  connection), so Delete Session / Modify Bearer / Release Access Bearers
  / bearer responses are re-targeted to the right session by EPS Bearer ID
  (or via the transaction).
* **Idle mode**: Release Access Bearers Request deactivates the DL FAR of
  every S11 session of the UE (UPF buffers). A Downlink Data Report from
  the UPF triggers a Downlink Data Notification to the MME, which pages
  the UE; the Service Request's Modify Bearer Request reactivates DL.
* **GTP-U Error Indication** from the eNB (reported by the UPF) mirrors
  SGW-C behaviour: DL is deactivated and a DDN with cause "Error
  Indication received" is sent, so the MME releases the S1 context and
  re-pages.

## Phase 2: home-routed roaming (S8 relay)

When the MME's PGW selection names a non-local PGW (HSS MIP6 Home Agent or
a `pgw_selection` rule), the SMF becomes a pure SGW-C for that session
(`src/smf/s11-relay.c`):

* **Control plane**: the S11 Create Session Request is rewritten in place
  into an S5/S8 CSR (sender F-TEID -> SGW S5/S8-C, bearer S5/S8-U SGW
  F-TEID from the UPF) and sent to the home PGW; the PGW's response is
  rewritten back to the MME (sender -> S11/S4 SGW F-TEID, bearer S1-U SGW
  F-TEID). Delete Session is relayed the same way, and PGW-initiated
  Update/Delete Bearer Requests pass through 1:1 in both directions.
* **User plane**: the UPF is programmed as a GTP-U forwarder - no UE IP,
  no Gx/Gy. UL: PDR (access, UPF-chosen F-TEID) -> FAR towards the home
  PGW S5/S8-U. DL: PDR (core, second UPF-chosen F-TEID) -> FAR towards
  the eNB (buffering until the eNB F-TEID is known). The UPF skips the
  source-IP spoofing check for FARs targeting S5/S8-U, like it already
  does for N9-for-roaming (the forwarder does not know the UE IP).
* **Idle mode / DDN / Error Indication** reuse the `sess->s11` paths.
* **Teardown**: S11 DSR -> S5 DSR -> PGW response -> PFCP session
  deletion -> S11 response. A PGW-initiated Delete Bearer Request for the
  default bearer tears the PDN down after the MME's response is relayed.

## Phase 2: dedicated bearers over S11

`smf_bearer_binding` creates dedicated bearers for S11 sessions too. The
Create Bearer Request carries the SGW S1-U F-TEID (instance 0, same UPF
F-TEID as the PGW S5/S8-U retyped as S1-U SGW GTP-U); the response's eNB
F-TEID (instance 0) programs the DL FAR. PGW-initiated Create Bearer
Requests towards relay sessions are rejected for now (Phase 2 relay covers
Update/Delete Bearer pass-through).

## Phase 2: TAU re-anchor adoption

An S11 Create Session Request that carries a PGW S5/S8 F-TEID matching an
existing session (our own per-session TEID for anchored sessions, or the
learned home-PGW TEID for relay sessions) with the same IMSI is an
inter-MME/SGW-relocation TAU, not a new PDN connection: the session is
adopted (MME endpoint updated, DL FAR re-pointed or buffered) and answered
from the existing context.

## Limitations

* PGW-initiated Create Bearer Request in relay mode is rejected
  ("Service not supported").
* Indirect data forwarding tunnels (S1-based handover) are untested.

## Tests

`tests/collapsed/` runs the standard attach scenarios (S1 setup, attach +
GTP-U ping, GUTI re-attach + TAU, idle/paging/Release Access Bearers/Error
Indication) plus the S8-relay roaming scenario against
`configs/collapsed.yaml.in`, which sets `no_sgwc`/`no_sgwu` and points
`mme.gtpc.client.sgwc` at the SMF.

The relay scenario uses a loopback home PGW: the SMF binds a second GTP-C
address (127.0.1.4) that is not its advertised one; a forced MME
`pgw_selection` entry steers the test roamer's IMSI prefix there, so the
SMF relays S5/S8 to itself and anchors the session in its normal PGW role.
The user plane traverses the UPF twice (eNB -> relay -> anchor -> ogstun).

```
./build/tests/collapsed/collapsed
```
