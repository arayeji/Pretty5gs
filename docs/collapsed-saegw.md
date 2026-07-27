# Collapsed SAEGW-C (MME S11 directly to SMF)

Phase 1 of running the EPC without SGW-C/SGW-U: the SMF terminates the
S11 interface from the MME and acts as the combined SGW-C + PGW-C
(collapsed SAEGW-C). The UPF terminates S1-U from the eNB directly, so
`open5gs-sgwcd` and `open5gs-sgwud` are not needed for local subscribers.
No MME code changes are required - the MME still "selects an SGW", it just
happens to be the SMF.

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
  compared against the SMF's own GTP-C address. If it is not local, the
  session would be home-routed roaming (SGW-C relay role) - that is
  phase 2 and is currently **rejected** with "No resources available", so
  inbound-roamer MME traffic must keep using a real SGW-C for now.
* **Create Session Response** carries the SMF's S11/S4 SGW F-TEID as
  sender and the UPF's S1-U F-TEID in the bearer context (S1-U SGW GTP-U
  interface type), so the eNB sends S1-U straight to the UPF.
* **Attach** (no eNB F-TEID yet): the DL FAR starts in BUFF|NOCP, exactly
  like the 5GC idle state. The Modify Bearer Request from the MME (Initial
  Context Setup / Service Request / TAU) carries the eNB F-TEID and flips
  the FAR to FORW.
* **S11 TEID quirk**: the MME uses one SGW S11 TEID per UE (not per PDN
  connection), so Delete Session / Modify Bearer / Release Access Bearers
  are re-targeted to the right session by EPS Bearer ID.
* **Idle mode**: Release Access Bearers Request deactivates the DL FAR of
  every S11 session of the UE (UPF buffers). A Downlink Data Report from
  the UPF triggers a Downlink Data Notification to the MME, which pages
  the UE; the Service Request's Modify Bearer Request reactivates DL.
* **GTP-U Error Indication** from the eNB (reported by the UPF) mirrors
  SGW-C behaviour: DL is deactivated and a DDN with cause "Error
  Indication received" is sent, so the MME releases the S1 context and
  re-pages.

## Phase 1 limitations

* Home-routed roamers (PGW not local) are rejected - keep SGW-C for them.
* Dedicated bearers over S11 are not created (logged and skipped in
  bearer binding); default bearer service is unaffected.
* Indirect data forwarding tunnels (S1-based handover) are untested.

## Tests

`tests/collapsed/` runs the standard attach scenarios (S1 setup, attach +
GTP-U ping, GUTI re-attach + TAU, idle/paging/Release Access Bearers/Error
Indication) against `configs/collapsed.yaml.in`, which sets
`no_sgwc`/`no_sgwu` and points `mme.gtpc.client.sgwc` at the SMF:

```
./build/tests/collapsed/collapsed
```
