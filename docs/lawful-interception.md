# Lawful Interception (HI1 / HI2 / HI3)

Pretty5GS adds a lab-grade LI stack aligned with 3GPP TS 33.127/33.128 and
ETSI TS 102 232 (JSON transport profile for development; production LEMF
integrations typically require ASN.1 BER per TS 33.108).

## Architecture

```
LEA ──HI1──► open5gs-admfd (ADMF + MDF2)
                │
                ├──X1──► MME/SMF  :9090/admin/li/target
                │
                ◄──X2──  MME/SMF  POST /mdf/x2
                │
                └──HI2──► /var/spool/open5gs/hi2/  (LEMF pickup)

UPG-VPP (SGW-U/UPF) ──X3──► MDF3 ──HI3──► LEMF   [external to Pretty5GS]
```

| Component | Daemon | Interface |
|-----------|--------|-----------|
| ADMF + MDF2 | `open5gs-admfd` | HI1 admin, X2 ingest, HI2 spool |
| MME IRI-POI | `open5gs-mmed` | X1 target table, X2 on attach/detach |
| SMF IRI-POI | `open5gs-smfd` | X1 target table, X2 on session create/release |
| CC-POI | **upg-vpp** | X3 user-plane mirror → HI3 (see below) |

## HI1 — activate an intercept

```bash
curl 'http://127.0.0.1:9051/hi1/intercepts?action=add&liid=CASE-001&imsi=001010000000001'
curl 'http://127.0.0.1:9051/hi1/intercepts?action=list'
curl 'http://127.0.0.1:9051/hi1/intercepts?action=remove&liid=CASE-001'
```

ADMF stores the target, pushes **X1** to MME and SMF admin APIs, and returns
the assigned **CIN** (correlation ID).

## HI2 — signaling delivery

When a target UE attaches or a PDN session is created, the POI sends **X2**
JSON to ADMF (`POST /mdf/x2`). MDF2 wraps it as **HI2** and writes:

`/var/spool/open5gs/hi2/hi2-<timestamp>.json`

A test LEMF or SIEM can tail this directory.

### Enable POIs

```yaml
# mme.yaml
mme:
  li:
    enabled: true
    mdf:
      addr: 127.0.0.1
      port: 9051

# smf.yaml
smf:
  li:
    enabled: true
    mdf:
      addr: 127.0.0.1
      port: 9051
```

## HI3 — why UPG-VPP, not Pretty5GS

**HI3 is content of communication (user IP packets).** It must be mirrored in
the **user-plane** function where GTP-U traffic flows.

Pretty5GS deployments using `global.parameter.use_upg_vpp: true` send PFCP to
**upg-vpp** as SGW-U/UPF. Therefore:

- **X3 / CC mirroring belongs in upg-vpp** (or another UPF), not in
  `open5gs-upfd` alone.
- Pretty5GS **SMF** should pass LI target identity to the UPF when X1 tasking
  is active (PFCP vendor IE or upg-vpp LI API — integration point TBD).
- **MDF3** and **HI3 delivery to LEMF** remain a separate mediation step,
  same as commercial LI platforms.

### Recommended HI3 integration path

1. ADMF provisions the same `liid`/IMSI to upg-vpp (REST/gRPC or config push).
2. upg-vpp mirrors matched GTP-U frames to MDF3 (X3).
3. MDF3 formats HI3 per ETSI TS 102 232-5 and delivers to LEMF.

Pretty5GS documents and tests HI1/HI2 end-to-end; HI3 is an **upg-vpp +
MDF3** deliverable.

## Build and run

```bash
./build.sh
sudo mkdir -p /var/spool/open5gs/hi2
sudo open5gs-admfd -c /etc/open5gs/admf.yaml
```

Rebuild/restart after pull: **open5gs-admfd**, **open5gs-mmed**, **open5gs-smfd**.

## Standards map

| Topic | Spec |
|-------|------|
| LI architecture | 3GPP TS 33.127 |
| Stage-3 X1/X2/X3 | 3GPP TS 33.128, ETSI TS 103 221 |
| HI2/HI3 handover | 3GPP TS 33.108, ETSI TS 102 232 |
| HI1 administration | ETSI TS 101 671 (national profiles vary) |
