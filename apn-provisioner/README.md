# apn-provisioner

A passive service that watches S1 signalling for LTE attaches and sends an OMA
Client Provisioning (OTA APN settings) SMS to subscribers **who did not set an
APN themselves**, with per-IMEI change detection and rate limiting.

The trigger lives **inside the MME**, where the attach and the APN decision
already happen; this service does the SMS work off to the side. The MME sends a
small **datagram** (not a log line) for each eligible attach, and this service
reads the HSS **read-only** and sends via `submit_sm` to the MSC's SMPP server.
It never injects S1 traffic, never writes the HSS, and never restarts or
reconfigures any production service. The datagram send is non-blocking
(fire-and-forget), so it cannot load or stall MME call processing, and nothing
is written to journald/disk.

---

## What it does, end to end

```
MME (Attach Complete) ──datagram──► apn-provisioner ──► decision ──► SMPP send
  per-PLMN rule, no-APN gate       (UNIX/UDP socket)   (HSS read-only) (concatenated)
```

The MME (`src/mme/mme-provisioning-sms.c`) already runs at Attach Complete. With
`delivery: event` it sends one datagram per eligible attach — **only** for UEs
whose Attach Request carried **no APN IE** (`sess->ue_provided_apn == false`) and
whose home PLMN matches a configured rule. The payload is one NUL-free line:

```
event=attach imsi=<imsi> msisdn=<msisdn> imei=<imei15> imeisv=<imeisv> mcc=<d> mnc=<d> apn_absent=1
```

sent over a UNIX-domain datagram socket (same host) or UDP (remote host). The
MME has already resolved IMSI/IMEISV/MSISDN, so no S1AP/NAS decoding or
GUTI→IMSI guessing is needed here. For each event this service:

1. **Subscriber lookup** (default APN + MSISDN) from the HSS; the MME-supplied
   MSISDN is used as a fallback if the HSS record lacks one. Skipped if absent.
2. **Change / rate decision:** new subscriber → send; IMEI changed → send
   (ignoring a change in the SV digits alone); last send older than
   `resend_interval` → send; otherwise skip.
3. **Rate limiting + circuit breaker**, then build the CP document with that
   subscriber's APN and IMSI-derived NETWPIN MAC, and send as concatenated SMPP
   segments.

Every decision (sent / skipped-why / failed-why) is logged with IMSI, IMEI, APN
and segment count. Counters are logged periodically.

---

## MME side (the trigger)

The trigger is a per-PLMN rule in the MME's `mme.provisioning_sms` config. The
MME feature (`src/mme/mme-provisioning-sms.c`) supports two delivery modes:

- `delivery: s1` (default, pre-existing) — the MME itself builds a binary OMA CP
  MT SMS and sends it over S1 Downlink NAS, tracking IMEI changes in MongoDB.
- `delivery: event` — the MME sends a **fire-and-forget datagram** to **this**
  service, which handles the send over SMPP. No logs, no MongoDB, no S1 SMS;
  change-detection and rate limiting live here. The datagram target is a
  UNIX-domain socket (`event_socket`, same host) or `host:port` for UDP
  (`event_addr`, remote host).

Both honour `require_no_apn` (default `true`): only UEs whose Attach Request
carried **no APN IE** are eligible — the MME reads `sess->ue_provided_apn`, which
its ESM handler sets to `false` exactly when the APN IE was absent/empty.

Example `mme.yaml` (same-host UNIX socket):

```yaml
mme:
  provisioning_sms:
    rules:
      - imsi_plmn_id: { mcc: 432, mnc: 12 }              # per-PLMN
        delivery: event                                  # hand off via datagram
        require_no_apn: true                             # only UEs with no APN IE
        event_socket: /run/apn-provisioner/events.sock   # or event_addr: "10.0.0.9:5005"
```

This service binds that socket and receives the datagrams:

| mode             | when to use |
|------------------|-------------|
| `mme_event_unix` | **production, same host** — bind `event_socket` (must equal the rule's `event_socket`) |
| `mme_event_udp`  | **production, remote host** — bind `event_bind_addr` (matches the rule's `event_addr`) |
| `pcap_replay`    | offline decoder bring-up — finite replay of one pcap |
| `pcap_tail`      | offline decoder fallback — tail rotated pcap files |

The provisioner:
- processes events in near-real-time (target < 5 s from attach),
- survives MME restarts without duplicating sends (per-IMSI de-dup + persisted
  state; datagram drops are re-fired on the next attach),
- never runs its own S1 capture, and never touches the MME log volume.

---

## Identities come from the MME (no GUTI→IMSI problem)

The IMSI is absent from most attaches on the air interface (GUTI/S-TMSI
re-attach), but the MME has already resolved IMSI, IMEISV and MSISDN from its own
context, and puts them directly in the event datagram. So there is no
GUTI→IMSI resolution to do here.

A self-learned GUTI→IMSI map (SQLite `guti_map`) and the S1AP/NAS decoder are
retained only for the **offline pcap modes**, where no MME context exists — there
we resolve via the learned map and, if a GUTI-only attach is unresolved, **skip
and log** (`guti_unresolved`) rather than guess a wrong IMSI (wrong MAC key →
handset silently rejects). These paths are unused in the `mme_event_*` modes.

---

## Ciphering is a non-issue in production

Identities in the event datagram come from the MME, which terminates NAS and
therefore always has the cleartext IMSI, IMEISV, MSISDN and the APN-IE-presence
flag regardless of `ciphering_order`. So the EEA0-vs-EEA1/2/3 concern that
affects passive capture does **not** apply to the production event path.

It only matters for the **offline pcap decoder** (`pcap_*` modes): passive S1
decoding of IMEISV/APN needs NAS to be unciphered (EEA0). The decoder detects
undecodable NAS (`decode_error`) and skips (`apn_unknown`) rather than guess.
Confirm with `tshark -r s1.pcap -Y 'nas-eps.emm.msg_type == 0x5e' -V | grep -i imeisv`.

---

## Install

```bash
sudo useradd --system --home /opt/apn-provisioner --shell /usr/sbin/nologin apnprov
sudo mkdir -p /opt/apn-provisioner /etc/apn-provisioner /var/lib/apn-provisioner
sudo chown -R apnprov:apnprov /var/lib/apn-provisioner

# code + venv
sudo cp -r apn_provisioner /opt/apn-provisioner/
python3 -m venv /opt/apn-provisioner/.venv
/opt/apn-provisioner/.venv/bin/pip install -r requirements.txt

# config (fill in real endpoints/credentials — never commit config.yaml)
sudo cp config.example.yaml /etc/apn-provisioner/config.yaml
sudo $EDITOR /etc/apn-provisioner/config.yaml

sudo cp systemd/apn-provisioner.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Run (dry-run first)

Dry-run **builds + validates + logs the hex and sends nothing**:

```bash
/opt/apn-provisioner/.venv/bin/python -m apn_provisioner \
    --config /etc/apn-provisioner/config.yaml --dry-run
```

Prove it before enabling sends: configure a `delivery: event` rule on the MME
(with `event_socket` pointing at this service's socket), watch the event
datagrams arrive, and confirm this service's own log shows correct IMSI / IMEI /
APN and `DRY-RUN would send ...` lines with zero messages sent. Then set
`dry_run: false` and `systemctl enable --now apn-provisioner`.

> Enabling live sends and any service restart require explicit operator sign-off.

---

## Testing & acceptance gate

```bash
pip install -r requirements.txt
python -m pytest            # unit tests (offline)
```

Covered: IMSI→key derivation (incl. the OMA worked example
`310170212226432 → 3901712021224623`), CP/WBXML byte golden + WSP + segmentation,
NAS decode (IMSI, GUTI re-attach, IMEISV, no-IMEISV, **APN-IE presence**), S1AP
decode + correlation, decision gates, rate limiter / circuit breaker, subscriber
selection, and an end-to-end dry-run over a synthetic pcap.

**Authoritative acceptance gate (run where tshark and the reference exist):**
1. `tshark` validation of the produced WSP PDU (the section-2.6 harness) — the
   `test_validator.py::test_tshark_validation_optional` test runs it
   automatically when `tshark` is installed (it auto-skips otherwise).
2. **Byte-diff the WBXML against the on-server reference** `/tmp/send_multi.py`
   on `THR1MSC01`. The builder output is pinned in
   `test_cp_builder.py::test_wbxml_golden_bytes`; confirm it matches the proven
   sender before enabling live sends.
3. Drop real captures into `tests/fixtures/pcaps/real/` and run
   `pytest tests/test_real_pcaps.py -s`.

---

## Rollback

- **Stop sending immediately:** `sudo systemctl stop apn-provisioner` (passive —
  stopping it cannot affect the MME/MSC/HSS). Or set `dry_run: true` and restart
  to keep observing without sending.
- **Full removal:** `systemctl disable --now apn-provisioner`, remove the unit
  and `/opt/apn-provisioner`. The only external side effect it ever produced was
  outbound provisioning SMS; there is nothing to undo in the MME/HSS.
- **State:** delete `/var/lib/apn-provisioner/state.db` to reset change-detection
  and the GUTI→IMSI map (it will relearn).
- The circuit breaker auto-stops sending if volume exceeds `breaker_per_min`
  (guards against an attach storm becoming an SMS storm) and resumes only once
  the rate falls below `breaker_resume_per_min`.

---

## Configuration reference

See `config.example.yaml`. Notable knobs: `resend_interval_hours` (24),
`send_on_imei_change` (true), `ignore_sv_change` (true),
`correlation_timeout_sec` (60), `dedup_window_sec` (60),
`max_sends_per_sub_per_day`, `global_max_per_sec`, `breaker_per_min`,
`breaker_resume_per_min`, `dry_run`.
