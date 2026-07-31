# Equivalent PLMN (EPLMN) — MME

## What it does

When configured, the Open5GS MME includes the **Equivalent PLMNs** optional IE (type `0x4A`, TLV) in **Attach Accept** (EMM `0x42`) and **Tracking Area Update Accept** (EMM `0x49`). UEs store this list per 3GPP TS 24.301 §9.9.3.18 and TS 23.122 §3.1 so that mobility and PLMN selection treat the listed PLMNs as equivalent to the registered PLMN (RPLMN).

The list is **local MME configuration only** in this release (no S6a/HSS AVP).

## Configuration

Add under `mme:` in `mme.yaml` (max **15** PLMNs):

```yaml
mme:
  attach_accept:
    equivalent_plmn: true
    equivalent_plmn_serving_only: true   # default: true (Huawei-like)
    # optional: send EPLMN only when UE matches access_control and TAC is allowed
    equivalent_plmn_access_control_tac: false
  equivalent_plmn:
    - { mcc: 999, mnc: 71 }
    - { mcc: 999, mnc: 35 }
  # used when equivalent_plmn_access_control_tac is true (existing ACL; no dedicated TAC list)
  access_control:
    - imsi_prefix: "43235"
      tac: [1234, 1235]
```

When `attach_accept.equivalent_plmn_serving_only` is **enabled** (default), the MME matches the UE’s **IMSI home PLMN** (not the visited/serving TAI PLMN) against the configured list. If the IMSI PLMN is listed (e.g. IMSI `43211…` and `{ mcc: 432, mnc: 11 }`), **only that PLMN** is sent in Attach/TAU Accept. If there is no match, the full list is sent.

When `attach_accept.equivalent_plmn_access_control_tac` is **enabled** (default: **false**), the EPLMN IE is included only if:

1. The UE matches an `access_control` entry (same IMSI-prefix / PLMN match as inbound roam), and
2. That entry has **no** `tac` list, **or** the UE’s current TAC is in that entry’s `tac` list.

No match → omit EPLMN. eNB-ID allow-lists are not used for this gate. Flat alias: `mme.equivalent_plmn_access_control_tac` (SIGHUP).

Set `attach_accept.equivalent_plmn: false` to omit the EPLMN IE even when `equivalent_plmn:` is configured.

If `equivalent_plmn` is omitted or empty, the IE is **not** sent.

Startup fails with `ogs_error()` if there are more than 15 entries or an entry lacks `mcc`/`mnc`.

## Log lines to expect

**MME at startup** (when EPLMNs are configured):

```
Equivalent PLMNs configured: 2
  EPLMN[0]: MCC=999 MNC=71
  EPLMN[1]: MCC=999 MNC=35
Attach/TAU Accept NAS options:
  equivalent_plmn: enabled
  equivalent_plmn_serving_only: enabled
  equivalent_plmn_access_control_tac: disabled
```

**MME on attach/TAU** (debug):

```
    Equivalent PLMNs[1/2] included in Attach Accept (IMSI[43211…] serving_only:1)
```

## Wire verification (tshark)

Capture S1AP/NAS on the MME–eNB SCTP association (default port **36412**):

```bash
tshark -i any -f "sctp port 36412" \
  -Y "nas-eps.emm.msg_type == 0x42 || nas-eps.emm.msg_type == 0x49" \
  -V 2>&1 | grep -B1 -A20 "Equivalent PLMN"
```

Attach Accept is `0x42`, TAU Accept is `0x49`. You should see the IE with your configured PLMNs (3 octets per PLMN).

## Unit tests

```bash
meson compile -C build unit
meson test -C build unit --suite unit
```

Covers YAML parsing (0, 1, 8, 15, 16 entries; malformed entry) and NAS PLMN packing (2- and 3-digit MNC).
