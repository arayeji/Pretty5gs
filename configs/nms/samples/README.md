# NMS sample configurations (fictional data only)

These files mirror the layout of **`/etc/open5gs/<daemon>.yaml`** on a live node.
All PLMNs, IMSIs, IP addresses, secrets, and hostnames are **placeholders** for
schema mapping and lab use — not real operator data.

| File | systemd unit | SIGHUP reload |
|------|--------------|---------------|
| [mme.yaml](mme.yaml) | `open5gs-mmed` | yes (see [docs/nms-sighup-reload.md](../../../docs/nms-sighup-reload.md)) |
| [smf.yaml](smf.yaml) | `open5gs-smfd` | yes |
| [sgwc.yaml](sgwc.yaml) | `open5gs-sgwcd` | yes |
| [sgwu.yaml](sgwu.yaml) | `open5gs-sgwud` | no — restart |
| [upf.yaml](upf.yaml) | `open5gs-upfd` | no — restart |
| [amf.yaml](amf.yaml) | `open5gs-amfd` | no — restart |
| [hss.yaml](hss.yaml) | `open5gs-hssd` | no — restart |
| [pcrf.yaml](pcrf.yaml) | `open5gs-pcrfd` | no — restart |
| [nrf.yaml](nrf.yaml) | `open5gs-nrfd` | no — restart |
| [scp.yaml](scp.yaml) | `open5gs-scpd` | no — restart |
| [ausf.yaml](ausf.yaml) | `open5gs-ausfd` | no — restart |
| [udm.yaml](udm.yaml) | `open5gs-udmd` | no — restart |
| [pcf.yaml](pcf.yaml) | `open5gs-pcfd` | no — restart |
| [nssf.yaml](nssf.yaml) | `open5gs-nssfd` | no — restart |
| [bsf.yaml](bsf.yaml) | `open5gs-bsfd` | no — restart |
| [udr.yaml](udr.yaml) | `open5gs-udrd` | no — restart |
| [cgf.yaml](cgf.yaml) | `open5gs-cgfd` | no — restart |

## Fictional lab addressing

| Role | IPv4 | Notes |
|------|------|-------|
| MME | 127.0.0.2 | S1-MME, S11, metrics :9090 |
| SGWC | 127.0.0.3 | S11, S5, PFCP, Gn, metrics :9090 |
| SMF | 127.0.0.4 | S5, PFCP, SBI :7777, metrics :9090 |
| AMF | 127.0.0.5 | NGAP, SBI :7777 |
| SGW-U | 127.0.0.6 | PFCP + GTP-U |
| UPF | 127.0.0.7 | PFCP + GTP-U, metrics :9090 |
| HSS | 127.0.0.8 | S6a Diameter |
| PCRF | 127.0.0.9 | Gx Diameter |
| NRF | 127.0.0.10 | SBI :7777 |
| AUSF | 127.0.0.11 | SBI :7777 |
| UDM | 127.0.0.12 | SBI :7777 |
| PCF | 127.0.0.13 | SBI :7777 |
| NSSF | 127.0.0.14 | SBI :7777 |
| BSF | 127.0.0.15 | SBI :7777 |
| UDR | 127.0.0.20 | SBI :7777 |
| SCP | 127.0.0.200 | SBI :7777 |
| RADIUS AAA | 127.0.0.99 | SMF RADIUS (fictional) |

**PLMN:** MCC `999`, MNC `70` (and visitor PLMNs `999/71`, `999/72` where shown).  
**Sample IMSI prefix:** `999700000000001` (trace / ACL examples only).

## Deploy on a lab host

Copy one file per daemon (do not merge into a single YAML — each process reads its own file):

```bash
sudo cp configs/nms/samples/mme.yaml  /etc/open5gs/mme.yaml
sudo cp configs/nms/samples/smf.yaml  /etc/open5gs/smf.yaml
# … etc.
```

Adjust `freeDiameter:` paths and MongoDB `db_uri` for your install prefix.
Diameter peer `.conf` files live under `/etc/open5gs/freeDiameter/` (see upstream install).

## Related docs

- SIGHUP reload matrix: [docs/nms-sighup-reload.md](../../../docs/nms-sighup-reload.md)
- Operator summary: [README.md](../../../README.md) (runtime reload sections)
- Shorter NMS field references (MME/SMF/SGWC only): [../mme-reference.yaml](../mme-reference.yaml), [../smf-reference.yaml](../smf-reference.yaml), [../sgwc-reference.yaml](../sgwc-reference.yaml)
