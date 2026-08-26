# Real S1 capture fixtures (not committed)

Drop real S1 captures from this network here as `*.pcap` / `*.pcapng`. They are
**gitignored** because they may contain subscriber identities.

`tests/test_real_pcaps.py` auto-discovers files in this folder and runs the full
decode pipeline over them (it auto-skips when the folder is empty, so CI in the
dev environment still passes).

Capture on the MME host (THR1EPC01), S1 only, without running a second competing
capture on the same interface — prefer exporting from the existing ptrace feed.
For a one-off validation capture:

```
# S1AP is SCTP on port 36412 between the eNBs and the MME
tcpdump -i <s1-iface> -w s1.pcap 'sctp port 36412'
```

Aim to include at least these four scenarios (spec deliverable):
- initial attach carrying the IMSI
- re-attach using GUTI/S-TMSI (no IMSI in the clear)
- Security Mode Complete carrying IMEISV
- an attach with no IMEISV available

Then run, on a host with the venv:

```
python -m pytest tests/test_real_pcaps.py -s
```
