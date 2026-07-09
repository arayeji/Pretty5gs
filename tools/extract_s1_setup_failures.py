#!/usr/bin/env python3
"""
Extract eNB S1 Setup failures from a PCAP (S1AP over SCTP).

Requires Wireshark/tshark on PATH or at the default Windows install location.

Usage:
  python tools/extract_s1_setup_failures.py c:\\Capture\\s1apdebug.pcap
  python tools/extract_s1_setup_failures.py s1apdebug.pcap --mme 127.0.0.2 -o failures.yaml
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


DEFAULT_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


@dataclass
class EnbSetupRequest:
    ip: str
    global_plmn_hex: str = ""
    supported_plmn_hex: str = ""
    tac: Optional[int] = None
    enb_id: str = ""
    enb_name: str = ""


def find_tshark() -> str:
    for candidate in (shutil.which("tshark"), DEFAULT_TSHARK):
        if candidate and os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError(
        "tshark not found. Install Wireshark or add tshark to PATH."
    )


def decode_plmn_hex(hex6: str) -> Tuple[int, int, int, str]:
    """Return (mcc, mnc, mnc_len, human_label)."""
    if len(hex6) != 6:
        return 0, 0, 0, "invalid"
    b = bytes.fromhex(hex6)
    mcc = (b[0] & 0x0F) * 100 + ((b[0] >> 4) & 0x0F) * 10 + (b[1] & 0x0F)
    mnc1 = (b[1] >> 4) & 0x0F
    mnc2 = b[2] & 0x0F
    mnc3 = (b[2] >> 4) & 0x0F
    if mnc1 == 0x0F:
        mnc_len = 2
        mnc = mnc2 * 10 + mnc3
    else:
        mnc_len = 3
        mnc = mnc1 * 100 + mnc2 * 10 + mnc3
    return mcc, mnc, mnc_len, f"{mcc:03d}-{mnc:0{mnc_len}d}"


def run_tshark_verbose(tshark: str, pcap: str, display_filter: str) -> str:
    cmd = [tshark, "-r", pcap, "-Y", display_filter, "-V"]
    return subprocess.check_output(cmd, text=True, errors="replace")


def parse_s1_setup_blocks(text: str, mme_ip: str) -> Tuple[Dict[str, EnbSetupRequest], Set[str]]:
    requests: Dict[str, EnbSetupRequest] = {}
    failures: Set[str] = set()

    for block in text.split("Frame "):
        src_m = re.search(r"Src: ([0-9.]+)", block)
        dst_m = re.search(r"Dst: ([0-9.]+)", block)
        if not src_m or not dst_m:
            continue
        src, dst = src_m.group(1), dst_m.group(1)

        if "S1SetupRequest" in block and src != mme_ip:
            plmns = re.findall(r"pLMNidentity: ([0-9a-f]{6})", block, re.I)
            tacs = re.findall(r"tAC: ([0-9]+)", block)
            enb_m = re.search(
                r"macroENB-ID: [0-9a-f]+ .* decimal value ([0-9]+)", block
            )
            enbname_m = re.search(r"ENBname: (\S+)", block)
            tac = int(tacs[0]) if tacs else None
            requests[src] = EnbSetupRequest(
                ip=src,
                global_plmn_hex=plmns[0] if plmns else "",
                supported_plmn_hex=plmns[-1] if plmns else "",
                tac=tac,
                enb_id=enb_m.group(1) if enb_m else "",
                enb_name=enbname_m.group(1) if enbname_m else "",
            )

        if "S1SetupFailure" in block and src == mme_ip:
            failures.add(dst)

    return requests, failures


def group_tacs_by_plmn(
    failing: List[Tuple[EnbSetupRequest, str]]
) -> Dict[Tuple[int, int, int], Set[int]]:
    grouped: Dict[Tuple[int, int, int], Set[int]] = collections.defaultdict(set)
    for req, _ in failing:
        if req.tac is None:
            continue
        mcc, mnc, mnc_len, _ = decode_plmn_hex(req.supported_plmn_hex or req.global_plmn_hex)
        grouped[(mcc, mnc, mnc_len)].add(req.tac)
    return grouped


def yaml_mnc_string(mnc: int, mnc_len: int) -> str:
    if mnc_len == 2:
        return f"'{mnc:02d}'"
    return f"'{mnc:03d}'"


def emit_yaml_snippet(grouped: Dict[Tuple[int, int, int], Set[int]]) -> str:
    lines = [
        "# Paste under mme: in mme.yaml",
        "# IMPORTANT: mnc string LENGTH sets 2- vs 3-digit PLMN encoding.",
        "# eNBs in this PCAP use 2-digit MNC (hex ...f2..). Use mnc: '70' NOT '070' (2- vs 3-digit PLMN encoding).",
        "  tai:",
    ]
    for (mcc, mnc, mnc_len) in sorted(grouped):
        tacs = sorted(grouped[(mcc, mnc, mnc_len)])
        lines.append("  - plmn_id:")
        lines.append(f"      mcc: '{mcc:03d}'")
        lines.append(f"      mnc: {yaml_mnc_string(mnc, mnc_len)}")
        lines.append("    tac:")
        for tac in tacs:
            lines.append(f"    - {tac}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--mme", default="127.0.0.2", help="MME IPv4 address")
    parser.add_argument("-o", "--output", help="Write YAML snippet to this file")
    parser.add_argument("--csv", help="Write CSV table to this file")
    args = parser.parse_args()

    tshark = find_tshark()
    text = run_tshark_verbose(tshark, args.pcap, "s1ap.procedureCode == 17")
    requests, failures = parse_s1_setup_blocks(text, args.mme)

    failing_rows: List[Tuple[EnbSetupRequest, str]] = []
    for ip in sorted(failures):
        req = requests.get(ip)
        if req is None:
            req = EnbSetupRequest(ip=ip)
        plmn_hex = req.supported_plmn_hex or req.global_plmn_hex
        _, _, _, plmn_label = decode_plmn_hex(plmn_hex)
        failing_rows.append((req, plmn_label))

    grouped = group_tacs_by_plmn(failing_rows)
    yaml_text = emit_yaml_snippet(grouped)

    print(f"PCAP: {args.pcap}")
    print(f"MME:  {args.mme}")
    print(f"S1SetupFailure eNBs: {len(failures)}")
    print()
    print(f"{'IP':<18} {'PLMN':<10} {'hex':<8} {'TAC':>6} {'hex':>8}  {'ENB_ID':>8}  NAME")
    print("-" * 80)
    for req, plmn_label in failing_rows:
        plmn_hex = req.supported_plmn_hex or req.global_plmn_hex
        tac_hex = f"0x{req.tac:04x}" if req.tac is not None else ""
        tac_s = str(req.tac) if req.tac is not None else "?"
        print(
            f"{req.ip:<18} {plmn_label:<10} {plmn_hex:<8} {tac_s:>6} {tac_hex:>8}  "
            f"{req.enb_id:>8}  {req.enb_name}"
        )

    print()
    print("=== Unique TACs per PLMN (for mme.tai) ===")
    for (mcc, mnc, mnc_len) in sorted(grouped):
        label = f"{mcc:03d}-{mnc:0{mnc_len}d}"
        tacs = sorted(grouped[(mcc, mnc, mnc_len)])
        print(f"  {label} (mnc_len={mnc_len}): {', '.join(str(t) for t in tacs)}")

    print()
    print("=== YAML snippet ===")
    print(yaml_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(yaml_text)
        print(f"Wrote YAML to {args.output}", file=sys.stderr)

    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as fh:
            fh.write("ip,plmn,plmn_hex,tac,tac_hex,enb_id,enb_name\n")
            for req, plmn_label in failing_rows:
                plmn_hex = req.supported_plmn_hex or req.global_plmn_hex
                tac_hex = f"0x{req.tac:04x}" if req.tac is not None else ""
                fh.write(
                    f"{req.ip},{plmn_label},{plmn_hex},{req.tac or ''},"
                    f"{tac_hex},{req.enb_id},{req.enb_name}\n"
                )
        print(f"Wrote CSV to {args.csv}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
