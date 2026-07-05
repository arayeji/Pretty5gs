#!/usr/bin/env python3
"""
Generate configs/nms/samples/*.yaml from configs/open5gs/*.yaml.in templates.

Each output file includes the full upstream parameter documentation (comment
blocks) plus active fictional sample values. Fork-specific keys from
configs/nms/*-reference.yaml are merged into mme/smf/sgwc.

Run from repo root: python3 tools/gen_nms_full_samples.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(1)


ROOT = Path(__file__).resolve().parents[1]
YAML_IN = ROOT / "configs" / "open5gs"
SAMPLES = ROOT / "configs" / "nms" / "samples"
REFERENCES = ROOT / "configs" / "nms"

HEADER = """\
# =============================================================================
# FICTIONAL NMS SAMPLE — not real operator data
# Generated from configs/open5gs/{src} (+ fork reference overlay when present)
# PLMN 999/70, IMSI prefix 99970, 127.0.0.x lab addresses
# Regenerate: python3 tools/gen_nms_full_samples.py
# =============================================================================
"""

# Map yaml.in basename -> output name (sepp uses sepp1.yaml.in -> sepp1.yaml)
SERVICE_MAP = {
    "mme.yaml.in": "mme.yaml",
    "smf.yaml.in": "smf.yaml",
    "sgwc.yaml.in": "sgwc.yaml",
    "sgwu.yaml.in": "sgwu.yaml",
    "upf.yaml.in": "upf.yaml",
    "amf.yaml.in": "amf.yaml",
    "hss.yaml.in": "hss.yaml",
    "pcrf.yaml.in": "pcrf.yaml",
    "nrf.yaml.in": "nrf.yaml",
    "scp.yaml.in": "scp.yaml",
    "ausf.yaml.in": "ausf.yaml",
    "udm.yaml.in": "udm.yaml",
    "pcf.yaml.in": "pcf.yaml",
    "nssf.yaml.in": "nssf.yaml",
    "bsf.yaml.in": "bsf.yaml",
    "udr.yaml.in": "udr.yaml",
    "cgf.yaml.in": "cgf.yaml",
    "sepp1.yaml.in": "sepp1.yaml",
    "sepp2.yaml.in": "sepp2.yaml",
}

REFERENCE_OVERLAY = {
    "mme.yaml": "mme-reference.yaml",
    "smf.yaml": "smf-reference.yaml",
    "sgwc.yaml": "sgwc-reference.yaml",
}

# NF root key per file (for overlay merge)
NF_ROOT = {
    "mme.yaml": "mme",
    "smf.yaml": "smf",
    "sgwc.yaml": "sgwc",
    "sgwu.yaml": "sgwu",
    "upf.yaml": "upf",
    "amf.yaml": "amf",
    "hss.yaml": "hss",
    "pcrf.yaml": "pcrf",
    "nrf.yaml": "nrf",
    "scp.yaml": "scp",
    "ausf.yaml": "ausf",
    "udm.yaml": "udm",
    "pcf.yaml": "pcf",
    "nssf.yaml": "nssf",
    "bsf.yaml": "bsf",
    "udr.yaml": "udr",
    "cgf.yaml": "cgf",
    "sepp1.yaml": "sepp",
    "sepp2.yaml": "sepp",
}


def deep_merge(base, overlay):
    """Recursively merge overlay into base (overlay wins on scalars/lists)."""
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return overlay
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def substitute_paths(text: str) -> str:
    text = text.replace("@localstatedir@", "/var")
    text = text.replace("@sysconfdir@", "/etc/open5gs")
    text = text.replace(
        "@build_subprojects_freeDiameter_extensions_dir@",
        "/usr/lib/x86_64-linux-gnu/freeDiameter",
    )
    text = text.replace("@build_configs_dir@", "/etc/open5gs")
    # Fictional PLMN / IMSI in active lines (keep comment examples readable)
    text = re.sub(r"\bmcc:\s*001\b", "mcc: 999", text)
    text = re.sub(r'\bmcc:\s*"001"', 'mcc: "999"', text)
    text = re.sub(r"\bmnc:\s*01\b", "mnc: 70", text)
    text = re.sub(r'\bmnc:\s*"01"', 'mnc: "70"', text)
    text = re.sub(r"001010000000001", "999700000000001", text)
    text = re.sub(r"00101", "99970", text)
    text = re.sub(r"mongodb://localhost/", "mongodb://127.0.0.1/", text)
    return text


def parse_yaml_safe(text: str):
    """Parse first YAML document; ignore trailing comment-only pseudo-docs."""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def dump_active_overlay(doc: dict) -> str:
    return yaml.dump(
        doc,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    ).rstrip()


def comment_out_active_lines(text: str) -> str:
    """Turn yaml.in active keys into reference comments (keep existing # docs)."""
    out = []
    for line in text.splitlines():
        if not line.strip():
            out.append(line)
        elif line.lstrip().startswith("#"):
            out.append(line)
        else:
            out.append("#" + line)
    return "\n".join(out)


def build_sample(src_name: str, out_name: str) -> str:
    src_path = YAML_IN / src_name
    body = substitute_paths(src_path.read_text(encoding="utf-8"))

    parts = [HEADER.format(src=src_name), ""]

    ref_name = REFERENCE_OVERLAY.get(out_name)
    if ref_name:
        ref_path = REFERENCES / ref_name
        if ref_path.exists():
            ref_doc = parse_yaml_safe(ref_path.read_text(encoding="utf-8"))
            base_doc = parse_yaml_safe(body)
            if ref_doc and base_doc:
                merged = deep_merge(base_doc, ref_doc)
                parts.append("# --- Active fictional values (fork reference overlay) ---")
                parts.append(dump_active_overlay(merged))
                parts.append("")
                parts.append(
                    "# --- Full parameter reference (upstream yaml.in; active lines commented) ---"
                )
                parts.append(comment_out_active_lines(body))
                return "\n".join(parts) + "\n"

    parts.append(body)
    return "\n".join(parts) + "\n"


def main() -> int:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    written = []
    for src, out in sorted(SERVICE_MAP.items()):
        if not (YAML_IN / src).exists():
            print(f"skip missing {src}", file=sys.stderr)
            continue
        content = build_sample(src, out)
        out_path = SAMPLES / out
        out_path.write_text(content, encoding="utf-8", newline="\n")
        written.append(out)
        print(f"wrote {out_path.relative_to(ROOT)} ({len(content.splitlines())} lines)")

    # README note
    print(f"\nGenerated {len(written)} files under configs/nms/samples/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
