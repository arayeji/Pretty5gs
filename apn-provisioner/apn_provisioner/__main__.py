"""CLI entrypoint: apn-provisioner --config /etc/apn-provisioner/config.yaml

The trigger is configured on the MME side: a per-PLMN `mme.provisioning_sms`
rule with `delivery: event` makes the MME send one fire-and-forget datagram
(UNIX socket or UDP -- no logs) per attach of a UE that sent no APN IE. This
service binds that socket, consumes the events and sends via SMPP.
"""
from __future__ import annotations

import argparse

from .config import Config
from .service import build_and_run


def main() -> None:
    ap = argparse.ArgumentParser(prog="apn-provisioner")
    ap.add_argument("-c", "--config", required=True, help="path to config.yaml")
    ap.add_argument("--dry-run", action="store_true",
                    help="force dry-run (build+validate+log, send nothing)")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    if args.dry_run:
        cfg.dry_run = True
    build_and_run(cfg)


if __name__ == "__main__":
    main()
