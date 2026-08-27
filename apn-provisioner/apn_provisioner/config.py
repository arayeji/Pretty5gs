"""Config-file driven settings (spec section 4). No values are hardcoded.

Real endpoints/credentials live only in the deployed config.yaml (gitignored);
config.example.yaml ships placeholders.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class S1SourceConfig:
    # mme_event_unix / mme_event_udp = receive the MME's attach datagrams (the
    # MME sends one per eligible attach when a per-PLMN provisioning_sms rule has
    # `delivery: event`). pcap_* are offline fallbacks for the decoder tests.
    mode: str = "mme_event_unix"       # mme_event_unix|mme_event_udp|pcap_replay|pcap_tail
    # mme_event_unix: UNIX-domain datagram socket this service binds (same host
    # as the MME). Must match the rule's `event_socket` in mme.yaml.
    event_socket: str = "/run/apn-provisioner/events.sock"
    # mme_event_udp: host:port this service binds to receive UDP datagrams.
    # Must match the rule's `event_addr` in mme.yaml.
    event_bind_addr: str = "0.0.0.0:5005"
    pcap_path: str = ""
    pcap_dir: str = ""
    pcap_pattern: str = "*.pcap"


@dataclass
class SmppConfig:
    host: str = ""
    port: int = 2776
    system_id: str = "jasmin"
    password: str = "jasmin"
    source_addr: str = "1234"
    segment_gap_sec: float = 1.0


@dataclass
class MongoConfig:
    uri: str = ""
    db: str = "open5gs"
    collection: str = "subscribers"


@dataclass
class Config:
    s1_source: S1SourceConfig = field(default_factory=S1SourceConfig)
    smpp: SmppConfig = field(default_factory=SmppConfig)
    mongo: MongoConfig = field(default_factory=MongoConfig)

    state_db_path: str = "/var/lib/apn-provisioner/state.db"

    resend_interval_hours: float = 24.0
    send_on_imei_change: bool = True
    ignore_sv_change: bool = True
    correlation_timeout_sec: float = 60.0

    dedup_window_sec: float = 60.0
    max_sends_per_sub_per_day: int = 5
    global_max_per_sec: float = 1.0
    breaker_per_min: int = 30
    breaker_resume_per_min: int = 5

    # HSS session names that are never the default internet APN (IMS is often
    # first in the slice; S6a default is "first session" and that is wrong here).
    non_data_apns: list[str] = field(
        default_factory=lambda: ["ims", "sos", "emergency", "xcap", "ims2"])

    dry_run: bool = True
    log_level: str = "INFO"

    @staticmethod
    def from_dict(d: dict) -> "Config":
        d = d or {}
        cfg = Config()
        if "s1_source" in d:
            cfg.s1_source = S1SourceConfig(**d["s1_source"])
        if "smpp" in d:
            cfg.smpp = SmppConfig(**d["smpp"])
        if "mongo" in d:
            cfg.mongo = MongoConfig(**d["mongo"])
        for k, v in d.items():
            if k in ("s1_source", "smpp", "mongo"):
                continue
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    @staticmethod
    def load(path: str) -> "Config":
        import yaml

        with open(path, "r") as f:
            return Config.from_dict(yaml.safe_load(f))
