"""Event sources for apn-provisioner.

Primary path (production): the MME sends ONE small datagram per eligible attach
-- a UE whose Attach Request carried NO APN IE, matching a per-PLMN
`mme.provisioning_sms` rule with `delivery: event`. The datagram (UNIX-domain
socket same-host, or UDP for a remote host) carries:

    event=attach imsi=.. msisdn=.. imei=.. imeisv=.. mcc=.. mnc=.. apn_absent=1

This is a real IPC event, not a log line: nothing is written to journald/disk,
and the MME send is non-blocking (fire-and-forget), so it cannot load or stall
MME call processing. `UnixDatagramEventSource` / `UdpEventSource` bind the
socket and yield `AttachEvent`s -- no S1AP/NAS decoding on the hot path.

Offline path (tests / bring-up): the pcap sources still parse raw S1AP so the
decoder can be exercised against real captures.
"""
from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass
from typing import Iterator

S1AP_PPID = 18
_KV_RE = re.compile(r"(\w+)=(\S+)")
_MAX_DGRAM = 4096


@dataclass
class AttachEvent:
    imsi: str
    msisdn: str | None = None
    imei: str | None = None       # 15-digit IMEI
    imeisv: str | None = None     # 16-digit IMEISV (if the MME had it)
    mcc: str | None = None
    mnc: str | None = None
    apn_absent: bool = True       # MME already gated on "no APN IE"


def _clean(v: str | None) -> str | None:
    return None if v in (None, "", "-") else v


def parse_event_payload(text: str) -> AttachEvent | None:
    """Parse one MME event datagram (space-separated key=val) into AttachEvent."""
    kv = dict(_KV_RE.findall(text))
    imsi = _clean(kv.get("imsi"))
    if not imsi:
        return None
    return AttachEvent(
        imsi=imsi,
        msisdn=_clean(kv.get("msisdn")),
        imei=_clean(kv.get("imei")),
        imeisv=_clean(kv.get("imeisv")),
        mcc=_clean(kv.get("mcc")),
        mnc=_clean(kv.get("mnc")),
        apn_absent=kv.get("apn_absent", "1") == "1",
    )


class UnixDatagramEventSource:
    """Bind a UNIX-domain datagram socket and yield MME attach events."""

    def __init__(self, socket_path: str, mode: int = 0o666):
        self.socket_path = socket_path
        self.mode = mode

    def events(self) -> Iterator[AttachEvent]:
        d = os.path.dirname(self.socket_path)
        if d:
            os.makedirs(d, exist_ok=True)
        try:
            os.unlink(self.socket_path)  # stale socket from a previous run
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.socket_path)
        try:
            os.chmod(self.socket_path, self.mode)  # let the MME user send
        except OSError:
            pass
        try:
            yield from _recv_loop(sock)
        finally:
            sock.close()
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass


class UdpEventSource:
    """Bind a UDP socket (host:port) and yield MME attach events."""

    def __init__(self, bind_addr: str):
        host, _, port = bind_addr.rpartition(":")
        if not host or not port:
            raise ValueError(f"event_bind_addr must be host:port, got {bind_addr!r}")
        self.host = host
        self.port = int(port)

    def events(self) -> Iterator[AttachEvent]:
        info = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)
        family, socktype, proto, _, sa = info[0]
        sock = socket.socket(family, socktype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(sa)
        try:
            yield from _recv_loop(sock)
        finally:
            sock.close()


def _recv_loop(sock: socket.socket) -> Iterator[AttachEvent]:
    while True:
        try:
            data, _ = sock.recvfrom(_MAX_DGRAM)
        except OSError:
            time.sleep(0.1)
            continue
        if not data:
            continue
        evt = parse_event_payload(data.decode("utf-8", "replace"))
        if evt is not None:
            yield evt


# --- offline S1AP (pcap) path ---------------------------------------------


@dataclass
class S1Frame:
    payload: bytes               # raw S1AP PDU (APER)
    assoc: str                   # correlation handle


def _assoc(a: str, b: str) -> str:
    lo, hi = sorted((a, b))
    return f"{lo}<->{hi}"


def iter_s1ap_from_pcap(path: str) -> Iterator[S1Frame]:
    """Yield S1Frames from every S1AP SCTP DATA chunk in a pcap (offline)."""
    from scapy.all import IP, SCTP, SCTPChunkData, PcapReader

    with PcapReader(path) as pr:
        for pkt in pr:
            if not pkt.haslayer(SCTP) or not pkt.haslayer(IP):
                continue
            assoc = _assoc(pkt[IP].src, pkt[IP].dst)
            chunk = pkt[SCTP].payload
            while isinstance(chunk, SCTPChunkData):
                if getattr(chunk, "proto_id", None) == S1AP_PPID:
                    data = bytes(chunk.data)
                    if data:
                        yield S1Frame(payload=data, assoc=assoc)
                chunk = chunk.payload


class PcapReplaySource:
    """Finite replay of one pcap (offline decoder tests)."""

    def __init__(self, path: str):
        self.path = path

    def events(self) -> Iterator[S1Frame]:
        yield from iter_s1ap_from_pcap(self.path)


class PcapDirTailSource:
    """Tail rotated pcap files in a directory (offline fallback)."""

    def __init__(self, directory: str, pattern: str = "*.pcap",
                 poll_interval: float = 1.0):
        self.directory = directory
        self.pattern = pattern
        self.poll_interval = poll_interval
        self._read_counts: dict[str, int] = {}

    def _files(self) -> list[str]:
        import glob
        paths = glob.glob(os.path.join(self.directory, self.pattern))
        return sorted(paths, key=lambda p: os.path.getmtime(p))

    def events(self) -> Iterator[S1Frame]:
        while True:
            for path in self._files():
                already = self._read_counts.get(path, 0)
                seen = 0
                try:
                    for i, frame in enumerate(iter_s1ap_from_pcap(path)):
                        seen = i + 1
                        if i < already:
                            continue
                        yield frame
                except (OSError, EOFError):
                    continue
                self._read_counts[path] = max(already, seen)
            time.sleep(self.poll_interval)


def build_source(cfg):
    """Instantiate the configured event source."""
    mode = cfg.mode
    if mode == "mme_event_unix":
        return UnixDatagramEventSource(cfg.event_socket)
    if mode == "mme_event_udp":
        return UdpEventSource(cfg.event_bind_addr)
    if mode == "pcap_replay":
        return PcapReplaySource(cfg.pcap_path)
    if mode == "pcap_tail":
        return PcapDirTailSource(cfg.pcap_dir, cfg.pcap_pattern)
    raise ValueError(f"unknown s1_source.mode {mode!r}")
