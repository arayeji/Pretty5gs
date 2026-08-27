"""Minimal SMPP 3.4 transmitter for the proven-working submit_sm (spec 2.1).

Sends each concatenated segment as its own submit_sm with esm_class=0x40 (UDHI)
and data_coding=0x04 (8-bit), ~1s apart, in order. Reconnects with backoff and
never spins (spec 5.4). The only write action this service performs is submit_sm
(spec 5.6).
"""
from __future__ import annotations

import logging
import socket
import struct
import time

log = logging.getLogger("apn_provisioner.smpp")

BIND_TRANSMITTER = 0x00000002
BIND_TRANSMITTER_RESP = 0x80000002
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
UNBIND = 0x00000006
ENQUIRE_LINK = 0x00000015
ENQUIRE_LINK_RESP = 0x80000015


def _cstr(s: str) -> bytes:
    return s.encode("ascii") + b"\x00"


def _pdu(command_id: int, seq: int, body: bytes, status: int = 0) -> bytes:
    length = 16 + len(body)
    return struct.pack(">IIII", length, command_id, status, seq) + body


class SmppError(Exception):
    pass


class SmppSender:
    def __init__(self, *, host: str, port: int, system_id: str, password: str,
                 source_addr: str, source_ton: int = 1, source_npi: int = 1,
                 dest_ton: int = 1, dest_npi: int = 1,
                 connect_timeout: float = 10.0, segment_gap_sec: float = 1.0,
                 max_backoff_sec: float = 60.0):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.source_addr = source_addr
        self.source_ton = source_ton
        self.source_npi = source_npi
        self.dest_ton = dest_ton
        self.dest_npi = dest_npi
        self.connect_timeout = connect_timeout
        self.segment_gap = segment_gap_sec
        self.max_backoff = max_backoff_sec
        self._sock: socket.socket | None = None
        self._seq = 0
        self._backoff = 1.0

    def _next_seq(self) -> int:
        self._seq = (self._seq % 0x7FFFFFFF) + 1
        return self._seq

    def _recv_pdu(self) -> tuple[int, int, int, bytes]:
        hdr = self._recv_exact(16)
        length, cid, status, seq = struct.unpack(">IIII", hdr)
        if length < 16 or length > 65535:
            raise SmppError(f"invalid PDU length {length}")
        body = self._recv_exact(length - 16) if length > 16 else b""
        return cid, status, seq, body

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise SmppError("connection closed by peer")
            buf += chunk
        return buf

    def _wait_resp(self, expected_cid: int, seq: int) -> bytes:
        """Read until the matching response. Reply to enquire_link so a long-lived
        bind does not consume the next submit_sm_resp as a failure (status=0)."""
        deadline = time.time() + self.connect_timeout
        want = expected_cid & 0x7FFFFFFF
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise SmppError(
                    f"timeout waiting for cid=0x{expected_cid:08X} seq={seq}")
            self._sock.settimeout(max(remaining, 0.1))
            try:
                cid, status, rseq, body = self._recv_pdu()
            except socket.timeout as e:
                raise SmppError(
                    f"timeout waiting for cid=0x{expected_cid:08X} seq={seq}") from e

            if cid == ENQUIRE_LINK:
                self._sock.sendall(_pdu(ENQUIRE_LINK_RESP, rseq, b""))
                continue

            if (cid & 0x7FFFFFFF) == want:
                if status != 0:
                    raise SmppError(
                        f"rejected cid=0x{cid:08X} status=0x{status:08X} seq={rseq}")
                if rseq != seq:
                    log.warning("SMPP seq mismatch want=%d got=%d cid=0x%08X (accepting)",
                                seq, rseq, cid)
                return body

            log.warning("SMPP ignore unexpected pdu cid=0x%08X status=0x%08X seq=%d "
                        "(want cid=0x%08X seq=%d)",
                        cid, status, rseq, expected_cid, seq)

    def connect(self) -> None:
        """Connect + bind_transmitter, with exponential backoff on failure."""
        while True:
            try:
                self._sock = socket.create_connection(
                    (self.host, self.port), timeout=self.connect_timeout)
                self._bind()
                self._backoff = 1.0
                log.info("SMPP bound as system_id=%s to %s:%s",
                         self.system_id, self.host, self.port)
                return
            except (OSError, SmppError) as e:
                log.warning("SMPP connect/bind failed: %s; backing off %.1fs",
                            e, self._backoff)
                self._close_socket()
                time.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, self.max_backoff)

    def _bind(self) -> None:
        body = (
            _cstr(self.system_id) + _cstr(self.password) + _cstr("")  # system_type
            + bytes([0x34])       # interface_version
            + bytes([0, 0]) + _cstr("")  # addr_ton, addr_npi, address_range
        )
        seq = self._next_seq()
        self._sock.sendall(_pdu(BIND_TRANSMITTER, seq, body))
        self._wait_resp(BIND_TRANSMITTER_RESP, seq)

    def _submit(self, destination_addr: str, short_message: bytes) -> None:
        body = (
            _cstr("")  # service_type
            + bytes([self.source_ton, self.source_npi]) + _cstr(self.source_addr)
            + bytes([self.dest_ton, self.dest_npi]) + _cstr(destination_addr)
            + bytes([0x40])   # esm_class = UDHI (MANDATORY, spec 2.1)
            + bytes([0x00])   # protocol_id
            + bytes([0x00])   # priority_flag
            + _cstr("") + _cstr("")  # schedule_delivery_time, validity_period
            + bytes([0x00])   # registered_delivery
            + bytes([0x00])   # replace_if_present
            + bytes([0x04])   # data_coding = 8-bit binary (spec 2.1)
            + bytes([0x00])   # sm_default_msg_id
            + bytes([len(short_message)]) + short_message
        )
        seq = self._next_seq()
        self._sock.sendall(_pdu(SUBMIT_SM, seq, body))
        self._wait_resp(SUBMIT_SM_RESP, seq)

    def send_segments(self, destination_addr: str, segments: list[bytes]) -> None:
        """Send all segments in order, ~1s apart. Raises SmppError on failure.

        All-or-nothing intent: never submit a segment without its partners
        (spec 5.5). If a segment fails we stop and raise so the caller does not
        record a partial success.
        """
        try:
            if self._sock is None:
                self.connect()
            for i, seg in enumerate(segments):
                self._submit(destination_addr, seg)
                if i + 1 < len(segments):
                    time.sleep(self.segment_gap)
        except (OSError, SmppError):
            self._close_socket()
            raise

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.sendall(_pdu(UNBIND, self._next_seq(), b""))
            except OSError:
                pass
            self._close_socket()
