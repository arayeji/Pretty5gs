"""SQLite state store (spec section 4).

Holds per-IMSI provisioning records (for change detection + rate limiting) and
the learned GUTI->IMSI map (spec 3.2 option a). Single file, path configurable,
survives restarts. This is the only persistent state the service keeps; it never
writes to the HSS.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass


@dataclass
class Record:
    imsi: str
    imei: str | None = None
    imei_confidence: str = "none"   # authoritative | masked | none
    sv: str | None = None
    msisdn: str | None = None
    apn: str | None = None
    last_sent: float | None = None
    send_count: int = 0
    last_result: str | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscribers (
    imsi            TEXT PRIMARY KEY,
    imei            TEXT,
    imei_confidence TEXT DEFAULT 'none',
    sv              TEXT,
    msisdn          TEXT,
    apn             TEXT,
    last_sent       REAL,
    send_count      INTEGER DEFAULT 0,
    last_result     TEXT
);
CREATE TABLE IF NOT EXISTS guti_map (
    guti     TEXT PRIMARY KEY,   -- hex of raw EPS mobile identity
    imsi     TEXT NOT NULL,
    updated  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guti_imsi ON guti_map(imsi);
"""


class Store:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- subscriber records ---------------------------------------------
    def get_record(self, imsi: str) -> Record | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM subscribers WHERE imsi=?", (imsi,)).fetchone()
        if row is None:
            return None
        return Record(**{k: row[k] for k in row.keys()})

    def upsert_record(self, rec: Record) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO subscribers
                    (imsi, imei, imei_confidence, sv, msisdn, apn,
                     last_sent, send_count, last_result)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(imsi) DO UPDATE SET
                    imei=excluded.imei,
                    imei_confidence=excluded.imei_confidence,
                    sv=excluded.sv,
                    msisdn=excluded.msisdn,
                    apn=excluded.apn,
                    last_sent=excluded.last_sent,
                    send_count=excluded.send_count,
                    last_result=excluded.last_result
                """,
                (rec.imsi, rec.imei, rec.imei_confidence, rec.sv, rec.msisdn,
                 rec.apn, rec.last_sent, rec.send_count, rec.last_result),
            )
            self._conn.commit()

    # --- GUTI -> IMSI map (spec 3.2) ------------------------------------
    def learn_guti(self, guti: bytes, imsi: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO guti_map (guti, imsi, updated) VALUES (?,?,?) "
                "ON CONFLICT(guti) DO UPDATE SET imsi=excluded.imsi, "
                "updated=excluded.updated",
                (guti.hex(), imsi, time.time()),
            )
            self._conn.commit()

    def resolve_guti(self, guti: bytes) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT imsi FROM guti_map WHERE guti=?", (guti.hex(),)).fetchone()
        return row["imsi"] if row else None
