"""Read-only HSS (MongoDB) subscriber lookup (spec 3.3).

The Open5GS HSS has no per-session default-APN flag. S6a marks context id 1,
which is simply the first session in the slice -- and that is often IMS.

This lookup still uses the slice with default_indicator (else the first slice),
then picks the first *data* session: skip well-known non-data APNs (ims/sos/…)
and QCI 5. Never send an IMS APN as OTA internet settings. If no data session
and/or no MSISDN remains, skip -- never guess. Read-only: find_one only.
"""
from __future__ import annotations

from dataclasses import dataclass

# Session names that are never a default internet APN in this network.
DEFAULT_NON_DATA_APNS = frozenset({
    "ims", "sos", "emergency", "xcap", "ims2",
})
IMS_QCI = 5


@dataclass
class Subscriber:
    imsi: str
    msisdn: str
    apn: str


def _is_data_session(sess: dict, skip_names: set[str]) -> bool:
    name = str(sess.get("name") or "").strip().lower()
    if not name or name in skip_names:
        return False
    qos = sess.get("qos") or {}
    if qos.get("index") == IMS_QCI:
        return False
    return True


def select_subscriber(doc: dict,
                      skip_names: set[str] | None = None) -> Subscriber | None:
    """Pure selection logic over a subscriber document (unit-testable)."""
    if not doc:
        return None
    imsi = doc.get("imsi")
    slices = doc.get("slice") or []
    if not slices:
        return None
    chosen = next((s for s in slices if s.get("default_indicator")), slices[0])
    sessions = chosen.get("session") or []
    skip = {s.lower() for s in (skip_names if skip_names is not None
                                else DEFAULT_NON_DATA_APNS)}
    sess = next((s for s in sessions if _is_data_session(s, skip)), None)
    if sess is None:
        return None
    apn = sess.get("name")
    msisdns = doc.get("msisdn") or []
    msisdn = msisdns[0] if msisdns else None
    if not apn or not msisdn or not imsi:
        return None
    return Subscriber(imsi=imsi, msisdn=str(msisdn), apn=str(apn))


class SubscriberLookup:
    def __init__(self, uri: str, db: str, collection: str,
                 skip_names: set[str] | None = None):
        from pymongo import MongoClient

        # read-only: connect but never issue writes
        self._client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        self._col = self._client[db][collection]
        self._skip_names = skip_names

    def lookup(self, imsi: str) -> Subscriber | None:
        doc = self._col.find_one({"imsi": imsi})
        return select_subscriber(doc, self._skip_names) if doc else None

    def close(self) -> None:
        self._client.close()
