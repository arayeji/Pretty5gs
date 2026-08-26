"""Read-only HSS (MongoDB) subscriber lookup (spec 3.3).

Selection rule: the slice with default_indicator == true (else the first slice),
then its FIRST session; session.name is the APN and msisdn[0] is the MSISDN. If
either is missing we skip the subscriber -- never send a guessed APN. This
service must NEVER write to the HSS, so it uses a read-only Mongo user and only
ever issues find_one.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Subscriber:
    imsi: str
    msisdn: str
    apn: str


def select_subscriber(doc: dict) -> Subscriber | None:
    """Pure selection logic over a subscriber document (unit-testable)."""
    if not doc:
        return None
    imsi = doc.get("imsi")
    slices = doc.get("slice") or []
    if not slices:
        return None
    chosen = next((s for s in slices if s.get("default_indicator")), slices[0])
    sessions = chosen.get("session") or []
    if not sessions:
        return None
    apn = sessions[0].get("name")
    msisdns = doc.get("msisdn") or []
    msisdn = msisdns[0] if msisdns else None
    if not apn or not msisdn or not imsi:
        return None
    return Subscriber(imsi=imsi, msisdn=str(msisdn), apn=str(apn))


class SubscriberLookup:
    def __init__(self, uri: str, db: str, collection: str):
        from pymongo import MongoClient

        # read-only: connect but never issue writes
        self._client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        self._col = self._client[db][collection]

    def lookup(self, imsi: str) -> Subscriber | None:
        doc = self._col.find_one({"imsi": imsi})
        return select_subscriber(doc) if doc else None

    def close(self) -> None:
        self._client.close()
