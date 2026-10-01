import pytest

from apn_provisioner import cp_builder


@pytest.fixture(autouse=True)
def generic_cp_profile(monkeypatch):
    """Generic profile identity, same lengths as the shipped one, so the
    byte-level reference values below carry no operator data."""
    monkeypatch.setattr(cp_builder, "NAPID", "TESTAGPRS")
    monkeypatch.setattr(cp_builder, "BOOTSTRAP_NAME", "TestA")
    monkeypatch.setattr(cp_builder, "NAP_NAME", "TestA Internet")
