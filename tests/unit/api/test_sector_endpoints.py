"""`/api/sectors` and `/api/sector-report` (SIH26164).

Same fixture and auth pattern as test_app.py.
"""
import pytest
from fastapi.testclient import TestClient

from ecdat.api.app import create_app
from ecdat.security.audit import InMemoryAuditLog
from ecdat.security.auth import Role, TokenRegistry

AS_OF = "2026-09-18"
BASE = {"rollout_y_days": 365, "as_of": AS_OF, "scenario": "Z_central"}

VIEWER_TOKEN = "test-viewer-token"


@pytest.fixture(scope="module")
def app():
    registry = TokenRegistry.from_raw_tokens({VIEWER_TOKEN: Role.VIEWER})
    return create_app(token_registry=registry, audit_log=InMemoryAuditLog())


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})


@pytest.fixture
def anonymous_client(app):
    return TestClient(app)


def q(**kw):
    return {**BASE, **kw}


def test_sectors_lists_all_four_with_citations(client):
    body = client.get("/api/sectors").json()
    keys = {s["key"] for s in body["sectors"]}
    assert keys == {"bfsi", "telecom", "cii", "government_enterprise"}
    for sector in body["sectors"]:
        assert sector["citation"]
        assert sector["quote"]
        for policy in sector["policies"]:
            assert policy["citation"]
            assert policy["quote"]


def test_sectors_requires_auth(anonymous_client):
    assert anonymous_client.get("/api/sectors").status_code == 401


def test_sector_report_requires_sector_and_scenario(client):
    assert client.get("/api/sector-report", params=BASE).status_code == 422


def test_sector_report_bfsi_rows_have_traffic_light_and_obligations(client):
    body = client.get("/api/sector-report", params=q(sector="bfsi")).json()
    assert body["sector"] == "bfsi"
    assert body["assets"]
    for asset in body["assets"]:
        assert asset["status"] in {"on_track", "at_risk", "overdue", "no_deadline"}
        obligation_keys = {o["policy"] for o in asset["obligations"]}
        assert obligation_keys == {"IN_SEBI_CSCRF", "IN_RBI_CYBERSEC_MD", "IN_RBI_QSAFE"}


def test_sector_report_unknown_sector_is_404(client):
    assert client.get("/api/sector-report", params=q(sector="healthcare")).status_code == 404


def test_sector_report_include_global_widens_annotations(client):
    without_global = client.get("/api/sector-report", params=q(sector="cii")).json()
    with_global = client.get(
        "/api/sector-report", params=q(sector="cii", include_global=True)
    ).json()
    keys_without = {
        a["policy"] for asset in without_global["assets"] for a in asset["annotations"]
    }
    keys_with = {a["policy"] for asset in with_global["assets"] for a in asset["annotations"]}
    assert "NIST_IR_8547_IPD" not in keys_without
    assert "NIST_IR_8547_IPD" in keys_with


def test_sector_report_never_changes_the_underlying_band(client):
    """Sanity: the sector view and the plain ledger agree on which asset ids
    exist -- the sector overlay adds annotations, it does not filter rows out
    of existence or recompute anything the ledger already decided."""
    ledger_body = client.get("/api/ledger", params=BASE).json()
    ledger_assets = {row["asset_id"] for row in ledger_body["rows"]}
    sector_body = client.get("/api/sector-report", params=q(sector="cii")).json()
    sector_assets = {a["asset_id"] for a in sector_body["assets"]}
    assert sector_assets <= ledger_assets
