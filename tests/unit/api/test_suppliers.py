"""POST /api/suppliers/import (SIH26164 task items 1-5)."""
import json

import pytest
from fastapi.testclient import TestClient

from ecdat.api.app import create_app
from ecdat.security.auth import Role, TokenRegistry

VIEWER_TOKEN = "test-viewer-token"
EXPORTER_TOKEN = "test-exporter-token"


def _cbom(**overrides) -> dict:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "version": 1,
        "metadata": {
            "timestamp": "2026-09-01T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "acme-scanner", "version": "3.1.0"}]},
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/1",
                "name": "kex",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "kem", "curve": "X25519"},
                },
            }
        ],
    }
    document.update(overrides)
    return document


@pytest.fixture(scope="module")
def app():
    registry = TokenRegistry.from_raw_tokens(
        {VIEWER_TOKEN: Role.VIEWER, EXPORTER_TOKEN: Role.EXPORTER}
    )
    return create_app(token_registry=registry)


@pytest.fixture(scope="module")
def exporter_client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {EXPORTER_TOKEN}"})


@pytest.fixture(scope="module")
def viewer_client(app):
    return TestClient(app, headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})


def test_import_succeeds_for_exporter_role(exporter_client):
    resp = exporter_client.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": json.dumps(_cbom())},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provenance"]["supplier"] == "Acme Vendor"
    assert body["provenance"]["signature_status"] == "UNVERIFIED"
    assert body["declared_count"] == 1
    assert any(q["family"] == "X25519" for q in body["quantum_vulnerable"])


def test_viewer_role_is_refused(viewer_client):
    resp = viewer_client.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": json.dumps(_cbom())},
    )
    assert resp.status_code == 403


def test_anonymous_is_refused(app):
    anon = TestClient(app)
    resp = anon.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": json.dumps(_cbom())},
    )
    assert resp.status_code == 401


def test_malformed_cbom_is_a_400(exporter_client):
    resp = exporter_client.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": "{not json"},
    )
    assert resp.status_code == 400


def test_unknown_sector_is_a_404(exporter_client):
    resp = exporter_client.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": json.dumps(_cbom()), "sector": "not-a-sector"},
    )
    assert resp.status_code == 404


def test_valid_sector_is_echoed_back(exporter_client):
    resp = exporter_client.post(
        "/api/suppliers/import",
        json={"supplier": "Acme Vendor", "cbom_json": json.dumps(_cbom()), "sector": "bfsi"},
    )
    assert resp.status_code == 200
    assert resp.json()["sector"] == "bfsi"
