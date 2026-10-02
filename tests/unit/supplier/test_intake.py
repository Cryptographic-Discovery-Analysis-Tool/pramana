"""Supplier CBOM intake tests (SIH26164 task item 6): valid, invalid schema,
signed-valid, signed-tampered CBOMs, and the epistemics/provenance contract.

Signed fixtures are generated with the repo's own `export/signing.py` in
this file (task item 6: "Generate signed ones with the repo's own signing
code in the test"), never a hand-crafted signature block.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from ecdat.export.cyclonedx import SchemaValidationError
from ecdat.export.signing import generate_signing_key, sign_bom
from ecdat.model.epistemic import EpistemicState
from ecdat.supplier.intake import (
    MalformedCbomError,
    UnsupportedSpecVersionError,
    import_supplier_cbom,
)
from ecdat.supplier.models import SignatureStatus


def _base_document() -> dict:
    return {
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
                "bom-ref": "crypto/cert-1",
                "name": "leaf-cert",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": "CN=vendor.example",
                        "issuerName": "CN=Vendor CA",
                        "certificateFormat": "X.509",
                    },
                },
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            },
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/kex-1",
                "name": "ML-KEM-768 key exchange",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "kem", "parameterSetIdentifier": "ML-KEM"},
                },
            },
            {
                # Not a crypto asset: must be skipped, never counted.
                "type": "library",
                "bom-ref": "lib/1",
                "name": "some-library",
            },
        ],
    }


def _raw(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


IMPORTED_AT = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def test_valid_cbom_imports_with_declared_components_and_provenance():
    result = import_supplier_cbom(_raw(_base_document()), supplier="Acme Vendor", imported_at=IMPORTED_AT)

    assert result.provenance.supplier == "Acme Vendor"
    assert result.provenance.imported_at == IMPORTED_AT
    assert result.provenance.signature_status == SignatureStatus.UNVERIFIED
    assert result.provenance.cbom_serial_number == "urn:uuid:11111111-1111-4111-8111-111111111111"
    assert result.provenance.cbom_version == 1
    assert result.provenance.source_tool == "acme-scanner"
    assert result.provenance.source_tool_version == "3.1.0"
    assert len(result.provenance.file_sha256) == 64

    # Exactly the two cryptographic-asset components; the plain library is skipped.
    assert len(result.components) == 2
    for component in result.components:
        assert component.state == EpistemicState.DECLARED

    cert = next(c for c in result.components if c.bom_ref == "crypto/cert-1")
    assert cert.der_sha256 == "a" * 64
    assert cert.certificate_subject == "CN=vendor.example"

    kex = next(c for c in result.components if c.bom_ref == "crypto/kex-1")
    assert kex.primitive == "kem"
    assert kex.algorithm_family == "ML-KEM"


def test_malformed_json_is_rejected_with_clear_error():
    with pytest.raises(MalformedCbomError):
        import_supplier_cbom(b"{not json", supplier="Acme Vendor")


def test_schema_invalid_document_is_rejected():
    document = _base_document()
    # additionalProperties: false on the schema -- an unknown top-level key
    # is invalid CycloneDX.
    document["notARealCycloneDxField"] = True
    with pytest.raises(SchemaValidationError):
        import_supplier_cbom(_raw(document), supplier="Acme Vendor")


def test_unsupported_spec_version_is_reported_honestly():
    document = _base_document()
    document["specVersion"] = "1.7"
    with pytest.raises(UnsupportedSpecVersionError):
        import_supplier_cbom(_raw(document), supplier="Acme Vendor")


def test_blank_supplier_name_is_rejected():
    with pytest.raises(ValueError):
        import_supplier_cbom(_raw(_base_document()), supplier="   ")


def test_signed_valid_cbom_verifies():
    key = generate_signing_key()
    document = sign_bom(_base_document(), private_key=key, key_id="vendor-key-1")

    result = import_supplier_cbom(_raw(document), supplier="Acme Vendor", imported_at=IMPORTED_AT)

    assert result.provenance.signature_status == SignatureStatus.VERIFIED
    assert result.provenance.signature_key_id == "vendor-key-1"


def test_signed_tampered_cbom_is_never_treated_as_verified():
    key = generate_signing_key()
    document = sign_bom(_base_document(), private_key=key, key_id="vendor-key-1")
    tampered = copy.deepcopy(document)
    tampered["components"][0]["name"] = "tampered-name"

    result = import_supplier_cbom(_raw(tampered), supplier="Acme Vendor", imported_at=IMPORTED_AT)

    assert result.provenance.signature_status == SignatureStatus.INVALID
    # A tampered/invalid signature never blocks the import itself -- the
    # components still get parsed as DECLARED evidence, only now flagged
    # INVALID rather than silently dropped or silently trusted.
    assert len(result.components) == 2
