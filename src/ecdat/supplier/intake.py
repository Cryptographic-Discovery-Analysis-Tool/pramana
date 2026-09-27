"""Supplier CBOM intake (task item 1/2): validate, verify, and record
provenance for a vendor's CycloneDX CBOM before anything in it is merged
into our own inventory.

Three things happen here, in this order, and none is skippable:

1. **Schema validation.** `export/cyclonedx.py::validate()` -- the same
   bundled CycloneDX 1.6 schema every export of ours is checked against.
   Malformed input is rejected with the schema validator's own error text,
   never partially parsed. Only `specVersion` 1.6 is accepted; 1.7 is
   honestly reported as unsupported (`UnsupportedSpecVersionError`) rather
   than run through a 1.6 validator that would silently misjudge it --
   `schemas/` ships no 1.7 schema (see `export/cyclonedx.py`'s own
   `SPEC_VERSION` constant), and inventing lenience for a spec version this
   repo has never fetched would be exactly the "some other tool wrote it"
   trust CLAUDE.md's anti-hallucination rules forbid.
2. **Signature verification**, only when the document carries one.
   `export/signing.py::verify_bom()` is reused unchanged -- an unsigned or
   invalid signature is never treated as verified (`SignatureStatus`,
   `supplier/models.py`).
3. **Component parsing**, entirely DECLARED (see `supplier/models.py`'s
   docstring for why).

`import_supplier_cbom` takes raw bytes (not a pre-parsed dict) because the
file SHA-256 recorded in provenance must be over exactly the bytes the
supplier handed us -- hashing a re-serialised dict would hash our own
JSON formatting choices instead of their document.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ecdat.export.cyclonedx import SPEC_VERSION, SchemaValidationError, validate
from ecdat.export.signing import SignatureVerificationError, verify_bom
from ecdat.supplier.models import (
    SignatureStatus,
    SupplierComponent,
    SupplierIntakeResult,
    SupplierProvenance,
)


class MalformedCbomError(ValueError):
    """The supplied bytes are not valid JSON at all. Distinct from
    `SchemaValidationError` (valid JSON, invalid CycloneDX) so a caller can
    tell "not JSON" from "JSON but not a CBOM" apart in its error message."""


class UnsupportedSpecVersionError(ValueError):
    """The document names a `specVersion` this repository has no bundled
    schema for. Reported honestly rather than validated against the wrong
    schema (task item 1: "accept 1.7 if the schema is available or mark as
    unsupported honestly" -- no 1.7 schema is bundled, so every 1.7
    document takes this path)."""


def _producing_tool(document: dict[str, Any]) -> tuple[str, str]:
    """Same read `export/cyclonedx.py::_producing_tool` does -- duplicated
    rather than imported because that helper is module-private, and this is
    three lines, not a shared contract worth exporting."""
    tools = (document.get("metadata") or {}).get("tools") or {}
    candidates = tools.get("components") if isinstance(tools, dict) else tools
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, dict):
            return (
                str(first.get("name") or "unknown-tool"),
                str(first.get("version") or "unknown-version"),
            )
    return ("unknown-tool", "unknown-version")


def _hash_of(component: dict[str, Any], *, alg: str) -> str | None:
    for entry in component.get("hashes") or ():
        if isinstance(entry, dict) and str(entry.get("alg", "")).upper() == alg.upper():
            content = entry.get("content")
            return str(content) if content else None
    return None


def _parse_component(component: dict[str, Any]) -> SupplierComponent | None:
    crypto = component.get("cryptoProperties")
    if not crypto:
        # Not a crypto asset -- §5.1: presence of a plain library component
        # is not even presence of an algorithm (export/cyclonedx.py's own
        # import_cbom() makes the same call).
        return None

    asset_type = str(crypto.get("assetType") or "unknown")
    algorithm = crypto.get("algorithmProperties") or {}
    certificate = crypto.get("certificateProperties") or {}
    related = crypto.get("relatedCryptoMaterialProperties") or {}
    protocol = crypto.get("protocolProperties") or {}

    der_sha256 = None
    spki_sha256 = None
    if asset_type == "certificate":
        der_sha256 = _hash_of(component, alg="SHA-256")
    elif asset_type == "related-crypto-material" and related.get("type") == "public-key":
        spki_sha256 = _hash_of(component, alg="SHA-256")

    bom_ref = str(component.get("bom-ref") or component.get("name") or "")
    if not bom_ref:
        return None

    return SupplierComponent(
        bom_ref=bom_ref,
        name=str(component.get("name") or bom_ref),
        asset_type=asset_type,
        primitive=algorithm.get("primitive"),
        parameter_set_identifier=algorithm.get("parameterSetIdentifier"),
        curve=algorithm.get("curve"),
        certificate_subject=certificate.get("subjectName"),
        certificate_issuer=certificate.get("issuerName"),
        certificate_format=certificate.get("certificateFormat"),
        related_material_type=related.get("type"),
        key_size_bits=related.get("size"),
        protocol_type=protocol.get("type"),
        protocol_version=protocol.get("version"),
        der_sha256=der_sha256,
        spki_sha256=spki_sha256,
        oid=crypto.get("oid"),
        properties=tuple(
            (str(p.get("name")), str(p.get("value", "")))
            for p in (component.get("properties") or ())
            if isinstance(p, dict)
        ),
    )


def import_supplier_cbom(
    raw: bytes,
    *,
    supplier: str,
    imported_at: datetime | None = None,
) -> SupplierIntakeResult:
    """Validate, verify, and parse one supplier CBOM. Raises
    `MalformedCbomError`, `SchemaValidationError`, or
    `UnsupportedSpecVersionError` on bad input; never returns a partial
    result for input it rejected."""
    if not supplier.strip():
        raise ValueError("supplier name must not be blank")

    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise MalformedCbomError(f"not UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise MalformedCbomError(f"not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise MalformedCbomError("top-level CBOM document must be a JSON object")

    spec_version = document.get("specVersion")
    if spec_version != SPEC_VERSION:
        raise UnsupportedSpecVersionError(
            f"specVersion {spec_version!r} is not supported; this build only carries a "
            f"bundled schema for CycloneDX {SPEC_VERSION} (no schemas/cyclonedx-1.7.schema.json "
            "is vendored, so a 1.7 document is reported unsupported rather than validated "
            "against the wrong schema)"
        )

    validate(document)  # raises SchemaValidationError

    signature_status = SignatureStatus.UNVERIFIED
    signature_key_id: str | None = None
    if "signature" in document:
        signature_key_id = (document.get("signature") or {}).get("keyId")
        try:
            verify_bom(document)
            signature_status = SignatureStatus.VERIFIED
        except SignatureVerificationError:
            signature_status = SignatureStatus.INVALID

    tool_name, tool_version = _producing_tool(document)
    components = tuple(
        parsed
        for component in (document.get("components") or ())
        if isinstance(component, dict) and (parsed := _parse_component(component)) is not None
    )

    provenance = SupplierProvenance(
        supplier=supplier,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        imported_at=imported_at or datetime.now(timezone.utc),
        signature_status=signature_status,
        signature_key_id=signature_key_id,
        cbom_serial_number=document.get("serialNumber"),
        cbom_version=document.get("version"),
        cbom_spec_version=str(spec_version),
        source_tool=tool_name,
        source_tool_version=tool_version,
    )
    return SupplierIntakeResult(provenance=provenance, components=components)


__all__ = [
    "MalformedCbomError",
    "UnsupportedSpecVersionError",
    "SchemaValidationError",
    "import_supplier_cbom",
]
