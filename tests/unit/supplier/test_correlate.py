"""Correlating supplier-DECLARED components against our own KNOWN scan
inventory (task item 3): agreement, conflict, declared-only, observed-only.
"""
from __future__ import annotations

from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.supplier.correlate import correlate_supplier
from ecdat.supplier.models import CoverageStatus, SupplierComponent

CERT_HASH = "b" * 64
KEY_HASH = "c" * 64


def _known(value):
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=("ev:our-scan",))


def _our_cert_asset(*, algorithm_family: str) -> CryptoAsset:
    return CryptoAsset(
        asset_id="asset:cert-1",
        scope_anchor="certdir:/vendor",
        algorithm_family=algorithm_family,
        fields={
            "der_sha256": _known(CERT_HASH),
            "public_key_algorithm": _known(algorithm_family),
        },
    )


def _our_unrelated_asset() -> CryptoAsset:
    return CryptoAsset(
        asset_id="asset:unmatched-1",
        scope_anchor="certdir:/other",
        algorithm_family="RSA",
        fields={"der_sha256": _known("d" * 64)},
    )


def test_matching_hash_and_agreeing_algorithm_is_corroborated():
    component = SupplierComponent(
        bom_ref="crypto/cert-1",
        name="leaf-cert",
        asset_type="certificate",
        curve="X25519",
        der_sha256=CERT_HASH,
    )
    our_assets = (_our_cert_asset(algorithm_family="X25519"),)

    correlations = correlate_supplier((component,), our_assets)

    assert len(correlations) == 1
    result = correlations[0]
    assert result.status == CoverageStatus.CORROBORATED
    assert result.matched_field == "der_sha256"
    assert result.our_asset_id == "asset:cert-1"
    assert result.declared_value == "X25519"
    assert result.observed_value == "X25519"


def test_matching_hash_but_disagreeing_algorithm_is_conflicting():
    """The task's own worked example: supplier declares ML-KEM, we observed
    only X25519 -- CONFLICTING, both evidences kept."""
    component = SupplierComponent(
        bom_ref="crypto/cert-1",
        name="leaf-cert",
        asset_type="algorithm",
        primitive="kem",
        parameter_set_identifier="ML-KEM",
        der_sha256=CERT_HASH,
    )
    our_assets = (_our_cert_asset(algorithm_family="X25519"),)

    correlations = correlate_supplier((component,), our_assets)

    assert len(correlations) == 1
    result = correlations[0]
    assert result.status == CoverageStatus.CONFLICTING
    assert result.declared_value == "ML-KEM"
    assert result.observed_value == "X25519"
    assert result.our_evidence_refs == ("ev:our-scan",)


def test_supplier_component_with_no_matching_hash_is_declared_only():
    component = SupplierComponent(
        bom_ref="crypto/cert-9",
        name="unrelated-cert",
        asset_type="certificate",
        der_sha256="f" * 64,
    )
    correlations = correlate_supplier((component,), (_our_unrelated_asset(),))

    statuses = {c.supplier_component_bom_ref: c.status for c in correlations}
    assert statuses["crypto/cert-9"] == CoverageStatus.DECLARED_ONLY


def test_our_asset_with_no_matching_supplier_component_is_observed_only():
    correlations = correlate_supplier((), (_our_unrelated_asset(),))

    assert len(correlations) == 1
    assert correlations[0].status == CoverageStatus.OBSERVED_ONLY
    assert correlations[0].our_asset_id == "asset:unmatched-1"


def test_asset_with_no_identity_hash_is_never_reported_observed_only():
    """R-UNSEEN: a CryptoAsset that never carried a der_sha256/spki_sha256
    KNOWN field cannot be joined to a supplier CBOM at all, and must not be
    silently reported as a coverage gap either."""
    asset = CryptoAsset(asset_id="asset:no-hash", scope_anchor="certdir:/x", fields={})
    correlations = correlate_supplier((), (asset,))
    assert correlations == ()


def test_spki_only_match_is_used_when_no_der_hash_matches():
    component = SupplierComponent(
        bom_ref="crypto/key-1",
        name="public-key",
        asset_type="related-crypto-material",
        related_material_type="public-key",
        curve="P-256",
        spki_sha256=KEY_HASH,
    )
    asset = CryptoAsset(
        asset_id="asset:key-1",
        scope_anchor="certdir:/vendor",
        algorithm_family="P-256",
        fields={"spki_sha256": _known(KEY_HASH)},
    )
    correlations = correlate_supplier((component,), (asset,))
    assert len(correlations) == 1
    assert correlations[0].status == CoverageStatus.CORROBORATED
    assert correlations[0].matched_field == "spki_sha256"
