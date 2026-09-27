"""Per-supplier coverage/gaps report (task item 4)."""
from __future__ import annotations

from datetime import datetime, timezone

from ecdat.risk.sector import UnknownSectorError
from ecdat.supplier.correlate import correlate_supplier
from ecdat.supplier.models import CoverageStatus
from ecdat.supplier.report import coverage_report
from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.supplier.models import SupplierComponent

AS_OF = datetime(2026, 9, 27, tzinfo=timezone.utc)


def _known(value):
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=("ev:our-scan",))


def test_coverage_report_counts_and_flags_quantum_vulnerable_declarations():
    components = (
        SupplierComponent(
            bom_ref="crypto/1",
            name="rsa-transport",
            asset_type="algorithm",
            primitive="pke",
            curve=None,
            parameter_set_identifier=None,
        ),
        SupplierComponent(
            bom_ref="crypto/2",
            name="x25519-kex",
            asset_type="algorithm",
            curve="X25519",
        ),
    )
    # RSA has no usable `curve`/`primitive` naming match in crypto_families.yaml
    # (its cited row keys on "RSA"), so use a component whose algorithm_family
    # readback is literally "X25519" -- a cited, shor_broken=true row.
    correlations = correlate_supplier(components, ())

    report = coverage_report(
        supplier="Acme Vendor",
        as_of=AS_OF,
        components=components,
        correlations=correlations,
    )

    assert report.supplier == "Acme Vendor"
    assert report.declared_count == 2
    assert report.declared_only_count == 2
    assert report.corroborated_count == 0
    assert report.conflicting_count == 0
    assert report.observed_only_count == 0

    flagged = {q.bom_ref for q in report.quantum_vulnerable}
    assert "crypto/2" in flagged  # X25519 is cited shor_broken: true
    assert "crypto/1" not in flagged  # "pke" is not a cited family key


def test_coverage_report_with_conflicts_and_sector():
    component = SupplierComponent(
        bom_ref="crypto/cert-1",
        name="leaf-cert",
        asset_type="algorithm",
        parameter_set_identifier="ML-KEM",
        primitive="kem",
        der_sha256="e" * 64,
    )
    asset = CryptoAsset(
        asset_id="asset:cert-1",
        algorithm_family="X25519",
        fields={
            "der_sha256": _known("e" * 64),
            "public_key_algorithm": _known("X25519"),
        },
    )
    correlations = correlate_supplier((component,), (asset,))

    report = coverage_report(
        supplier="Acme Vendor",
        as_of=AS_OF,
        components=(component,),
        correlations=correlations,
        sector_key="bfsi",
    )

    assert report.conflicting_count == 1
    conflict = next(c for c in report.correlations if c.status == CoverageStatus.CONFLICTING)
    assert conflict.declared_value == "ML-KEM"
    assert conflict.observed_value == "X25519"
    assert report.sector == "bfsi"
    assert isinstance(report.sector_obligation_policy_keys, tuple)


def test_unknown_sector_raises():
    import pytest

    with pytest.raises(UnknownSectorError):
        coverage_report(
            supplier="Acme Vendor",
            as_of=AS_OF,
            components=(),
            correlations=(),
            sector_key="not-a-real-sector",
        )
