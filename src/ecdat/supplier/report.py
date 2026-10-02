"""Per-supplier coverage/gaps report (task item 4).

Nothing here computes a new judgement about risk: it counts
`ComponentCorrelation` outcomes `supplier/correlate.py` already produced,
flags declared components whose algorithm family is cited quantum-
vulnerable in `data/crypto_families.yaml` (the same registry
`risk/confidentiality_ledger.py` and `risk/policy.py` already use -- no
family classification is invented here), and, when a sector is given,
names which of that sector's cited policy keys apply
(`risk/sector.py`'s own `data/sector_profiles.yaml`-backed mapping) --
never a second copy of the sector traffic-light calculation itself.
"""
from __future__ import annotations

from datetime import datetime

from ecdat.data.crypto_families import NoCitedFamilyError, canonical_family, is_shor_broken
from ecdat.risk.sector import UnknownSectorError, sector_profile
from ecdat.supplier.models import (
    ComponentCorrelation,
    CoverageStatus,
    QuantumVulnerableDeclaration,
    SupplierComponent,
    SupplierCoverageReport,
)

_CITATION = "data/crypto_families.yaml (shor_broken row)"


def _quantum_vulnerable_declarations(
    components: tuple[SupplierComponent, ...],
) -> tuple[QuantumVulnerableDeclaration, ...]:
    flagged: list[QuantumVulnerableDeclaration] = []
    for component in components:
        family = component.algorithm_family
        if not family:
            continue
        canonical = canonical_family(family)
        try:
            if not is_shor_broken(canonical):
                continue
        except NoCitedFamilyError:
            # Not classified either way -- never guessed (module docstring
            # and data.crypto_families' own docstring: "a family with no
            # usable row is UNKNOWN, which produces ... a closure task, not
            # a guess").
            continue
        flagged.append(
            QuantumVulnerableDeclaration(
                bom_ref=component.bom_ref,
                name=component.name,
                family=canonical,
                citation=_CITATION,
            )
        )
    return tuple(flagged)


def coverage_report(
    *,
    supplier: str,
    as_of: datetime,
    components: tuple[SupplierComponent, ...],
    correlations: tuple[ComponentCorrelation, ...],
    sector_key: str | None = None,
) -> SupplierCoverageReport:
    counts = {status: 0 for status in CoverageStatus}
    for correlation in correlations:
        counts[correlation.status] += 1

    sector_obligation_keys: tuple[str, ...] = ()
    sector_label: str | None = None
    if sector_key is not None:
        try:
            profile = sector_profile(sector_key)
        except UnknownSectorError:
            raise
        sector_label = profile.key
        sector_obligation_keys = tuple(p.policy_key for p in profile.policies)

    return SupplierCoverageReport(
        supplier=supplier,
        as_of=as_of,
        declared_count=len(components),
        corroborated_count=counts[CoverageStatus.CORROBORATED],
        conflicting_count=counts[CoverageStatus.CONFLICTING],
        declared_only_count=counts[CoverageStatus.DECLARED_ONLY],
        observed_only_count=counts[CoverageStatus.OBSERVED_ONLY],
        correlations=correlations,
        quantum_vulnerable=_quantum_vulnerable_declarations(components),
        sector=sector_label,
        sector_obligation_policy_keys=sector_obligation_keys,
    )


__all__ = ["coverage_report"]
