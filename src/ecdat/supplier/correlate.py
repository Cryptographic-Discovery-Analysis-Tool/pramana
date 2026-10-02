"""Correlate a supplier's DECLARED components against our own KNOWN scan
inventory (task item 3).

Joined ONLY by content-identity hash (`der_sha256` / `spki_sha256`) -- the
same two fields CLAUDE.md names as the only legitimate cross-surface
identity signal, and the same two `correlation/engine.py` already treats
that way for our own multi-adapter findings. No weaker signal (matching on
a certificate subject string, a component name, an algorithm name alone)
is used to decide two records describe the same real-world object: that
would be exactly the kind of unfounded merge Part 5 and R-UNSEEN warn
against, and a name collision between an unrelated supplier component and
one of our own assets is far more likely than a SHA-256 collision.

For every supplier component whose declared hash matches one of our own
`CryptoAsset`s' KNOWN hash field, the pair's declared vs. observed
algorithm-shaped fields (`algorithm_family`/`parameters` readback on our
side, `algorithm_family` property on the supplier side) are compared:

* same value -> CORROBORATED ("supplier claim corroborated", task item 3).
* different value -> CONFLICTING, with both evidences kept -- "this is a
  key selling point" per the task brief.

A supplier component with a declared hash that matches nothing of ours is
DECLARED_ONLY: real evidence of a gap in our own inventory, or of an asset
we have simply never scanned. Symmetrically, one of our own assets whose
KNOWN hash matches no supplier component is OBSERVED_ONLY: we see it, the
supplier's CBOM never mentioned it.
"""
from __future__ import annotations

from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState
from ecdat.supplier.models import ComponentCorrelation, CoverageStatus, SupplierComponent

_DER_FIELD = "der_sha256"
_SPKI_FIELD = "spki_sha256"


def _our_hash_index(assets: tuple[CryptoAsset, ...], field_name: str) -> dict[str, CryptoAsset]:
    """asset keyed by every KNOWN, non-empty value of `field_name`. Mirrors
    `correlation/engine.py::_hash_groups`'s own R-UNSEEN posture: a
    CONFLICTING or absent hash on our side never participates -- an
    identity claim needs a positively observed hash, not the mere
    possibility of one. Unlike `_hash_groups`, this keeps a single winner
    per hash (first asset wins; a hash collision across our own assets is
    itself already reported by `correlation/engine.py`'s own same-object
    relationships and is not this module's concern)."""
    index: dict[str, CryptoAsset] = {}
    for asset in assets:
        field = asset.fields.get(field_name)
        if field is None or field.state != EpistemicState.KNOWN or not field.value:
            continue
        index.setdefault(str(field.value), asset)
    return index


def _our_algorithm_readback(asset: CryptoAsset) -> str | None:
    return asset.algorithm_family or asset.parameters


def correlate_supplier(
    components: tuple[SupplierComponent, ...],
    our_assets: tuple[CryptoAsset, ...],
) -> tuple[ComponentCorrelation, ...]:
    der_index = _our_hash_index(our_assets, _DER_FIELD)
    spki_index = _our_hash_index(our_assets, _SPKI_FIELD)

    correlations: list[ComponentCorrelation] = []
    matched_asset_ids: set[str] = set()

    for component in components:
        matched_field = ""
        matched_hash: str | None = None
        asset: CryptoAsset | None = None
        if component.der_sha256 and component.der_sha256 in der_index:
            matched_field = _DER_FIELD
            matched_hash = component.der_sha256
            asset = der_index[matched_hash]
        elif component.spki_sha256 and component.spki_sha256 in spki_index:
            matched_field = _SPKI_FIELD
            matched_hash = component.spki_sha256
            asset = spki_index[matched_hash]

        if asset is None:
            correlations.append(
                ComponentCorrelation(
                    supplier_component_bom_ref=component.bom_ref,
                    supplier_component_name=component.name,
                    matched_field="",
                    matched_hash=None,
                    our_asset_id=None,
                    status=CoverageStatus.DECLARED_ONLY,
                    declared_value=component.algorithm_family,
                    observed_value=None,
                    reason=(
                        "supplier declares this component; no der_sha256/spki_sha256 in our "
                        "own inventory matches it (either an unscanned asset, or one that "
                        "carries no identity hash on our side)"
                    ),
                )
            )
            continue

        matched_asset_ids.add(asset.asset_id)
        declared_value = component.algorithm_family
        observed_value = _our_algorithm_readback(asset)
        if declared_value is not None and observed_value is not None and declared_value != observed_value:
            status = CoverageStatus.CONFLICTING
            reason = (
                f"identity confirmed via {matched_field}={matched_hash}, but supplier declares "
                f"{declared_value!r} while our own scan observed {observed_value!r}"
            )
        else:
            status = CoverageStatus.CORROBORATED
            reason = f"identity confirmed via {matched_field}={matched_hash}; declared value agrees with our observation"

        matched_field_evidence = asset.fields.get(matched_field)
        correlations.append(
            ComponentCorrelation(
                supplier_component_bom_ref=component.bom_ref,
                supplier_component_name=component.name,
                matched_field=matched_field,
                matched_hash=matched_hash,
                our_asset_id=asset.asset_id,
                status=status,
                declared_value=declared_value,
                observed_value=observed_value,
                reason=reason,
                our_evidence_refs=matched_field_evidence.evidence_refs if matched_field_evidence else (),
            )
        )

    for asset in our_assets:
        if asset.asset_id in matched_asset_ids:
            continue
        has_identity_hash = any(
            asset.fields.get(name) is not None and asset.fields[name].state == EpistemicState.KNOWN
            for name in (_DER_FIELD, _SPKI_FIELD)
        )
        if not has_identity_hash:
            continue
        correlations.append(
            ComponentCorrelation(
                supplier_component_bom_ref="",
                supplier_component_name="",
                matched_field="",
                matched_hash=None,
                our_asset_id=asset.asset_id,
                status=CoverageStatus.OBSERVED_ONLY,
                declared_value=None,
                observed_value=_our_algorithm_readback(asset),
                reason="we observed this asset; no component in the supplier's CBOM declares a matching hash",
            )
        )

    return tuple(correlations)


__all__ = ["correlate_supplier"]
