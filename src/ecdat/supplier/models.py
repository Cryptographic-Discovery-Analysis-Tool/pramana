"""Supplier CBOM intake record types (SIH26164: India DST "Roadmap to Quantum
Resiliency" makes vendor CBOM submission mandatory from FY2027-28,
docs/sources/India_DST_Quantum_Safe_Roadmap_2026.md; RBI's Q-SAFE committee
evaluates banks via CBOMs, docs/sources/IN_RBI_QSAFE_Committee_2026.md).

A regulated org (bank, telco) ingests a supplier's CycloneDX CBOM as
*evidence about a third party's inventory*, never as our own observation.
CLAUDE.md hard rule and `export/cyclonedx.py`'s own docstring are both
explicit: another tool asserting an algorithm exists is a statement, not
something we saw ourselves. Every field this module produces from a
supplier's document is therefore `EpistemicState.DECLARED` and only
DECLARED -- there is no code path in this package that can promote a
supplier claim to KNOWN. Recording it as KNOWN would launder a third
party's certainty into ours, which R-MONOTONE forbids.

This module holds only the plain record shapes (provenance, one parsed
component, one correlation entry, one coverage report). Parsing lives in
`supplier/intake.py`; comparing against our own asset model lives in
`supplier/correlate.py`; summarising lives in `supplier/report.py`.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from ecdat.model.epistemic import EpistemicState


class SignatureStatus(str, Enum):
    """Three states only -- deliberately not a boolean. A CBOM with no
    `signature` block at all is neither valid nor invalid; conflating
    "not signed" with "signature failed to verify" would let an unsigned
    document masquerade as merely-unverified when it is missing evidence
    entirely, and would let a tampered one masquerade as merely-absent."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INVALID = "INVALID"


class SupplierProvenance(BaseModel):
    """Provenance recorded for one supplier CBOM import (task item 2:
    "Record provenance (supplier, file SHA-256, import time, signature
    status, CBOM serialNumber/version)"). Frozen -- an import, once
    recorded, is a fact about that import; re-importing produces a new
    provenance record, never an edit to an old one (same posture as
    `store/repository.py`'s `Run`)."""

    model_config = ConfigDict(frozen=True)

    supplier: str
    file_sha256: str
    imported_at: datetime
    signature_status: SignatureStatus
    signature_key_id: str | None = None
    cbom_serial_number: str | None = None
    cbom_version: int | None = None
    cbom_spec_version: str
    source_tool: str
    source_tool_version: str

    @field_validator("supplier", "file_sha256", "cbom_spec_version", "source_tool", "source_tool_version")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


class SupplierComponent(BaseModel):
    """One `cryptographic-asset` component read out of a supplier's CBOM,
    with the fields this task's merge/correlate step actually needs
    (algorithm, key size/curve, certificate fingerprints, protocol) --
    quoted verbatim from the bundled CycloneDX 1.6 schema's own field
    names (`schemas/cyclonedx-1.6.schema.json` `cryptoProperties`,
    `algorithmProperties`, `certificateProperties`,
    `relatedCryptoMaterialProperties`, `protocolProperties`), never
    guessed. `state` is always DECLARED (see module docstring) and is not
    a free parameter -- the validator below enforces it, the same closed
    posture `export/cyclonedx.py::ImportedCryptoAsset` already takes for
    a plainer subset of these same fields.

    `der_sha256` / `spki_sha256`: a supplier's own component `hashes[]`
    entry, tagged onto this model only when the CBOM's own `assetType`
    already says what kind of object the hash is over (`certificate` ->
    `der_sha256`, a `related-crypto-material` of type `public-key` ->
    `spki_sha256`). This is a naming-identity readback, exactly the
    convention `correlation/engine.py::_DER_FIELD` /
    `_SPKI_FIELD` already use for our own findings -- never a guess at
    what a supplier's unlabelled hash covers.
    """

    model_config = ConfigDict(frozen=True)

    bom_ref: str
    name: str
    asset_type: str
    state: EpistemicState = EpistemicState.DECLARED
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    curve: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_format: str | None = None
    related_material_type: str | None = None
    key_size_bits: int | None = None
    protocol_type: str | None = None
    protocol_version: str | None = None
    der_sha256: str | None = None
    spki_sha256: str | None = None
    oid: str | None = None
    properties: tuple[tuple[str, str], ...] = ()

    @field_validator("bom_ref", "name", "asset_type")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("state")
    @classmethod
    def _must_be_declared(cls, value: EpistemicState) -> EpistemicState:
        if value != EpistemicState.DECLARED:
            raise ValueError(
                "SupplierComponent.state is always DECLARED -- a supplier's "
                "claim is never promoted to KNOWN by this module (R-MONOTONE)"
            )
        return value

    @property
    def algorithm_family(self) -> str | None:
        """Best-effort readback for display and quantum-vulnerability
        lookup: the algorithm/curve naming this component actually
        carries, in the order a family classification is most likely to
        key on. Convenience only -- `data.crypto_families.is_shor_broken`
        is the only place that turns this into a claim."""
        return self.curve or self.parameter_set_identifier or self.primitive


class CoverageStatus(str, Enum):
    """Per-identity correlation outcome (task item 3/4: "coverage/gaps
    report per supplier: components declared vs observed"). A closed set,
    same discipline as every other enum in this codebase."""

    CORROBORATED = "CORROBORATED"
    CONFLICTING = "CONFLICTING"
    DECLARED_ONLY = "DECLARED_ONLY"
    OBSERVED_ONLY = "OBSERVED_ONLY"


class ComponentCorrelation(BaseModel):
    """One correlation outcome between a supplier's DECLARED component and
    our own scan inventory, joined ONLY by a shared content-identity hash
    (`der_sha256` / `spki_sha256`) -- the same two fields
    `correlation/engine.py` already treats as the sole legitimate
    cross-surface identity signal (CLAUDE.md: "Never merge across
    surfaces. Only cross-surface identity: same-object (SHA-256 of cert
    DER), shares-public-key (SHA-256 of SPKI DER)."). No weaker signal
    (name matching, subject-string matching) is used to join a supplier
    claim to our own asset -- that would be exactly the over-claim
    R-UNSEEN warns against.

    `epistemic_state` is CONFLICTING or a plain closed-set status word,
    never routed through `model.field_value.derive()` or
    `model.relationship.Relationship`: this is a plain comparison record,
    not a derived field or a graph edge, so neither the CLAUDE.md
    R-DERIVE `rule_id` requirement nor the Relationship contract's
    `rule_id`-for-CONFLICTING requirement applies to it (see DEV entry
    for why no rule_id is registered for this).
    """

    model_config = ConfigDict(frozen=True)

    supplier_component_bom_ref: str
    supplier_component_name: str
    matched_field: str  # "der_sha256" | "spki_sha256" | None -> "" when unmatched
    matched_hash: str | None
    our_asset_id: str | None
    status: CoverageStatus
    declared_value: str | None
    observed_value: str | None
    reason: str
    supplier_evidence_refs: tuple[str, ...] = ()
    our_evidence_refs: tuple[str, ...] = ()


class QuantumVulnerableDeclaration(BaseModel):
    model_config = ConfigDict(frozen=True)

    bom_ref: str
    name: str
    family: str
    citation: str


class SupplierIntakeResult(BaseModel):
    """What `supplier.intake.import_supplier_cbom` returns: provenance plus
    every parsed component. Nothing here is a coverage judgement -- that is
    `supplier.report.coverage_report`'s job, and it needs our own asset
    inventory as a second input that intake alone never has."""

    model_config = ConfigDict(frozen=True)

    provenance: SupplierProvenance
    components: tuple[SupplierComponent, ...]


class SupplierCoverageReport(BaseModel):
    """Task item 4: "Coverage/gaps report per supplier: components declared
    vs observed, conflicts, crypto that is quantum-vulnerable, and which
    sector obligations ... the supplier's assets fall under." Every count
    here is read directly off `correlations`/`quantum_vulnerable` -- no
    number in this model is computed anywhere else."""

    model_config = ConfigDict(frozen=True)

    supplier: str
    as_of: datetime
    declared_count: int
    corroborated_count: int
    conflicting_count: int
    declared_only_count: int
    observed_only_count: int
    correlations: tuple[ComponentCorrelation, ...]
    quantum_vulnerable: tuple[QuantumVulnerableDeclaration, ...]
    sector: str | None = None
    sector_obligation_policy_keys: tuple[str, ...] = ()
