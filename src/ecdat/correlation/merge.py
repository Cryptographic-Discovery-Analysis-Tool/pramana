"""Within-surface CryptoAsset merge (Final Architecture Part 5 "Asset
resolution (deliberately constrained)").

    "Canonical asset key = (algorithm_family, parameters, purpose,
    scope_anchor) where scope_anchor is per-surface: repo path, image + layer
    digest, host:port, or binary path. Within a surface: merge aggressively
    ... Across surfaces: do not merge. Emit explicit relationship edges
    instead."

This module does ONLY the within-surface half of Part 5: group Findings from
ONE adapter/surface into `CryptoAsset` records. Cross-surface relationship
GENERATION -- the declared/artifact_asserted edges Part 5 also describes
("TLS endpoint -> served by -> container image -> contains -> OpenSSL
package") -- needs topology/context input this module is never given, and is
explicitly out of scope here. `src/ecdat/correlation/gate.py` is the other
half of this phase: a pure check over whatever Relationships an orchestrator
eventually assembles.

Everything a merge key reads comes only from fields a real adapter Finding
actually populates (grounded in each cited adapter's own `_fields()`
method) -- `purpose` is never one of them (that is function.classifier's
separate job, done later with more context than one Finding carries), so it
is never part of any grouping key and never invented.

**Which surfaces get Part 5's aggressive algorithm-based merge, and which
don't.** Part 5's literal key `(algorithm_family, parameters, purpose,
scope_anchor)` was written about *cryptographic algorithm assets* --
"all RSA-2048 signing in repo X collapses to one asset" is its own example.
Only two adapters today actually describe an algorithm-in-use the way that
key means: `certs-x509` (public_key_algorithm/size/curve) and `tls-endpoint`
(the negotiated group/suite/protocol). `_KEY_SIGNATURES` below recognises
exactly those two field-shapes, each grounded in the cited adapter's own
`_fields()` code, and NO OTHERS. A Finding that matches neither signature
(packages-trivy, images-cbomkit-theia, hsm-pkcs11, binary-yara-readelf,
config-chain-spring, source-semgrep) gets **no** algorithm-based merge at
all: it becomes its own single-Finding CryptoAsset. That is the conservative
default, and it is deliberate -- inventing an untested merge rule for a
surface Part 5 never discussed (e.g. "two Trivy packages with the same name
merge") would be exactly the kind of unfounded rule CLAUDE.md's
anti-hallucination section exists to prevent. Extending this to a new
surface later is a one-line addition to `_KEY_SIGNATURES`, made when that
surface's own field shape is known -- not a guess made here ahead of time.

`algorithm_family` is deliberately NOT part of the strict grouping-equality
key for the certs signature, even though Part 5's literal key tuple lists
it. See docs/deviations.md DEV-007 for why: two Findings that disagree on it
must still be able to land in one CryptoAsset with a CONFLICTING field
(R-MONOTONE -- silently reporting "two unrelated, individually-certain
assets" instead of "one asset, disputed field" would manufacture unsupported
*distinctness*). `algorithm_family` flows through the same agree/CONFLICT
field-merge path as every other field instead.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import NamedTuple

from ecdat.model.asset import CryptoAsset
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding

#: (required field-signature, ordered key fields) pairs. See "Which surfaces
#: get Part 5's aggressive algorithm-based merge, and which don't" above.
#: Checked in order; the first signature that is a subset of a Finding's
#: field names wins. Field names are quoted verbatim from the cited
#: adapter's own `_fields()` method -- never guessed.
_KEY_SIGNATURES: tuple[tuple[frozenset[str], tuple[str, ...]], ...] = (
    # certs-x509 -- src/ecdat/adapters/certs/adapter.py CertificateAdapter._fields()
    # ("public_key_algorithm" alone disambiguates: hsm-pkcs11 has a
    # similarly-named "algorithm_family" field, never this exact name).
    # `algorithm_family` is deliberately NOT one of the key fields here --
    # see DEV-007 in the module docstring: two Findings disagreeing on it
    # must still land in one CryptoAsset with a CONFLICTING field, which
    # would be structurally impossible if algorithm were part of the key
    # two disagreeing Findings would never even group together.
    (
        frozenset({"public_key_algorithm"}),
        ("public_key_size", "public_key_curve"),
    ),
    # tls-endpoint -- src/ecdat/adapters/tls/adapter.py TlsEndpointAdapter._fields()
    # `negotiated_group` is excluded from the key for the same DEV-007
    # reason as certs' algorithm above; `negotiated_cipher_suite` and
    # `negotiated_protocol` distinguish genuinely different negotiated
    # configurations observed at the same scope_anchor.
    (
        frozenset({"negotiated_group", "negotiated_cipher_suite"}),
        ("negotiated_cipher_suite", "negotiated_protocol"),
    ),
)

#: Candidate field names for CryptoAsset's plain `algorithm_family` readback,
#: tried in this order. Convenience only -- the evidentiary field is
#: whichever of these actually exists in `fields`, per-Finding, unchanged.
#: "algorithm" is `adapters/source/semgrep.py`'s field name for a call
#: site's literal JCA algorithm/transformation string (e.g. "RSA/ECB/OAEP...",
#: "AES/GCM/NoPadding", "HmacSHA256") -- added 2026-09-28 (quickscan demo
#: root cause: without it, no source-semgrep Finding ever carried an
#: `algorithm_family` at all, so a concrete algorithm found in Java source
#: was silently excluded from every quantum-vulnerable count rather than
#: showing up as vulnerable, not-vulnerable or honestly unclassified).
_ALGORITHM_FAMILY_READBACK_CANDIDATES: tuple[str, ...] = (
    "public_key_algorithm",
    "negotiated_group",
    "algorithm",
)


class MergeKey(NamedTuple):
    """The grouping identity for one CryptoAsset. See module docstring and
    DEV-007 for why `algorithm_family` is read (for the convenience readback
    field) but not included here."""

    parameters: tuple
    scope_anchor: str


def _field_value(finding: Finding, name: str):
    field = finding.fields.get(name)
    return field.value if field is not None else None


def _key_fields_for(finding: Finding) -> tuple[str, ...] | None:
    """Which signature (if any) this Finding's fields match. None means no
    recognised algorithm-shaped signature -- see the module docstring."""
    names = frozenset(finding.fields)
    for signature, key_fields in _KEY_SIGNATURES:
        if signature <= names:
            return key_fields
    return None


def _merge_key(finding: Finding) -> MergeKey:
    key_fields = _key_fields_for(finding)
    if key_fields is None:
        # No recognised algorithm-shaped signature: one asset per Finding,
        # the conservative default (module docstring). `finding_id` is
        # unique per Finding by the Finding model's own contract, so this
        # can never accidentally collide with another Finding's key.
        parameters: tuple = (finding.finding_id,)
    else:
        parameters = tuple(_field_value(finding, name) for name in key_fields)
    # scope_anchor: naturally the surface string already on the Finding (e.g.
    # "certdir:<root>") -- Part 5: "scope_anchor is per-surface: repo path,
    # image + layer digest, host:port, or binary path." This is what makes
    # cross-surface merging structurally impossible: two Findings with a
    # different `surface` can never land in the same group.
    return MergeKey(parameters=parameters, scope_anchor=finding.surface)


def _parameters_string(parameters: tuple) -> str | None:
    parts = [str(part) for part in parameters if part is not None]
    return "/".join(parts) if parts else None


def _asset_id(key: MergeKey) -> str:
    canonical = f"{key.scope_anchor}|{_parameters_string(key.parameters)}"
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return f"asset:{digest}"


def _merge_field(name: str, values: list[FieldValue]) -> FieldValue:
    """Merge one field name across a group of Findings that share a merge key.

    R-MONOTONE (CLAUDE.md): more evidence never manufactures unsupported
    certainty. A field stays a single value only when every contributing
    Finding reports the SAME value under the SAME epistemic state; any
    disagreement -- in the value or in the certainty behind it -- becomes
    CONFLICTING with no value chosen, rather than silently keeping one side's
    answer.
    """
    evidence_refs = tuple(dict.fromkeys(ref for value in values for ref in value.evidence_refs))
    first = values[0]
    all_agree = all(value.value == first.value and value.state == first.state for value in values)

    if all_agree:
        return FieldValue(value=first.value, state=first.state, evidence_refs=evidence_refs)

    distinct_values: list = []
    for value in values:
        if value.value not in distinct_values:
            distinct_values.append(value.value)
    return FieldValue(
        value=None,
        state=EpistemicState.CONFLICTING,
        resolution=Resolution(
            status=ResolutionStatus.UNRESOLVED,
            reason=(
                f"merged Findings within one surface disagree on {name!r}: "
                f"{[str(value) for value in distinct_values]}"
            ),
        ),
        evidence_refs=evidence_refs,
    )


def _plain_readback(fields: dict[str, FieldValue], name: str) -> str | None:
    """Read one field back out as CryptoAsset's plain convenience string,
    only when it is not itself in dispute -- a CONFLICTING field never gets
    silently collapsed into a single string on the asset (R-MONOTONE)."""
    field = fields.get(name)
    if field is None or field.state == EpistemicState.CONFLICTING or field.value is None:
        return None
    return str(field.value)


def _algorithm_family_readback(fields: dict[str, FieldValue]) -> str | None:
    for name in _ALGORITHM_FAMILY_READBACK_CANDIDATES:
        value = _plain_readback(fields, name)
        if value is not None:
            return value
    return None


def merge_within_surface(findings: Iterable[Finding]) -> tuple[CryptoAsset, ...]:
    """Group Findings from ONE adapter/surface into CryptoAsset records.

    Findings from different surfaces (different `finding.surface`, i.e.
    different scope_anchor) NEVER merge, even when algorithm/parameters match
    byte-for-byte: Part 5's "within a surface only" rule is enforced by
    including scope_anchor in the grouping key itself, so a caller cannot
    accidentally defeat it by passing mixed-surface input to this function.

    Cross-surface relationship generation is explicitly out of scope for this
    function; see the module docstring.
    """
    groups: dict[MergeKey, list[Finding]] = {}
    matched_signature: dict[MergeKey, bool] = {}
    for finding in findings:
        key = _merge_key(finding)
        groups.setdefault(key, []).append(finding)
        matched_signature[key] = _key_fields_for(finding) is not None

    assets: list[CryptoAsset] = []
    for key, group in groups.items():
        field_names: dict[str, None] = {}
        for finding in group:
            for name in finding.fields:
                field_names.setdefault(name, None)

        fields: dict[str, FieldValue] = {}
        for name in field_names:
            values = [finding.fields[name] for finding in group if name in finding.fields]
            if values:
                fields[name] = _merge_field(name, values)

        assets.append(
            CryptoAsset(
                asset_id=_asset_id(key),
                scope_anchor=key.scope_anchor,
                algorithm_family=_algorithm_family_readback(fields),
                # `key.parameters` is the Finding's own finding_id, not real
                # crypto parameters, when no signature matched (see
                # `_merge_key`) -- do not read that back as if it meant
                # something about the asset's algorithm parameters.
                parameters=_parameters_string(key.parameters) if matched_signature[key] else None,
                purpose=_plain_readback(fields, "purpose"),
                finding_refs=tuple(finding.finding_id for finding in group),
                fields=fields,
            )
        )

    return tuple(assets)
