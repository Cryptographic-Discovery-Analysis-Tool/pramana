"""India sector-specific compliance views (SIH26164).

A "sector" is an operator-selected lens (BFSI, Telecom, Critical Information
Infrastructure, Government/general enterprise) over the same ledger rows
`risk/policy.py` already annotates. This module adds nothing new to a band:
exactly like `risk/policy.py`, it only asks, for the policy rows a cited
source (`data/sector_profiles.yaml`) says apply to the selected sector,
whether each row's nearest OPEN dated milestone is comfortably away, close,
or already past -- a traffic light over `PolicyAnnotation.status`, never a
second risk calculation.

Two things stay honest by construction:

* `data/sector_profiles.yaml` rows are checked by
  `tools/ci/check_data_citations.py` exactly like every other data/ file --
  the claim "policy X applies to sector Y" carries its own citation and
  quote, same as a policy deadline or a confidence value.
* A policy mapped to a sector but `usable: false` in
  `data/policy_deadlines.yaml` (SEBI CSCRF, the RBI Master Direction, the
  RBI Q-SAFE committee, the TEC telecom report -- none state a calendar
  date) is never coerced into a light. It is surfaced separately as an
  undated `ObligationRef`, labelled "obligation, no deadline" by callers.

`at_risk_days` is an engineering choice, not a citation -- there is no
regulatory source for "how many days before a deadline counts as amber".
It defaults to 180 and every caller can override it; it is never hidden
inside a silent default the way CLAUDE.md forbids for cited constants.
"""
from __future__ import annotations

from datetime import date
from enum import Enum
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from ecdat.risk.policy import PolicyAnnotation, PolicyStatus, annotate, load_policies
from ecdat.risk.record import CalculationRecord

#: See module docstring: an engineering choice, not a regulatory citation.
DEFAULT_AT_RISK_DAYS = 180


class SectorTrafficLight(str, Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    OVERDUE = "overdue"
    NO_DEADLINE = "no_deadline"


class UnknownSectorError(ValueError):
    pass


class SectorPolicyRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_key: str
    citation: str
    quote: str


class SectorProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    label: str
    citation: str
    quote: str
    policies: tuple[SectorPolicyRef, ...]


class ObligationRef(BaseModel):
    """A sector-mapped policy with no dated milestone (`usable: false` in
    data/policy_deadlines.yaml). Never folded into the traffic light."""

    model_config = ConfigDict(frozen=True)

    policy_key: str
    citation: str
    quote: str


class AssetSectorStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    sector: str
    status: SectorTrafficLight
    reason: str
    as_of: date
    annotations: tuple[PolicyAnnotation, ...]
    obligations: tuple[ObligationRef, ...]
    record_ids: tuple[str, ...]


def _data_path() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "sector_profiles.yaml"


@lru_cache(maxsize=1)
def _document() -> dict:
    return yaml.safe_load(_data_path().read_text(encoding="utf-8")) or {}


@lru_cache(maxsize=1)
def load_sector_profiles() -> tuple[SectorProfile, ...]:
    """Usable sectors only -- same `usable: true` convention as every other
    data/ registry (tools/ci/check_data_citations.py enforces it)."""
    document = _document()
    return tuple(
        SectorProfile(
            key=row["key"],
            label=row["label"],
            citation=row["citation"],
            quote=row["quote"],
            policies=tuple(
                SectorPolicyRef(
                    policy_key=p["policy_key"], citation=p["citation"], quote=p["quote"]
                )
                for p in row.get("policies") or ()
                if p.get("usable") is True
            ),
        )
        for row in document.get("sectors") or ()
        if row.get("usable") is True
    )


@lru_cache(maxsize=1)
def load_global_policy_keys() -> tuple[str, ...]:
    return tuple(_document().get("global_policies") or ())


def available_sectors() -> tuple[str, ...]:
    return tuple(profile.key for profile in load_sector_profiles())


def sector_profile(sector_key: str) -> SectorProfile:
    for profile in load_sector_profiles():
        if profile.key == sector_key:
            return profile
    known = ", ".join(available_sectors())
    raise UnknownSectorError(f"unknown sector {sector_key!r}; known sectors: {known}")


def _applicable_policy_keys(sector: SectorProfile, *, include_global: bool) -> tuple[str, ...]:
    keys = [p.policy_key for p in sector.policies]
    if include_global:
        keys.extend(load_global_policy_keys())
    return tuple(dict.fromkeys(keys))


def _obligations(sector: SectorProfile, *, include_global: bool) -> tuple[ObligationRef, ...]:
    """Sector-mapped policies that have no dated milestone in
    data/policy_deadlines.yaml (that file's own `usable: false` rows)."""
    dated_keys = {policy.key for policy in load_policies()}
    keys = _applicable_policy_keys(sector, include_global=include_global)
    refs: list[ObligationRef] = []
    for policy_ref in sector.policies:
        if policy_ref.policy_key in keys and policy_ref.policy_key not in dated_keys:
            refs.append(
                ObligationRef(
                    policy_key=policy_ref.policy_key,
                    citation=policy_ref.citation,
                    quote=policy_ref.quote,
                )
            )
    return tuple(refs)


def _record_status(
    record: CalculationRecord,
    *,
    sector: SectorProfile,
    include_global: bool,
    at_risk_days: int,
) -> tuple[SectorTrafficLight, tuple[PolicyAnnotation, ...], str]:
    keys = set(_applicable_policy_keys(sector, include_global=include_global))
    policies = tuple(p for p in load_policies() if p.key in keys)
    annotations = annotate(record, policies=policies)

    if not annotations:
        return (
            SectorTrafficLight.NO_DEADLINE,
            annotations,
            "no dated policy milestone from this sector applies to this row",
        )

    open_annotations = [a for a in annotations if a.status == PolicyStatus.OPEN]
    met_annotations = [a for a in annotations if a.status == PolicyStatus.MET]

    if open_annotations:
        nearest = min(open_annotations, key=lambda a: a.days_remaining)
        if nearest.days_remaining < 0:
            status = SectorTrafficLight.OVERDUE
            reason = (
                f"{nearest.policy_label} / {nearest.milestone_label} deadline "
                f"{nearest.deadline.isoformat()} passed {-nearest.days_remaining} day(s) ago"
            )
        elif nearest.days_remaining <= at_risk_days:
            status = SectorTrafficLight.AT_RISK
            reason = (
                f"{nearest.policy_label} / {nearest.milestone_label} deadline "
                f"{nearest.deadline.isoformat()} is {nearest.days_remaining} day(s) away"
            )
        else:
            status = SectorTrafficLight.ON_TRACK
            reason = (
                f"nearest open deadline is {nearest.policy_label} / {nearest.milestone_label} "
                f"on {nearest.deadline.isoformat()}, {nearest.days_remaining} day(s) away"
            )
        return status, annotations, reason

    if met_annotations:
        return (
            SectorTrafficLight.ON_TRACK,
            annotations,
            "an observed migration met every applicable deadline",
        )

    return (
        SectorTrafficLight.NO_DEADLINE,
        annotations,
        "algorithm family is unknown or not quantum-vulnerable for every applicable policy; "
        "no deadline can be said to apply",
    )


_STATUS_RANK: dict[SectorTrafficLight, int] = {
    SectorTrafficLight.OVERDUE: 3,
    SectorTrafficLight.AT_RISK: 2,
    SectorTrafficLight.ON_TRACK: 1,
    SectorTrafficLight.NO_DEADLINE: 0,
}


def sector_report(
    records: list[CalculationRecord],
    *,
    sector_key: str,
    include_global: bool = False,
    at_risk_days: int = DEFAULT_AT_RISK_DAYS,
) -> tuple[AssetSectorStatus, ...]:
    """One `AssetSectorStatus` per distinct asset_id in `records`, for the
    sector named by `sector_key`.

    An asset with more than one usage context (record) takes the worst status
    among its records (`overdue` > `at_risk` > `on_track` > `no_deadline`);
    `derived_from` for that choice is each contributing record's own
    `record_id`, carried in `record_ids`. `as_of` is read off each record
    (never `date.today()`), so a caller controls it the same way every other
    risk/ module requires -- by constructing records with the `as_of` they
    want, not by this module reading a clock.
    """
    sector = sector_profile(sector_key)
    obligations = _obligations(sector, include_global=include_global)

    by_asset: dict[str, list[CalculationRecord]] = {}
    for record in records:
        asset_id = record.inputs.usage_context.asset_id
        by_asset.setdefault(asset_id, []).append(record)

    results: list[AssetSectorStatus] = []
    for asset_id, asset_records in by_asset.items():
        best_status: SectorTrafficLight | None = None
        best_reason = ""
        all_annotations: list[PolicyAnnotation] = []
        record_ids: list[str] = []
        as_of = asset_records[0].as_of
        for record in asset_records:
            record_ids.append(record.record_id)
            status, annotations, reason = _record_status(
                record,
                sector=sector,
                include_global=include_global,
                at_risk_days=at_risk_days,
            )
            all_annotations.extend(annotations)
            if best_status is None or _STATUS_RANK[status] > _STATUS_RANK[best_status]:
                best_status = status
                best_reason = reason
        results.append(
            AssetSectorStatus(
                asset_id=asset_id,
                sector=sector.key,
                status=best_status or SectorTrafficLight.NO_DEADLINE,
                reason=best_reason or "no records for this asset",
                as_of=as_of,
                annotations=tuple(all_annotations),
                obligations=obligations,
                record_ids=tuple(record_ids),
            )
        )

    return tuple(sorted(results, key=lambda r: r.asset_id))
