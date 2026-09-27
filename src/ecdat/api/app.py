"""FastAPI read API over ledger rows (Pramana_Ledger_Spec.md §7.2 phase 7).

Presentation and orchestration only. Every number this API returns comes out
of `risk/`; nothing here decides a band, weights anything, or holds a
threshold. If a value appears on screen that this module computed, that is a
bug -- the dashboard's job is to show the ledger, not to be a second one.

Two deliberate awkwardnesses, both there to keep assumptions visible:

* `scenario` is a required query parameter. There is no "the answer"; there is
  an answer per Z date, and the caller has to say which one it is asking about.
* `rollout_y_days` is required too, with no default. data/scenarios.yaml
  records that §5.4 names the knob and states no number, so a default here
  would put an uncited constant behind every ROTATE_BEFORE_Z deadline in the
  UI. The dashboard shows it as a control the operator owns.
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from ecdat.adapters.base import ScanTarget
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.closure.engine import closure_queue, tasks_for
from ecdat.context.binding import Lifetime
from ecdat.correlation.engine import CorrelationReport, correlate
from ecdat.correlation.graph import EvidenceGraph, build_graph
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecdat.export.cyclonedx import build_bom
from ecdat.export.signing import sign_bom, signing_key_from_env
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.recommend.engine import (
    NoCitedOptionError,
    Profile,
    hybrid_rationale,
    recommend,
)
from ecdat.risk.record import CalculationRecord, ExposureBand, rank_key, replay
from ecdat.risk.run import GroverFlag, LedgerSubject, RunResult, evaluate_run
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    NoCitedScenarioError,
    Policy,
    Scenario,
)
from ecdat.risk.policy import annotate as annotate_policies
from ecdat.risk.sector import (
    DEFAULT_AT_RISK_DAYS,
    UnknownSectorError,
    available_sectors,
    load_sector_profiles,
    sector_report,
)
from ecdat.risk.sensitivity import sensitivity_for
from ecdat.security.audit import AuditLog, InMemoryAuditLog, Verb, entry_for
from ecdat.security.auth import AuthError, InsufficientRoleError, Principal, Role, TokenRegistry

SubjectsProvider = Callable[[], list[LedgerSubject]]
_bearer_scheme = HTTPBearer(auto_error=False)

#: The fixture the dashboard opens with when nothing else is configured.
#: Clearly labelled in the UI as a fixture: it is constructed evidence, not a
#: scan of anything, and no adapter has run.
DEFAULT_SUBJECTS = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "ledger" / "subjects.json"
)


def load_subjects(path: Path) -> list[LedgerSubject]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return [LedgerSubject.model_validate(row) for row in document["subjects"]]


CorrelationProvider = Callable[[], CorrelationReport]

#: Three services, one certificate copied byte-for-byte between two of them
#: (a real `same-object` edge) and re-issued on the same key at the third (a
#: real `shares_public_key_unclaimed` pair) -- pre-generated fixture
#: certificates plus a plan file, the exact shape `ecdat correlate --plan`
#: reads. `confidence` and its justification live in the plan file (data),
#: never as a literal in this module: src/'s own citation guard
#: (test_no_confidence_literal_is_hardcoded_in_src) forbids a hardcoded
#: `base_confidence=<number>` in src/, because no cited table exists yet
#: (OI-004) and every real value must come from an explicit, justified
#: source outside the code -- here, the fixture's own data file.
DEFAULT_CORRELATION_PLAN = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "correlation" / "demo_plan.json"
)


def load_correlation_report(plan_path: Path) -> CorrelationReport:
    """Run `certs-x509` over every entry in a correlate-style plan file and
    return the resulting `CorrelationReport` -- the same path `ecdat
    correlate` drives, just without argparse in between."""
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    base_dir = plan_path.parent
    results = []
    for entry in plan:
        basis = ConfidenceBasis(
            source="ADAPTER_DECLARED", justification=entry["confidence_justification"]
        )
        adapter = CertificateAdapter(base_confidence=entry["confidence"], confidence_basis=basis)
        target = ScanTarget(target_id=entry["target_id"], locator=str(base_dir / entry["input"]))
        results.append(adapter.run(target))
    return correlate(results)


def default_correlation_report() -> CorrelationReport:
    """P15's demo graph. Clearly a fixture in the UI, exactly like
    `DEFAULT_SUBJECTS` is -- no adapter has scanned anything real."""
    return load_correlation_report(DEFAULT_CORRELATION_PLAN)


def _policy(
    capture: CaptureMode, since: date | None, accept_inferred: bool, rollout_y_days: int
) -> Policy:
    try:
        return Policy(
            capture_assumption=CaptureAssumption(mode=capture, since=since),
            rollout_Y_default=Lifetime(days=rollout_y_days),
            accept_inferred_inputs=accept_inferred,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _scenario(scenario_id: str) -> Scenario:
    try:
        return Scenario.load(scenario_id)
    except NoCitedScenarioError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


def _sensitivity(record: CalculationRecord) -> dict[str, Any]:
    """P19: every row's band, re-run under all three cited Z dates, so a row
    that would answer differently under a different scenario says so without
    the operator having to flip the control and remember what it said before.
    """
    sensitivity = sensitivity_for(record)
    return {
        "scenario_sensitive": sensitivity.scenario_sensitive,
        "under_scenario": [
            {
                "scenario_id": o.scenario_id,
                "label": o.label,
                "z_date": o.z_date.isoformat(),
                "band": o.band.value,
                "deadline": o.deadline.isoformat() if o.deadline else None,
            }
            for o in sensitivity.outcomes
        ],
        "first_flip": (
            {
                "scenario_id": sensitivity.first_flip.scenario_id,
                "label": sensitivity.first_flip.label,
                "z_date": sensitivity.first_flip.z_date.isoformat(),
                "band": sensitivity.first_flip.band.value,
                "deadline": (
                    sensitivity.first_flip.deadline.isoformat()
                    if sensitivity.first_flip.deadline
                    else None
                ),
            }
            if sensitivity.first_flip is not None
            else None
        ),
    }


def _row(record: CalculationRecord) -> dict[str, Any]:
    """One ledger row, flattened for display. No input is summarised away that
    a reader would need in order to disagree with the band."""
    context = record.inputs.usage_context
    return {
        "record_id": record.record_id,
        "usage_context_id": record.usage_context_id,
        "asset_id": context.asset_id,
        "surface_id": context.surface_id,
        "protocol_context": context.protocol_context,
        "function": record.function.value if record.function else "UNKNOWN",
        "function_status": context.function.state.value,
        "algorithm": context.algorithm.value if context.algorithm else None,
        "algorithm_status": (
            context.algorithm.state.value if context.algorithm else EpistemicState.UNKNOWN.value
        ),
        "band": record.band.value,
        "qualifiers": [q.value for q in record.qualifiers],
        "windows": [{"start": w.start.isoformat(), "end": w.end.isoformat(), "days": w.days} for w in record.windows],
        "deadline": record.deadline.isoformat() if record.deadline else None,
        "conditional_band": record.conditional_band.value if record.conditional_band else None,
        "reason": record.reason,
        "capture_sentence": record.capture_sentence,
        "scenario_id": record.scenario_id,
        "ledger": "authentication" if record.rule_version.startswith("LEDGER-AUTH") else "confidentiality",
        "X": str(record.X) if record.X else None,
        "A": str(record.A) if record.A else None,
        "M": record.M.isoformat() if record.M else None,
        "start_possible": record.start_possible.isoformat() if record.start_possible else None,
        "start_confirmed": record.start_confirmed.isoformat() if record.start_confirmed else None,
        "sensitivity": _sensitivity(record),
        # P22: regulator deadlines laid over the row. Never moves the band.
        "policy_deadlines": [
            {
                "policy": a.policy_key,
                "policy_label": a.policy_label,
                "milestone": a.milestone_key,
                "milestone_label": a.milestone_label,
                "deadline": a.deadline.isoformat(),
                "status": a.status.value,
                "days_remaining": a.days_remaining,
                "reason": a.reason,
                "citation": a.citation,
            }
            for a in annotate_policies(record)
        ],
    }


def _evidence_card(record: CalculationRecord) -> dict[str, Any]:
    """§7.2's "Evidence card": everything the band rests on, plus proof that
    re-running the calculation still produces it."""
    replayed = replay(record)
    return {
        **_row(record),
        "evidence_refs": [
            {"id": ref.id, "status": ref.status, "ts": ref.ts.isoformat() if ref.ts else None}
            for ref in record.evidence_refs
        ],
        "temporal_status": {
            name: state.value for name, state in record.inputs.temporal.status_per_field.items()
        },
        "migrations": [
            {
                "vantage": m.vantage,
                "observed_at": m.observed_at.isoformat(),
                "negotiated_group": m.negotiated_group,
                "classical_still_accepted": m.classical_still_accepted,
                "status": m.status.value,
                "stops_the_clock": m.stops_the_clock,
            }
            for m in record.inputs.migrations
        ],
        "binding": (
            {
                "classification": record.inputs.binding.classification,
                "cited_table_row": record.inputs.binding.cited_table_row,
                "source_ref": record.inputs.binding.source_ref,
                "status": record.inputs.binding.status.value,
            }
            if record.inputs.binding
            else None
        ),
        "policy": {
            "capture_assumption": str(record.capture_assumption),
            "accept_inferred_inputs": record.policy_snapshot.accept_inferred_inputs,
            "accept_declared_go_live": record.policy_snapshot.accept_declared_go_live,
            "rollout_Y": str(record.policy_snapshot.rollout_Y_default),
        },
        "provenance": {
            "rule_version": record.rule_version,
            "calc_version": record.calc_version,
            "inputs_sha256": record.inputs_sha256,
        },
        "replay": {
            "band": replayed.band.value,
            "matches": replayed.band == record.band,
            "hash_stable": replayed.inputs_sha256 == record.inputs_sha256,
        },
        "closure_tasks": [task.model_dump(mode="json") for task in tasks_for(record)],
        "recommendation": recommend(record.inputs.usage_context).model_dump(mode="json"),
    }


def _coverage(result: RunResult) -> dict[str, Any]:
    """§7.2's "Coverage" panel.

    What this can honestly report today is the evidence status of what reached
    the ledger. The adapter visibility matrix -- what each sensor looked at and
    what it skipped -- is P6 work and no adapter feeds this yet, so the panel
    says so rather than showing an empty table that reads as full coverage.
    """
    by_status: dict[str, int] = {}
    surfaces: dict[str, set[str]] = {}
    for record in result.records:
        state = record.inputs.usage_context.function.state.value
        by_status[state] = by_status.get(state, 0) + 1
        surfaces.setdefault(record.inputs.usage_context.surface_id, set()).add(state)

    bands: dict[str, int] = {}
    for record in result.records:
        bands[record.band.value] = bands.get(record.band.value, 0) + 1

    return {
        "rows": len(result.records),
        "by_function_status": by_status,
        "by_band": bands,
        "surfaces": {surface: sorted(states) for surface, states in sorted(surfaces.items())},
        "grover_flags": [flag.model_dump(mode="json") for flag in result.grover_flags],
        "skipped": list(result.skipped),
        "adapter_visibility": {
            "available": False,
            "note": (
                "No adapter has run. Per-sensor coverage -- what was scanned, "
                "what was skipped, what is unsupported -- arrives with P6 and "
                "is not shown as empty here, because an empty coverage table "
                "reads as full coverage."
            ),
        },
    }


def create_app(
    subjects_provider: SubjectsProvider | None = None,
    *,
    static_dir: Path | None = None,
    correlation_provider: CorrelationProvider | None = None,
    token_registry: TokenRegistry | None = None,
    audit_log: AuditLog | None = None,
    signing_key: Ed25519PrivateKey | None = None,
    signing_key_id: str = "pramana-export-key",
) -> FastAPI:
    app = FastAPI(
        title="Pramana",
        description="Read API over the exposure ledger. Presentation only.",
        version="0.1.0",
    )
    #: P21: `ECDAT_SUBJECTS_PATH` points the dashboard at a file produced by
    #: `ecdat assemble` (real scans) instead of the hand-built fixture. The
    #: UI's "Fixture data" banner follows `/api/health`'s `fixture` flag, so
    #: it is shown only when the fixture is actually what is being served.
    configured_path = os.environ.get("ECDAT_SUBJECTS_PATH")
    subjects_path = Path(configured_path) if configured_path else DEFAULT_SUBJECTS
    serving_fixture = subjects_provider is None and subjects_path == DEFAULT_SUBJECTS
    provider: SubjectsProvider = subjects_provider or (lambda: load_subjects(subjects_path))
    #: Computed once per app instance, not per request -- it runs a real
    #: adapter and the correlation engine, and (like DEFAULT_SUBJECTS) is
    #: fixture data, not a live scan.
    correlation_report = (correlation_provider or default_correlation_report)()

    #: build-plan.md P17. Secure by default: no explicit registry and no
    #: ECDAT_API_TOKENS means every request is refused until an operator
    #: configures one. app.state carries both so a test or an operator can
    #: introspect what got recorded without a second wiring path.
    registry = token_registry or TokenRegistry.from_env()
    audit = audit_log or InMemoryAuditLog()
    app.state.token_registry = registry
    app.state.audit_log = audit

    #: OI-013. `None` when unconfigured (default: no ECDAT_SIGNING_KEY_PATH)
    #: -- export proceeds unsigned rather than inventing a key. app.state
    #: carries it so a test can pass one in without an env var round-trip.
    key = signing_key if signing_key is not None else signing_key_from_env()
    app.state.signing_key = key

    def _require(role: Role, verb: Verb):
        """One dependency factory used by every protected route. Every call
        -- allowed or refused -- is audited (P17: "who read or exported
        what", including who tried and was refused); a raw token is never
        the thing that gets logged or compared, only its fingerprint
        (security/auth.py)."""

        def dependency(
            request: Request,
            credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
        ) -> Principal:
            raw_token = credentials.credentials if credentials else None
            principal: Principal | None = None
            try:
                principal = registry.authenticate(raw_token)
                if not principal.can(role):
                    raise InsufficientRoleError(required=role, actual=principal.role)
            except AuthError as error:
                audit.record(
                    entry_for(
                        principal, verb=verb, path=request.url.path, outcome=type(error).__name__
                    )
                )
                raise HTTPException(status_code=error.status_code, detail=str(error)) from error
            audit.record(entry_for(principal, verb=verb, path=request.url.path, outcome="allowed"))
            return principal

        return dependency

    require_viewer = _require(Role.VIEWER, Verb.READ)
    require_exporter = _require(Role.EXPORTER, Verb.EXPORT)

    def run(
        scenario_id: str,
        capture: CaptureMode,
        since: date | None,
        accept_inferred: bool,
        rollout_y_days: int,
        as_of: date | None,
    ) -> RunResult:
        return evaluate_run(
            provider(),
            scenario=_scenario(scenario_id),
            policy=_policy(capture, since, accept_inferred, rollout_y_days),
            as_of=as_of or date.today(),
        )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "subjects": len(provider()), "fixture": serving_fixture}

    @app.get("/api/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {
                    "id": s.id,
                    "label": s.label,
                    "z_date": s.z_date.isoformat(),
                    "basis_citation": s.basis_citation,
                }
                for s in Scenario.load_all()
            ],
            "capture_modes": [mode.value for mode in CaptureMode],
            "rollout_y_note": (
                "No cited default for Y exists (data/scenarios.yaml). "
                "Whatever you set here is your assumption, and it is recorded "
                "on every row it affects."
            ),
        }

    @app.get("/api/ledger")
    def ledger_rows(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        principal: Principal = Depends(require_viewer),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        ordered = sorted(result.records, key=lambda r: rank_key(r))
        return {
            "scenario_id": result.scenario_id,
            "as_of": result.as_of.isoformat(),
            "rows": [_row(record) for record in ordered],
            "counts": {
                band.value: sum(1 for r in result.records if r.band == band)
                for band in ExposureBand
                if any(r.band == band for r in result.records)
            },
        }

    @app.get("/api/sectors")
    def sectors(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
        """India sector lenses (SIH26164): the sectors a cited source
        (data/sector_profiles.yaml) says have their own compliance obligations,
        and which policy rows apply to each -- for the dashboard's sector
        picker to render without hardcoding the list."""
        return {
            "sectors": [
                {
                    "key": profile.key,
                    "label": profile.label,
                    "citation": profile.citation,
                    "quote": profile.quote,
                    "policies": [
                        {
                            "policy_key": p.policy_key,
                            "citation": p.citation,
                            "quote": p.quote,
                        }
                        for p in profile.policies
                    ],
                }
                for profile in load_sector_profiles()
            ],
            "default_at_risk_days": DEFAULT_AT_RISK_DAYS,
        }

    @app.get("/api/sector-report")
    def sector_report_endpoint(
        sector: str = Query(...),
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        include_global: bool = Query(False),
        at_risk_days: int = Query(DEFAULT_AT_RISK_DAYS, ge=0),
        principal: Principal = Depends(require_viewer),
    ) -> dict[str, Any]:
        """Per-asset traffic light for one sector (SIH26164). Evaluates the
        same ledger `/api/ledger` does, then overlays `risk/sector.py` --
        never a second risk calculation, and the band a row already has never
        moves because of this endpoint."""
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        try:
            statuses = sector_report(
                list(result.records),
                sector_key=sector,
                include_global=include_global,
                at_risk_days=at_risk_days,
            )
        except UnknownSectorError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

        return {
            "sector": sector,
            "scenario_id": result.scenario_id,
            "as_of": result.as_of.isoformat(),
            "assets": [
                {
                    "asset_id": s.asset_id,
                    "status": s.status.value,
                    "reason": s.reason,
                    "record_ids": list(s.record_ids),
                    "annotations": [
                        {
                            "policy": a.policy_key,
                            "policy_label": a.policy_label,
                            "milestone": a.milestone_key,
                            "milestone_label": a.milestone_label,
                            "deadline": a.deadline.isoformat(),
                            "status": a.status.value,
                            "days_remaining": a.days_remaining,
                            "reason": a.reason,
                            "citation": a.citation,
                        }
                        for a in s.annotations
                    ],
                    "obligations": [
                        {
                            "policy": o.policy_key,
                            "citation": o.citation,
                            "quote": o.quote,
                        }
                        for o in s.obligations
                    ],
                }
                for s in statuses
            ],
            "counts": {
                status_value: sum(1 for s in statuses if s.status.value == status_value)
                for status_value in ("on_track", "at_risk", "overdue", "no_deadline")
                if any(s.status.value == status_value for s in statuses)
            },
        }

    @app.get("/api/records/{record_id:path}")
    def record_detail(
        record_id: str,
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        principal: Principal = Depends(require_viewer),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        for record in result.records:
            if record.record_id == record_id:
                return _evidence_card(record)
        raise HTTPException(status_code=404, detail=f"no record {record_id!r} in this run")

    @app.get("/api/closure")
    def closure(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        principal: Principal = Depends(require_viewer),
    ) -> dict[str, Any]:
        result = run(scenario, capture, since, accept_inferred, rollout_y_days, as_of)
        return {
            "scenario_id": result.scenario_id,
            "tasks": [task.model_dump(mode="json") for task in closure_queue(result.records)],
        }

    @app.get("/api/coverage")
    def coverage(
        scenario: str = Query(...),
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        principal: Principal = Depends(require_viewer),
    ) -> dict[str, Any]:
        return _coverage(run(scenario, capture, since, accept_inferred, rollout_y_days, as_of))

    @app.get("/api/graph")
    def graph(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
        """P15: the evidence graph view. `fixture` is always true today --
        `correlation_report` is `default_correlation_report()` unless a
        caller wires a real one in, exactly like `DEFAULT_SUBJECTS`."""
        def agility_field(fv) -> dict[str, Any]:
            return {
                "value": fv.value.value if hasattr(fv.value, "value") else fv.value,
                "state": fv.state.value,
                "evidence_refs": list(fv.evidence_refs),
            }

        evidence_graph: EvidenceGraph = build_graph(correlation_report)
        return {
            "fixture": True,
            "nodes": [
                {
                    "asset_id": n.asset_id,
                    "algorithm_family": n.algorithm_family,
                    "purpose": n.purpose,
                    "scope_anchor": n.scope_anchor,
                    "agility": {
                        "algorithm_selection": agility_field(n.agility.algorithm_selection),
                        "hybrid_capable": agility_field(n.agility.hybrid_capable),
                        "provider_pluggable": agility_field(n.agility.provider_pluggable),
                    },
                }
                for n in evidence_graph.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "strength": e.strength.value,
                    "type": e.type,
                    "evidence_basis": e.evidence_basis,
                    "rule_id": e.rule_id,
                    "epistemic_state": e.epistemic_state,
                    "note": e.note,
                }
                for e in evidence_graph.edges
            ],
            "gaps": [
                {"from_layer": g.from_layer, "to_layer": g.to_layer, "why": g.why}
                for g in evidence_graph.gaps
            ],
        }

    @app.get("/api/profiles")
    def profiles(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
        return {
            "profiles": [
                {
                    "key": p.key,
                    "label": p.label,
                    "parameter_sets": p.parameter_sets,
                    "firmware_signing": p.firmware_signing,
                    "citation": p.citation,
                }
                for p in Profile.load_all()
            ],
            "default": Profile.default().key,
        }

    @app.get("/api/recommendations")
    def recommendations(
        profile: str | None = Query(None), principal: Principal = Depends(require_viewer)
    ) -> dict[str, Any]:
        """Part 8. Keyed on purpose, so it needs no scenario and no Z date --
        what to move to does not depend on when Z is, only on what the key is
        doing."""
        try:
            chosen = Profile.load(profile) if profile else Profile.default()
        except NoCitedOptionError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        results = [recommend(subject, profile=chosen) for subject in provider()]
        return {
            "profile": {
                "key": chosen.key,
                "label": chosen.label,
                "citation": chosen.citation,
            },
            "hybrid_rationale": hybrid_rationale(),
            "recommendations": [r.model_dump(mode="json") for r in results],
            "undetermined": [
                r.usage_context_id for r in results if r.insufficient_evidence
            ],
        }

    @app.get("/api/export")
    def export(
        capture: CaptureMode = Query(CaptureMode.SINCE_CONFIRMED),
        since: date | None = Query(None),
        accept_inferred: bool = Query(False),
        rollout_y_days: int = Query(..., ge=0),
        as_of: date | None = Query(None),
        principal: Principal = Depends(require_exporter),
    ) -> JSONResponse:
        """Every scenario in one document (ADR-005 decision 2). Signed
        (OI-013) when the app was configured with a key; the response says
        which, via `X-Pramana-Signed`, rather than leaving a caller to
        infer it from parsing the body."""
        records: list[CalculationRecord] = []
        for scenario in Scenario.load_all():
            records.extend(
                run(scenario.id, capture, since, accept_inferred, rollout_y_days, as_of).records
            )
        document = build_bom(records, timestamp=datetime.now(timezone.utc))
        signed = app.state.signing_key is not None
        if signed:
            document = sign_bom(document, private_key=app.state.signing_key, key_id=signing_key_id)
        return JSONResponse(
            content=document,
            headers={
                "Content-Disposition": 'attachment; filename="pramana-cbom.json"',
                "X-Pramana-Signed": "true" if signed else "false",
            },
        )

    bundle = static_dir or (Path(__file__).resolve().parents[3] / "ui" / "dashboard" / "dist")
    if bundle.is_dir():
        app.mount("/assets", StaticFiles(directory=bundle / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(bundle / "index.html")

    return app


app = create_app()
