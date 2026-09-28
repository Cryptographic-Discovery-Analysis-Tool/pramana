"""`ecdat quickscan <path>`: one command, folder in, demo-ready summary out.

DEV-018 (docs/deviations.md): an independent review noted a judge cannot
point Pramana at a folder and get a result quickly -- every `ecdat scan`
needs `--adapter`, `--target-id`, `--confidence`, `--confidence-justification`
and per-adapter flags, run one adapter at a time, then `correlate`,
`ledger-run`, `sector-report` and a CBOM export separately. This module wires
those same steps together for a folder, auto-discovering which adapters even
apply. It is a thin orchestrator: every step below calls the exact function
`ecdat.cli`'s own subcommands call (`ecdat.cli._run_plan` for the scan step,
`ecdat.correlation.engine.correlate`, `ecdat.assemble.assemble`,
`ecdat.recommend.engine.recommend`, `ecdat.risk.run.evaluate_run`,
`ecdat.risk.sector.sector_report`, `ecdat.export.cyclonedx.build_bom`,
`ecdat.export.signing.sign_bom`) -- nothing here re-implements adapter,
correlation, ledger or export logic.

**Discovery never fakes a result.** A folder is scanned once for candidate
files; an adapter only enters the plan when a real match exists (a
certificate file, a `kind: Secret` manifest, a Spring config file, a package
manifest/jar, a source file) AND, for `packages-trivy`/`source-semgrep`
(subprocess-backed), its tool actually resolves on this machine (bare PATH or
`ECDAT_<TOOL>_LAUNCHER`/`ECDAT_<TOOL>_BIN`, see `adapters/live_launcher.py`).
An adapter whose tool does not resolve is SKIPPED with a one-line reason; it
is never run against a recorded fixture here (CLAUDE.md: "Replay of a
recorded file (--input) is for tests and scoring only").

**Confidence is never invented.** `data/base_confidence.yaml` has
`usable_row_count: 0` -- no citable per-source-tool confidence value exists
in this repository yet (OI-004/ADR-002). quickscan therefore cannot draw a
"documented default" from that file. It instead applies one clearly labelled
placeholder (`QUICKSCAN_DEFAULT_CONFIDENCE`) with an honest
`ADAPTER_DECLARED` justification -- the same pattern
`tests/fixtures/correlation/demo_plan.json` already uses for its own 0.9
("dashboard fixture ... not a real scan"). `ecdat scan
--confidence/--confidence-justification` remains the way to record a
defensible, reviewed number for anything beyond a live triage demo.

**Risk banding needs a number nothing here can cite.** `rollout_Y_default`
has no cited default (`data/scenarios.yaml`; `ledger-run --rollout-y-days` is
`required=True` for the same reason). quickscan does not invent one: the
ledger/risk band, the sector traffic-light view and the CBOM export are all
skipped, with that reason stated in the summary, unless the caller opts in
with `--rollout-y-days`. Discovery, the per-adapter scans, correlation and
purpose-based recommendations (`recommend()` needs no scenario -- Part 8)
still run either way.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ecdat.adapters.base import AdapterRunResult
from ecdat.adapters.certs.parser import CERTIFICATE_SUFFIXES
from ecdat.adapters.live_launcher import resolve_launcher_prefix, resolve_tool_bin
from ecdat.assemble import Declarations, assemble
from ecdat.context.binding import Lifetime
from ecdat.correlation.engine import ForbiddenEdgeError, correlate
from ecdat.data.crypto_families import NoCitedFamilyError, canonical_family, is_shor_broken
from ecdat.export.cyclonedx import build_bom
from ecdat.export.signing import sign_bom, signing_key_from_env
from ecdat.recommend.engine import Profile, recommend
from ecdat.risk.run import evaluate_run
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    NoCitedScenarioError,
    Policy,
)
from ecdat.risk.sector import UnknownSectorError, sector_report

#: Shipped alongside this module -- the honest default `--context example`
#: resolves to (DEV-019). src/ecdat/quickscan.py -> src/ecdat -> src -> repo
#: root -> examples/.
_EXAMPLE_CONTEXT_PATH = (
    Path(__file__).resolve().parents[2] / "examples" / "quickscan-context.example.yaml"
)

# --- what "no citable value" means for quickscan's own placeholder inputs --

QUICKSCAN_DEFAULT_CONFIDENCE = 0.5
QUICKSCAN_CONFIDENCE_JUSTIFICATION = (
    "quickscan placeholder: no cited base_confidence.yaml row exists for any adapter "
    "(usable_row_count=0, OI-004/ADR-002); this is a triage default, not a measured "
    "value -- use `ecdat scan --confidence` for a reviewed number"
)

#: A reasonable, documented set of security-relevant Spring property keys to
#: resolve when quickscan finds Spring config but has no upstream
#: source-adapter finding to hand config-chain-spring specific keys
#: (adapters/config/adapter.py: this adapter never discovers keys itself --
#: that is deliberately out of its scope). This chooses which keys get
#: looked up, never a value for them.
QUICKSCAN_SPRING_PROPERTY_KEYS: tuple[str, ...] = (
    "server.ssl.protocol",
    "server.ssl.enabled-protocols",
    "server.ssl.ciphers",
    "server.ssl.key-store-type",
)

_MANIFEST_SUFFIXES = frozenset({".yaml", ".yml"})
_SPRING_CONFIG_NAMES = frozenset(
    {"application.yml", "application.yaml", "application.properties", "bootstrap.yml", "bootstrap.yaml"}
)
_PACKAGE_MANIFEST_NAMES = frozenset(
    {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "package-lock.json",
        "yarn.lock",
        "requirements.txt",
        "Pipfile.lock",
        "go.sum",
        "Gemfile.lock",
    }
)
_SOURCE_SUFFIXES = frozenset(
    {".java", ".py", ".js", ".ts", ".go", ".rb", ".php", ".c", ".cpp", ".cs", ".kt"}
)
_SKIP_DIR_NAMES = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build", ".mypy_cache", ".pytest_cache"}
)

#: adapter_id -> the external tool name `live_launcher.py` resolves for it
#: (used only for the availability check below; the actual live runner still
#: does its own resolution independently, exactly as `ecdat scan --live` does).
_SUBPROCESS_TOOLS = {"packages-trivy": "trivy", "source-semgrep": "semgrep"}


@dataclass(frozen=True)
class DiscoveredAdapter:
    """One row of the discovery table: an adapter that will run, or one that
    was skipped and why."""

    adapter_id: str
    run: bool
    reason: str


@dataclass(frozen=True)
class QuickscanResult:
    """Everything a caller (CLI wrapper, tests) needs: the raw pieces and a
    ready-to-print/serialise summary."""

    out_dir: Path
    discovery: tuple[DiscoveredAdapter, ...]
    scan_results: tuple[AdapterRunResult, ...]
    correlation_document: dict[str, Any] | None
    recommendations: tuple[dict[str, Any], ...]
    ledger_skip_reason: str | None
    sector_statuses: tuple[dict[str, Any], ...]
    sector_skip_reason: str | None
    cbom_signed: bool | None
    cbom_skip_reason: str | None
    context_hint: str | None
    elapsed_seconds: float
    written_files: tuple[str, ...]

    def summary_text(self) -> str:
        return _render_text_summary(self)

    def to_json_document(self) -> dict[str, Any]:
        return _render_json_document(self)


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def _tool_available(tool: str) -> tuple[bool, str]:
    """Best-effort availability check: does the launcher prefix (or, absent
    one, the bare tool binary) resolve on PATH? Mirrors the same
    `ECDAT_<TOOL>_LAUNCHER`/`ECDAT_<TOOL>_BIN` resolution
    `live_scan_runner()` uses, so "available" here means "the same
    invocation `--live` would attempt has something to run". It cannot
    prove the tool inside a launched environment (e.g. WSL) actually has it
    installed -- that surfaces as a FAILED outcome on the real run, same as
    `ecdat scan --live` today."""
    prefix = resolve_launcher_prefix(tool)
    if prefix:
        found = shutil.which(prefix[0]) is not None
        where = " ".join(prefix)
    else:
        binary = resolve_tool_bin(tool, tool)
        found = shutil.which(binary) is not None
        where = binary
    return found, where


def _classify_family(algorithm_family: str | None, curve: str | None) -> tuple[str, bool | None]:
    """One asset's cited Shor-broken classification, or honestly
    "unclassified" when no citable row covers it.

    `algorithm_family` is the raw value `adapters/certs/parser.py`'s
    `_public_key_description` reports -- "RSA"/"EC"/"DSA"/... -- which is
    also a literal `data/crypto_families.yaml` family key for RSA, but NOT
    for EC: that file classifies elliptic-curve keys by curve (P-256,
    P-384, ...), never by the generic "EC" label `cryptography` reports.
    For an EC asset this resolves the actual curve name through
    `canonical_family()` (`family_aliases` rows, e.g. "secp256r1" ->
    "P-256") before asking `is_shor_broken` -- this is the fix for a bug
    that silently reported 0 quantum-vulnerable assets whenever the only
    matches were EC certs/keys, because `is_shor_broken("EC")` has no row
    and was being swallowed as if EC were simply not vulnerable.

    A curve with no alias row yet (e.g. "secp384r1" today -- only
    secp256r1/prime256v1 are aliased) has no citable path and returns
    `None` (unclassified) rather than a guessed True/False.
    """
    if not algorithm_family:
        return "UNKNOWN", None
    candidate = curve if algorithm_family == "EC" and curve else algorithm_family
    canonical = canonical_family(candidate)
    try:
        return canonical, is_shor_broken(canonical)
    except NoCitedFamilyError:
        label = f"{algorithm_family}/{curve}" if curve else algorithm_family
        return label, None


def _field_value(asset: dict[str, Any], name: str) -> Any:
    for entry in asset.get("fields", ()):
        if entry.get("field") == name:
            return entry.get("value")
    return None


def _relpath(path_str: str, root: Path) -> str:
    """Display-only rendering: relative to the scanned folder, forward
    slashes, so a label never mixes an absolute path with a `..`-heavy
    relative one or backslash/forward-slash separators in the same string.
    Falls back to the original text (e.g. a bare `file://` ref, or a path
    genuinely outside `root`, such as a symlink target) rather than raising."""
    try:
        candidate = Path(path_str.split("#", 1)[0])
        rel = os.path.relpath(candidate, root) if candidate.is_absolute() else str(candidate)
    except (ValueError, OSError):
        return path_str
    return rel.replace("\\", "/")


def _relpath_in_text(text: str, root: Path) -> str:
    """Same display intent as `_relpath`, applied to a label that embeds an
    absolute path inside a larger string (e.g. `protocol_context`'s
    `"Cipher at C:\\...\\Foo.java:25"`) rather than being only a path.
    Strips the scanned folder's own absolute prefix wherever it appears and
    normalises slashes; leaves the text alone when the prefix is not found
    rather than guessing at a different one."""
    for candidate in (str(root.resolve()), str(root)):
        if candidate and candidate in text:
            text = text.replace(candidate, "").lstrip("/\\")
            break
    return text.replace("\\", "/")


def _extract_cn(subject_dn: str | None) -> str | None:
    if not subject_dn:
        return None
    for part in subject_dn.split(","):
        part = part.strip()
        if part[:3].upper() == "CN=":
            return part[3:]
    return None


def _cert_label_index(results: tuple[AdapterRunResult, ...], target_root: Path) -> dict[str, str]:
    """`assemble/bridge.py::_cert_asset_id`'s `"cert:<der[:16]>"` -> a human
    label (relative file, subject CN, algorithm) built from the same
    certs-x509/k8s-secret findings the ledger subjects already came from --
    no new evidence read, just a friendlier rendering of what is already
    there. Fixes the top-risk list showing raw internal ids like
    `certdir:<abs path>|keyUsage|digitalSignature`."""
    index: dict[str, str] = {}
    for result in results:
        if result.adapter_id not in ("certs-x509", "k8s-secret"):
            continue
        evidence_by_id = {evidence.evidence_id: evidence for evidence in result.evidence}
        for finding in result.findings:
            der_field = finding.fields.get("der_sha256")
            if der_field is None or der_field.value is None:
                continue
            asset_id = f"cert:{str(der_field.value)[:16]}"
            if asset_id in index:
                continue
            subject_field = finding.fields.get("subject")
            algo_field = finding.fields.get("public_key_algorithm")
            curve_field = finding.fields.get("public_key_curve")
            cn = _extract_cn(str(subject_field.value)) if subject_field and subject_field.value else None
            family = str(algo_field.value) if algo_field and algo_field.value else None
            if family == "EC" and curve_field and curve_field.value:
                family = f"EC/{curve_field.value}"
            location = None
            for ref in der_field.evidence_refs:
                evidence = evidence_by_id.get(ref)
                if evidence is not None:
                    location = evidence.location
                    break
            parts = [_relpath(location, target_root) if location else finding.surface]
            if cn:
                parts.append(f"CN={cn}")
            if family:
                parts.append(family)
            index[asset_id] = "  ".join(parts)
    return index


def _resolve_context_path(value: str) -> Path:
    """`--context example` is shorthand for the shipped, documented example
    file; anything else is a path the operator supplies."""
    return _EXAMPLE_CONTEXT_PATH if value == "example" else Path(value)


def _substitute_tokens(value: Any, mapping: dict[str, str]) -> Any:
    """Recursively replace `{target}`/`{host}`/`{port}` in every string leaf
    of a parsed YAML document. Substitution happens AFTER parsing (not by
    string-replacing the raw YAML text before `yaml.safe_load`) so that an
    arbitrary substituted value -- notably a Windows path full of
    backslashes, e.g. `C:\\Atharv's Stack\\...` -- is never re-interpreted as
    YAML escape syntax inside a quoted scalar."""
    if isinstance(value, str):
        for token, replacement in mapping.items():
            value = value.replace(token, replacement)
        return value
    if isinstance(value, list):
        return [_substitute_tokens(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _substitute_tokens(item, mapping) for key, item in value.items()}
    return value


def _load_context(path: Path, *, target: Path, live_tls: tuple[str, ...]) -> Declarations:
    """Load a `Declarations` file (the exact format `ecdat assemble
    --declarations`/`assemble.bridge.Declarations.load()` already reads --
    see that module's own docstring), after substituting the `{target}` /
    `{host}` / `{port}` tokens documented in
    `examples/quickscan-context.example.yaml` with this run's actual scanned
    path and (first) `--live-tls` host/port. This is plain string
    substitution of quickscan's own already-known inputs into an
    operator-authored template, not a new field on `Declarations` and not a
    derived or invented value -- `surface_id`s like `certdir:<root>` are
    otherwise unpredictable ahead of a run (they embed the absolute path
    handed to that adapter), which would make a portable example file
    impossible without it.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mapping = {"{target}": str(target)}
    if live_tls:
        host, _, port_text = live_tls[0].partition(":")
        mapping["{host}"] = host
        mapping["{port}"] = port_text or "443"
    document = _substitute_tokens(document, mapping)
    return Declarations.model_validate(document)


def discover(target: Path) -> dict[str, bool]:
    """One pass over `target`: which of the five folder-discoverable
    adapters have a real match. `packages-trivy`/`source-semgrep` tool
    availability is checked separately (`_tool_available`) -- this only
    answers "is there something for that adapter to look at"."""
    found = {
        "certs-x509": False,
        "k8s-secret": False,
        "config-chain-spring": False,
        "packages-trivy": False,
        "source-semgrep": False,
    }
    for path in _iter_files(target):
        suffix = path.suffix.lower()
        name = path.name
        if suffix in CERTIFICATE_SUFFIXES:
            found["certs-x509"] = True
        if name in _SPRING_CONFIG_NAMES:
            found["config-chain-spring"] = True
        if suffix in _MANIFEST_SUFFIXES and not found["k8s-secret"]:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            if "kind: Secret" in text or "kind:Secret" in text:
                found["k8s-secret"] = True
        if name in _PACKAGE_MANIFEST_NAMES or suffix == ".jar":
            found["packages-trivy"] = True
        if suffix in _SOURCE_SUFFIXES:
            found["source-semgrep"] = True
    return found


def _target_id(adapter_id: str, target: Path) -> str:
    """Deterministic from the path: same folder, same adapter -> same id
    every run, with no operator-supplied `--target-id`."""
    digest = hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:10]
    return f"quickscan-{adapter_id}-{target.name or 'root'}-{digest}"


def _plan_entries(
    target: Path, discovered: dict[str, bool], live_tls: tuple[str, ...]
) -> tuple[list[dict[str, Any]], list[DiscoveredAdapter]]:
    entries: list[dict[str, Any]] = []
    rows: list[DiscoveredAdapter] = []

    def base_entry(adapter_id: str) -> dict[str, Any]:
        return {
            "adapter": adapter_id,
            "target_id": _target_id(adapter_id, target),
            "confidence": QUICKSCAN_DEFAULT_CONFIDENCE,
            "confidence_justification": QUICKSCAN_CONFIDENCE_JUSTIFICATION,
        }

    if discovered["certs-x509"]:
        entries.append({**base_entry("certs-x509"), "input": str(target)})
        rows.append(DiscoveredAdapter("certs-x509", True, "certificate/keystore file(s) found"))
    else:
        rows.append(DiscoveredAdapter("certs-x509", False, "no certificate/keystore file found"))

    if discovered["k8s-secret"]:
        entries.append({**base_entry("k8s-secret"), "input": str(target)})
        rows.append(DiscoveredAdapter("k8s-secret", True, "YAML manifest with kind: Secret found"))
    else:
        rows.append(DiscoveredAdapter("k8s-secret", False, "no kind: Secret manifest found"))

    if discovered["config-chain-spring"]:
        entries.append(
            {
                **base_entry("config-chain-spring"),
                "input": str(target),
                "property_key": list(QUICKSCAN_SPRING_PROPERTY_KEYS),
            }
        )
        rows.append(
            DiscoveredAdapter(
                "config-chain-spring",
                True,
                "Spring config found; resolving quickscan's default TLS-relevant property keys",
            )
        )
    else:
        rows.append(DiscoveredAdapter("config-chain-spring", False, "no Spring config file found"))

    if discovered["packages-trivy"]:
        available, where = _tool_available(_SUBPROCESS_TOOLS["packages-trivy"])
        if available:
            entries.append({**base_entry("packages-trivy"), "input": str(target), "live": True})
            rows.append(DiscoveredAdapter("packages-trivy", True, f"package manifest/jar found; trivy resolved ({where})"))
        else:
            rows.append(
                DiscoveredAdapter(
                    "packages-trivy",
                    False,
                    f"package manifest/jar found but trivy not found on PATH ({where}); "
                    "set ECDAT_TRIVY_LAUNCHER/ECDAT_TRIVY_BIN or install trivy",
                )
            )
    else:
        rows.append(DiscoveredAdapter("packages-trivy", False, "no package manifest/jar found"))

    if discovered["source-semgrep"]:
        available, where = _tool_available(_SUBPROCESS_TOOLS["source-semgrep"])
        if available:
            entries.append({**base_entry("source-semgrep"), "input": str(target), "live": True})
            rows.append(DiscoveredAdapter("source-semgrep", True, f"source file(s) found; semgrep resolved ({where})"))
        else:
            rows.append(
                DiscoveredAdapter(
                    "source-semgrep",
                    False,
                    f"source file(s) found but semgrep not found on PATH ({where}); "
                    "set ECDAT_SEMGREP_LAUNCHER/ECDAT_SEMGREP_BIN or install semgrep",
                )
            )
    else:
        rows.append(DiscoveredAdapter("source-semgrep", False, "no source file found"))

    for spec in live_tls:
        host, _, port_text = spec.partition(":")
        port = int(port_text) if port_text else 443
        available, where = _tool_available("openssl")
        if not available:
            rows.append(
                DiscoveredAdapter(
                    "tls-endpoint",
                    False,
                    f"--live-tls {spec}: openssl not found on PATH ({where}); "
                    "set ECDAT_OPENSSL_BIN or install openssl",
                )
            )
            continue
        entries.append(
            {
                **base_entry("tls-endpoint"),
                "host": host,
                "port": port,
                "vantage": "quickscan-cli",
                "consent": True,
                "live": True,
            }
        )
        rows.append(DiscoveredAdapter("tls-endpoint", True, f"--live-tls {spec}: openssl resolved ({where})"))

    return entries, rows


# --- the pipeline -------------------------------------------------------------


def run_quickscan(
    target: str,
    *,
    sector: str | None = None,
    out_dir: str | None = None,
    live_tls: tuple[str, ...] = (),
    rollout_y_days: int | None = None,
    scenario_id: str = "Z_central",
    context: str | None = None,
    capture: str = "SINCE_CONFIRMED",
    accept_inferred: bool = False,
) -> QuickscanResult:
    start = time.perf_counter()
    target_path = Path(target)
    if not target_path.is_dir():
        raise NotADirectoryError(f"{target!r} is not a directory")

    resolved_out = Path(out_dir) if out_dir else Path("pramana-out") / datetime.now().strftime("%Y%m%dT%H%M%S")
    resolved_out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    discovered = discover(target_path)
    entries, discovery_rows = _plan_entries(target_path, discovered, live_tls)

    plan_path = resolved_out / "quickscan_plan.json"
    plan_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    written.append(str(plan_path))

    results: tuple[AdapterRunResult, ...] = ()
    if entries:
        # Reuses exactly the function `ecdat correlate`/`ecdat assemble`
        # already run every plan entry through -- no second plan runner.
        from ecdat.cli import _run_document, _run_plan  # local import: avoids a load-time cycle with cli.py

        plan_results = _run_plan(str(plan_path))
        if isinstance(plan_results, int):
            raise RuntimeError(f"quickscan plan {plan_path} failed to run (exit {plan_results})")
        results = tuple(plan_results)

        scan_dir = resolved_out / "scan"
        scan_dir.mkdir(exist_ok=True)
        for result in results:
            doc_path = scan_dir / f"{result.adapter_id}.json"
            doc_path.write_text(json.dumps(_run_document(result), indent=2), encoding="utf-8")
            written.append(str(doc_path))

    correlation_document: dict[str, Any] | None = None
    if results:
        try:
            from ecdat.cli import _correlate_document

            report = correlate(results)
            correlation_document = _correlate_document(report)
            correlate_path = resolved_out / "correlate.json"
            correlate_path.write_text(json.dumps(correlation_document, indent=2), encoding="utf-8")
            written.append(str(correlate_path))
        except ForbiddenEdgeError as exc:
            correlation_document = {"error": f"correlation refused: {exc}"}

    declarations = Declarations()
    if context:
        declarations = _load_context(_resolve_context_path(context), target=target_path, live_tls=live_tls)
    assembly = assemble(results, declarations=declarations)
    subjects_path = resolved_out / "ledger_subjects.json"
    subjects_path.write_text(json.dumps(assembly.to_subjects_document(), indent=2), encoding="utf-8")
    written.append(str(subjects_path))

    profile = Profile.default()
    recommendations = tuple(
        recommend(subject, profile=profile).model_dump(mode="json") for subject in assembly.subjects
    )
    recommendations_path = resolved_out / "recommendations.json"
    recommendations_path.write_text(json.dumps(list(recommendations), indent=2), encoding="utf-8")
    written.append(str(recommendations_path))

    ledger_skip_reason: str | None = None
    records: list = []
    if rollout_y_days is None:
        ledger_skip_reason = (
            "ledger/risk banding, sector view and CBOM export skipped: --rollout-y-days has "
            "no cited default (data/scenarios.yaml Section 5.4) and was not supplied"
        )
    else:
        try:
            from ecdat.risk.scenarios import Scenario

            scenario = Scenario.load(scenario_id)
            policy = Policy(
                capture_assumption=CaptureAssumption(mode=CaptureMode(capture), since=None),
                rollout_Y_default=Lifetime(days=rollout_y_days),
                accept_inferred_inputs=accept_inferred,
            )
            run_result = evaluate_run(list(assembly.subjects), scenario=scenario, policy=policy, as_of=date.today())
            records = list(run_result.records)
            cert_labels = _cert_label_index(results, target_path)
            ledger_path = resolved_out / "ledger_records.json"
            ledger_path.write_text(
                json.dumps(
                    [
                        {
                            "record_id": r.record_id,
                            "usage_context_id": r.usage_context_id,
                            "asset_id": r.inputs.usage_context.asset_id,
                            "asset_label": (
                                f"{cert_labels[r.inputs.usage_context.asset_id]}  "
                                f"({r.inputs.usage_context.protocol_context})"
                                if r.inputs.usage_context.asset_id in cert_labels
                                # No cert label (e.g. a source-semgrep call site):
                                # `protocol_context` is already a readable label
                                # ("Cipher at <path>:<line>") -- just relativize
                                # the path it embeds rather than showing the raw
                                # usage_context_id a second time.
                                else _relpath_in_text(r.inputs.usage_context.protocol_context, target_path)
                            ),
                            "band": r.band.value,
                            "reason": r.reason,
                            "deadline": r.deadline.isoformat() if r.deadline else None,
                        }
                        for r in records
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )
            written.append(str(ledger_path))
        except (NoCitedScenarioError, ValueError) as exc:
            ledger_skip_reason = f"ledger/risk banding failed: {exc}"

    sector_statuses: tuple[dict[str, Any], ...] = ()
    sector_skip_reason: str | None = None
    if sector:
        if ledger_skip_reason:
            sector_skip_reason = f"sector view skipped: {ledger_skip_reason}"
        else:
            try:
                statuses = sector_report(records, sector_key=sector)
                sector_statuses = tuple(
                    {
                        "asset_id": s.asset_id,
                        "sector": s.sector,
                        "status": s.status.value,
                        "reason": s.reason,
                    }
                    for s in statuses
                )
                sector_path = resolved_out / "sector_report.json"
                sector_path.write_text(json.dumps(list(sector_statuses), indent=2), encoding="utf-8")
                written.append(str(sector_path))
            except UnknownSectorError as exc:
                sector_skip_reason = str(exc)

    cbom_signed: bool | None = None
    cbom_skip_reason: str | None = None
    if ledger_skip_reason:
        cbom_skip_reason = f"CBOM export skipped: {ledger_skip_reason}"
    else:
        document = build_bom(records, timestamp=datetime.now(timezone.utc))
        signing_key = signing_key_from_env()
        cbom_signed = signing_key is not None
        if signing_key is not None:
            document = sign_bom(document, private_key=signing_key, key_id="quickscan")
        cbom_path = resolved_out / "cbom.json"
        cbom_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        written.append(str(cbom_path))

    context_hint: str | None = None
    if rollout_y_days is not None and not context:
        context_hint = (
            "no --context supplied: every usage context is UNBOUNDED for lack of a "
            "declared data-class binding (Pramana_Ledger_Spec.md §5.3: 'nothing declared "
            "-> no binding -> UNBOUNDED with a closure task, never a default lifetime'); "
            "pass --context example (or your own file, same format as `ecdat assemble "
            "--declarations`) for meaningful bands and sector traffic lights"
        )

    elapsed = time.perf_counter() - start
    return QuickscanResult(
        out_dir=resolved_out,
        discovery=tuple(discovery_rows),
        scan_results=results,
        correlation_document=correlation_document,
        recommendations=recommendations,
        ledger_skip_reason=ledger_skip_reason,
        sector_statuses=sector_statuses,
        sector_skip_reason=sector_skip_reason,
        cbom_signed=cbom_signed,
        cbom_skip_reason=cbom_skip_reason,
        context_hint=context_hint,
        elapsed_seconds=elapsed,
        written_files=tuple(written),
    )


# --- summary rendering ---------------------------------------------------------


def _asset_risk_rows(result: QuickscanResult) -> list[dict[str, Any]]:
    """Top-5 riskiest-first list with a human label and a one-line "why",
    built only from values already computed: ledger bands when the ledger
    stage ran (`--rollout-y-days` supplied), else each correlated asset's
    cited Shor-broken classification (`_classify_family`) -- never a number
    invented for the summary.

    The label is `asset_label` (a relative file path, subject CN and
    algorithm -- see `_cert_label_index`), not the raw
    `certdir:<abs path>|keyUsage|<bit>` usage-context id: one certificate's
    several keyUsage bits are genuinely distinct ledger subjects (§5.1: one
    row per capability the certificate declares), so the split itself is
    correct -- what was wrong was rendering the internal id as if it were a
    name.
    """
    if result.correlation_document is None:
        return []
    if not result.ledger_skip_reason:
        # ledger_records.json rows are already asset-labelled and keyed by
        # usage_context_id, but the summary works from the written file
        # back since only the QuickscanResult dataclass (not the raw
        # records) crosses this boundary, keeping this function pure
        # display logic.
        ledger_path = result.out_dir / "ledger_records.json"
        if ledger_path.is_file():
            rows = json.loads(ledger_path.read_text(encoding="utf-8"))
            rank = {"UNSAVABLE": 0, "BLEEDING": 1, "UNBOUNDED": 2, "SAVABLE": 3, "SAFE": 4}
            ordered = sorted(rows, key=lambda r: rank.get(r["band"], 5))
            return [
                {
                    "asset_id": row["usage_context_id"],
                    "label": row.get("asset_label", row["usage_context_id"]),
                    "why": f"band={row['band']}" + (f": {row['reason']}" if row["reason"] else ""),
                }
                for row in ordered[:5]
            ]
    assets = result.correlation_document.get("assets", [])
    scored = []
    for asset in assets:
        family = asset.get("algorithm_family")
        curve = _field_value(asset, "public_key_curve")
        canonical, vulnerable = _classify_family(family, curve)
        if family is None:
            continue
        rank = 0 if vulnerable is True else (1 if vulnerable is None else 2)
        scored.append((rank, asset["asset_id"], canonical, vulnerable))
    scored.sort(key=lambda row: row[:2])

    def why(canonical: str, vulnerable: bool | None) -> str:
        if vulnerable is True:
            return f"{canonical} is Shor-broken (quantum-vulnerable), data/crypto_families.yaml"
        if vulnerable is False:
            return f"{canonical} is not classified Shor-broken, data/crypto_families.yaml"
        return f"{canonical} has no cited row in data/crypto_families.yaml -- unclassified, not guessed"

    return [
        {"asset_id": asset_id, "label": asset_id, "why": why(canonical, vulnerable)}
        for _, asset_id, canonical, vulnerable in scored[:5]
    ]


def _family_counts(result: QuickscanResult) -> dict[str, int]:
    """`{vulnerable, not_vulnerable, unclassified}` counts over every
    correlated asset that carries an algorithm family at all (assets with
    none -- e.g. a k8s-secret opaque key blob -- are counted in neither).
    See `_classify_family` for why this is not simply `algorithm_family` fed
    straight to `is_shor_broken`."""
    counts = {"vulnerable": 0, "not_vulnerable": 0, "unclassified": 0}
    if result.correlation_document is None:
        return counts
    for asset in result.correlation_document.get("assets", []):
        family = asset.get("algorithm_family")
        if not family:
            continue
        curve = _field_value(asset, "public_key_curve")
        _, vulnerable = _classify_family(family, curve)
        if vulnerable is True:
            counts["vulnerable"] += 1
        elif vulnerable is False:
            counts["not_vulnerable"] += 1
        else:
            counts["unclassified"] += 1
    return counts


def _render_json_document(result: QuickscanResult) -> dict[str, Any]:
    return {
        "out_dir": str(result.out_dir),
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "discovery": [
            {"adapter": row.adapter_id, "ran": row.run, "reason": row.reason} for row in result.discovery
        ],
        "adapters": [
            {
                "adapter_id": r.adapter_id,
                "outcome": r.outcome.value,
                "finding_count": len(r.findings),
                "scanned": len(r.coverage.scanned),
                "skipped": len(r.coverage.skipped),
            }
            for r in result.scan_results
        ],
        "asset_count": len(result.correlation_document["assets"]) if result.correlation_document else 0,
        "quantum_vulnerable_count": _family_counts(result)["vulnerable"],
        "not_quantum_vulnerable_count": _family_counts(result)["not_vulnerable"],
        "unclassified_family_count": _family_counts(result)["unclassified"],
        "top_risk": _asset_risk_rows(result),
        "recommendation_count": len(result.recommendations),
        "ledger_skip_reason": result.ledger_skip_reason,
        "context_hint": result.context_hint,
        "sector": [dict(row) for row in result.sector_statuses],
        "sector_skip_reason": result.sector_skip_reason,
        "cbom_signed": result.cbom_signed,
        "cbom_skip_reason": result.cbom_skip_reason,
        "written_files": list(result.written_files),
    }


def _render_text_summary(result: QuickscanResult) -> str:
    lines: list[str] = []
    lines.append(f"pramana quickscan -- {result.elapsed_seconds:.2f}s")
    lines.append("")
    lines.append("adapters:")
    for r in result.scan_results:
        lines.append(
            f"  [{r.outcome.value:9s}] {r.adapter_id}: {len(r.findings)} finding(s), "
            f"{len(r.coverage.scanned)} item(s) scanned"
        )
    skipped = [row for row in result.discovery if not row.run]
    if skipped:
        lines.append("skipped:")
        for row in skipped:
            lines.append(f"  {row.adapter_id}: {row.reason}")
    lines.append("")
    asset_count = len(result.correlation_document["assets"]) if result.correlation_document else 0
    counts = _family_counts(result)
    lines.append(
        f"assets: {asset_count}  quantum-vulnerable: {counts['vulnerable']}  "
        f"not-vulnerable: {counts['not_vulnerable']}  unclassified: {counts['unclassified']}  "
        f"recommendations: {len(result.recommendations)}"
    )
    top = _asset_risk_rows(result)
    if top:
        lines.append("top riskiest assets:")
        for row in top:
            lines.append(f"  {row['label']}: {row['why']}")
    if result.ledger_skip_reason:
        lines.append(f"note: {result.ledger_skip_reason}")
    if result.context_hint:
        lines.append(f"note: {result.context_hint}")
    if result.sector_statuses:
        counts: dict[str, int] = {}
        for row in result.sector_statuses:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        lines.append("sector: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    elif result.sector_skip_reason and not result.ledger_skip_reason:
        lines.append(f"sector: {result.sector_skip_reason}")
    if result.cbom_signed is not None:
        lines.append(f"CBOM export: {'signed' if result.cbom_signed else 'unsigned'} -> {result.out_dir / 'cbom.json'}")
    elif result.cbom_skip_reason and not result.ledger_skip_reason:
        lines.append(f"CBOM export: {result.cbom_skip_reason}")
    lines.append("")
    lines.append(f"wrote {len(result.written_files)} file(s) -> {result.out_dir}")
    return "\n".join(lines)
