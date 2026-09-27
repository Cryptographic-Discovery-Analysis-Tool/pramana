"""ECDAT command line.

`scan` runs one adapter over one target and writes a run document: the
findings, their per-field epistemic states, the evidence behind them, and the
visibility entries saying what was and was not examined.

The run document is the only thing a scorer ever sees. ECDAT itself never reads
ground truth -- the join between a run and planted truth happens on the harness
side, so the tool cannot be tuned against the answer key.

**Eight adapters, two very different shapes.** `certs-x509` and
`config-chain-spring` read a local path directly -- `--input` *is* the
target, with no live/replay distinction. The other six (`packages-trivy`,
`source-semgrep`, `images-cbomkit-theia`, `hsm-pkcs11`,
`binary-yara-readelf`, `tls-endpoint`) wrap a real tool behind a "runner"
(CLAUDE.md's subprocess-injection pattern, see each adapter's own module):
pass `--live` to actually shell out to that tool with its pinned flags, or
omit it to replay pre-recorded raw output through the same parser instead
(CLAUDE.md: "Replay of a recorded file (--input) is for tests and scoring
only") -- this is exactly what every one of those adapters' own unit tests
already do, just driven from argv instead of from Python. `tls-endpoint
--live` shells out to `openssl` only (DEV-004's full-offer/classical-only
probes plus DEV-013's per-group probes); sslyze's own live wiring is a
separate, larger, still-open piece of work (see the note above this
docstring's `correlate` section) -- `tools/prober/` remains the reference
for a coordinated sslyze+openssl vantage this single-process CLI does not
attempt to replicate.

`source-semgrep --live` and `packages-trivy --live` can both be routed
through an external launcher (e.g. WSL on a Windows dev machine, OI-009) via
`ECDAT_TOOL_LAUNCHER`/`ECDAT_<TOOL>_LAUNCHER`, `ECDAT_<TOOL>_BIN`, and
`ECDAT_<TOOL>_PATH_TRANSLATE` -- see `adapters/live_launcher.py`. `--input`
under `--live` is a directory to scan, translated into the launched
environment's own path convention when a launcher is configured; nothing
here hardcodes WSL.

`tls-endpoint --live` (DEV-004 + DEV-013) runs the openssl-only probes for
real: the full-offer and classical-only `s_client` handshakes and one
per-group `s_client` handshake per named group in `data/crypto_families.yaml`
-- see `adapters/tls/adapter.py::live_tls_probe_runner`. It never invokes
sslyze: sslyze's own live wiring (the AGPL-3.0 separate-process boundary,
spec §3) is a separate, larger piece of work this CLI does not attempt, so a
live TLS scan reports every sslyze-sourced field (curve enumeration,
`der_sha256`, `leaf_subject`, ...) as absent/UNKNOWN, with the coverage list
and visibility entry saying in words that sslyze was not run for that scan --
never a silent gap. Replay mode (`--sslyze-input` / `--negotiated-input` /
`--classical-only-input`) is unaffected and still accepts a recorded sslyze
document when one is available.

`correlate` runs several `scan`-shaped specs from one JSON plan file, in one
process, and feeds every resulting `AdapterRunResult` straight into
`ecdat.correlation.engine.correlate()` -- the one asset view across whichever
adapters were in the plan, with cross-surface same-object relationships
where a `der_sha256` hash actually matches. Kept in-process rather than
reading back `scan`'s own JSON output: that run-document shape is a
flattened, scorer-facing serialisation (fields become a list, not a dict),
and reconstructing full `Finding`/`FieldValue` objects from it would be a
lossy round-trip for no reason when the results are already sitting in
memory right after running each scan.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Callable

from ecdat.adapters.base import Adapter, AdapterRunResult, ScanTarget
from ecdat.adapters.binary.adapter import BinaryAdapter, BinaryScanBundle
from ecdat.adapters.binary.adapter import live_scan_runner as live_binary_runner
from ecdat.adapters.certs.adapter import CertificateAdapter
from ecdat.adapters.config.adapter import ConfigChainAdapter
from ecdat.adapters.hsm.adapter import HsmPkcs11Adapter, Pkcs11ProbeBundle
from ecdat.adapters.hsm.adapter import live_probe_runner as live_hsm_runner
from ecdat.adapters.kms.adapter import KmsAdapter, KmsProbeBundle
from ecdat.adapters.kms.adapter import live_kms_runner
from ecdat.adapters.images.adapter import ImagesAdapter
from ecdat.adapters.images.adapter import live_file_reader, live_theia_runner
from ecdat.adapters.k8s_secret.adapter import K8sSecretAdapter
from ecdat.adapters.packages.adapter import PackagesAdapter, TrivyScanBundle
from ecdat.adapters.packages.adapter import live_scan_runner as live_packages_runner
from ecdat.adapters.source.semgrep import SemgrepSourceAdapter
from ecdat.adapters.source.semgrep import live_scan_runner as live_semgrep_runner
from ecdat.adapters.tls.adapter import TlsEndpointAdapter, TlsProbeBundle
from ecdat.adapters.tls.adapter import live_tls_probe_runner
from ecdat.correlation.engine import CorrelationReport, ForbiddenEdgeError, correlate
from ecdat.correlation.graph import EvidenceGraph, build_graph
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity
from ecdat.risk.run import LedgerSubject, evaluate_run
from ecdat.risk.scenarios import (
    CaptureAssumption,
    CaptureMode,
    NoCitedScenarioError,
    Policy,
    Scenario,
)
from ecdat.context.binding import Lifetime
from ecdat.assemble import Declarations, assemble
from ecdat.store import DiffClass, InvalidRunIdError, JsonlRunStore, NoSuchRunError, Run
from ecdat.store.diff import diff_runs
from ecdat.export.signing import (
    MissingSignatureError,
    SignatureVerificationError,
    generate_signing_key,
    load_signing_key,
    private_key_pem,
    verify_bom,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: Every adapter that exists, keyed by its own declared `adapter_id`. Not
#: only a CLI concern -- kept as the canonical id -> class map other code
#: (scoring, a future orchestrator) can import instead of re-listing adapters.
ADAPTERS: dict[str, type[Adapter]] = {
    SemgrepSourceAdapter.adapter_id: SemgrepSourceAdapter,
    CertificateAdapter.adapter_id: CertificateAdapter,
    TlsEndpointAdapter.adapter_id: TlsEndpointAdapter,
    ConfigChainAdapter.adapter_id: ConfigChainAdapter,
    PackagesAdapter.adapter_id: PackagesAdapter,
    ImagesAdapter.adapter_id: ImagesAdapter,
    HsmPkcs11Adapter.adapter_id: HsmPkcs11Adapter,
    KmsAdapter.adapter_id: KmsAdapter,
    BinaryAdapter.adapter_id: BinaryAdapter,
    K8sSecretAdapter.adapter_id: K8sSecretAdapter,
}

#: Path to this repository's own YARA rules, used as `binary-yara-readelf`'s
#: `--live` default so a caller does not have to know the package layout to
#: run it. src/ecdat/cli.py -> src/ecdat -> src -> repo root.
_DEFAULT_RULES_PATH = str(
    Path(__file__).resolve().parents[2] / "rules" / "yara" / "crypto-constants.yar"
)


class CliUsageError(RuntimeError):
    """A `--adapter`-specific requirement was not met (e.g. a required flag
    for that adapter is missing). Distinct from argparse's own errors: this
    is a semantic requirement ("hsm-pkcs11 --live needs --pkcs11-module"),
    not a syntax one, and depends on which `--adapter` was chosen."""


def _read_optional_path(path: str | None) -> str | None:
    """None when no path was given at all; None when a given path does not
    exist, exactly like a real probe that never ran a particular sub-command
    -- this mirrors how e.g. `BinaryScanBundle`'s own fields distinguish
    "did not run" from "ran and got an empty string" (see its docstring)."""
    if not path:
        return None
    candidate = Path(path)
    return candidate.read_text(encoding="utf-8") if candidate.is_file() else None


# --- per-adapter construction --------------------------------------------------
# Each builder returns (adapter, target) from the same argparse.Namespace and
# ConfidenceBasis. Kept as one function per adapter rather than one generic
# path: the eight adapters take genuinely different required arguments
# (a property key list, a probe identity, a PKCS#11 module path, ...) and
# forcing them through one shape would either hide required inputs behind
# silent defaults or make every flag "required" for every adapter -- both are
# the kind of false uniformity this project's own adapter contract (Lock §4)
# was written to avoid.


def _build_semgrep(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError(
            "source-semgrep requires --input <directory to scan, with --live> or "
            "<recorded semgrep JSON file, without --live>"
        )
    runner = live_semgrep_runner() if args.live else None
    adapter = SemgrepSourceAdapter(
        base_confidence=args.confidence, confidence_basis=basis, scan_runner=runner
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_certs(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("certs-x509 requires --input <certificate file or directory>")
    password = args.keystore_password.encode("utf-8") if args.keystore_password else None
    adapter = CertificateAdapter(
        base_confidence=args.confidence, confidence_basis=basis, keystore_password=password
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_k8s_secret(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("k8s-secret requires --input <manifest file or directory>")
    adapter = K8sSecretAdapter(base_confidence=args.confidence, confidence_basis=basis)
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_config(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not args.input:
        raise CliUsageError("config-chain-spring requires --input <repository root>")
    if not args.property_key:
        raise CliUsageError(
            "config-chain-spring requires at least one --property-key (it resolves specific "
            "keys handed to it by an upstream source-adapter finding, never discovers them "
            "itself -- see adapters/config/adapter.py's module docstring)"
        )
    adapter = ConfigChainAdapter(
        property_keys=tuple(args.property_key),
        base_confidence=args.confidence,
        confidence_basis=basis,
        active_profile=args.active_profile,
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_packages(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("packages-trivy --live requires --input <rootfs directory>")
        runner = live_packages_runner(offline_db_path=args.offline_db_path)
    else:
        if not args.input:
            raise CliUsageError(
                "packages-trivy replay mode requires --input <recorded trivy JSON file> "
                "(or pass --live to run trivy for real)"
            )
        stdout_json = Path(args.input).read_text(encoding="utf-8")

        def runner(target: ScanTarget, _text: str = stdout_json) -> TrivyScanBundle:
            return TrivyScanBundle(stdout_json=_text)

    adapter = PackagesAdapter(
        base_confidence=args.confidence, confidence_basis=basis, scan_runner=runner
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_images(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("images-cbomkit-theia --live requires --input <image ref>")
        runner = live_theia_runner()
        # --live also enables certificate-hash enrichment (see
        # adapters/images/adapter.py's "Certificate hash enrichment"):
        # cbomkit-theia's own CBOM never carries one, so the adapter
        # independently re-reads and hashes each certificate it reported,
        # the same real capability replay mode has no bytes to offer.
        file_reader = live_file_reader()
    else:
        if not args.input:
            raise CliUsageError(
                "images-cbomkit-theia replay mode requires --input <recorded cbomkit-theia "
                "CycloneDX JSON file> (or pass --live to run it for real)"
            )
        document = json.loads(Path(args.input).read_text(encoding="utf-8"))

        def runner(target: ScanTarget, _document: dict[str, Any] = document) -> dict[str, Any]:
            return _document

        file_reader = None

    adapter = ImagesAdapter(
        base_confidence=args.confidence, confidence_basis=basis, runner=runner, file_reader=file_reader
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=args.input)


def _build_hsm(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.pkcs11_module:
            raise CliUsageError("hsm-pkcs11 --live requires --pkcs11-module <path to .so>")
        runner = live_hsm_runner(module_path=args.pkcs11_module, pin=args.pin)
        locator = args.pkcs11_module
    else:
        if not (args.pkcs11_slots_input or args.pkcs11_objects_input or args.pkcs11_mechanisms_input):
            raise CliUsageError(
                "hsm-pkcs11 replay mode requires at least one of --pkcs11-slots-input / "
                "--pkcs11-objects-input / --pkcs11-mechanisms-input (or pass --live with "
                "--pkcs11-module to probe a real token)"
            )
        bundle = Pkcs11ProbeBundle(
            slots_text=_read_optional_path(args.pkcs11_slots_input),
            objects_text=_read_optional_path(args.pkcs11_objects_input),
            authenticated=args.authenticated,
            mechanisms_text=_read_optional_path(args.pkcs11_mechanisms_input),
        )

        def runner(target: ScanTarget, _bundle: Pkcs11ProbeBundle = bundle) -> Pkcs11ProbeBundle:
            return _bundle

        locator = args.input or args.target_id
    adapter = HsmPkcs11Adapter(
        base_confidence=args.confidence, confidence_basis=basis, probe_runner=runner
    )
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_kms(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        runner = live_kms_runner(endpoint_url=args.kms_endpoint_url, region=args.kms_region)
        locator = args.kms_region or "aws-kms"
    else:
        if not args.kms_list_keys_input:
            raise CliUsageError(
                "kms-aws replay mode requires --kms-list-keys-input <recorded list-keys JSON "
                "file> (or pass --live, optionally with --kms-endpoint-url for LocalStack, to "
                "read a real account)"
            )
        bundle = KmsProbeBundle(
            list_keys_text=_read_optional_path(args.kms_list_keys_input),
            describe_key_texts=tuple(
                text for p in args.kms_describe_key_input if (text := _read_optional_path(p))
            ),
            public_key_texts=tuple(
                text for p in args.kms_public_key_input if (text := _read_optional_path(p))
            ),
        )

        def runner(target: ScanTarget, _bundle: KmsProbeBundle = bundle) -> KmsProbeBundle:
            return _bundle

        locator = args.kms_region or args.target_id
    adapter = KmsAdapter(base_confidence=args.confidence, confidence_basis=basis, runner=runner)
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_binary(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if args.live:
        if not args.input:
            raise CliUsageError("binary-yara-readelf --live requires --input <path to binary>")
        rules_path = args.rules_path or _DEFAULT_RULES_PATH
        runner = live_binary_runner(rules_path=rules_path)
    else:
        if not (args.yara_input or args.readelf_header_input or args.readelf_dynamic_input):
            raise CliUsageError(
                "binary-yara-readelf replay mode requires at least one of --yara-input / "
                "--readelf-header-input / --readelf-dynamic-input (or pass --live with "
                "--input <binary path> to scan a real file)"
            )
        bundle = BinaryScanBundle(
            yara_output=_read_optional_path(args.yara_input),
            readelf_header_output=_read_optional_path(args.readelf_header_input),
            readelf_dynamic_output=_read_optional_path(args.readelf_dynamic_input),
        )

        def runner(target: ScanTarget, _bundle: BinaryScanBundle = bundle) -> BinaryScanBundle:
            return _bundle

    adapter = BinaryAdapter(
        base_confidence=args.confidence, confidence_basis=basis, scan_runner=runner
    )
    locator = args.input or args.target_id
    return adapter, ScanTarget(target_id=args.target_id, locator=locator)


def _build_tls(args: argparse.Namespace, basis: ConfidenceBasis) -> tuple[Adapter, ScanTarget]:
    if not (args.host and args.vantage):
        raise CliUsageError(
            "tls-endpoint requires --host and --vantage: probe identity is recorded, never "
            "assumed (Lock §5 row 1 / CLAUDE.md)"
        )
    if args.live:
        # openssl only (DEV-004 full-offer/classical-only + DEV-013 per-group
        # probes) -- sslyze's own live wiring is separate, larger, still-open
        # work (module docstring above; docs/deviations.md DEV-013 "Scope not
        # attempted"). The adapter itself handles a bundle with no
        # sslyze_json correctly: those fields simply stay absent/UNKNOWN and
        # the coverage list records "sslyze: not run for this target".
        runner = live_tls_probe_runner(openssl_bin=args.openssl_bin)
    else:
        if not (args.sslyze_input or args.negotiated_input or args.classical_only_input):
            raise CliUsageError(
                "tls-endpoint replay mode requires at least one of --sslyze-input / "
                "--negotiated-input / --classical-only-input (or pass --live to run "
                "the openssl probes for real)"
            )
        bundle = TlsProbeBundle(
            sslyze_json=_read_optional_path(args.sslyze_input),
            negotiated_text=_read_optional_path(args.negotiated_input),
            classical_only_text=_read_optional_path(args.classical_only_input),
        )

        def runner(target: ScanTarget, _bundle: TlsProbeBundle = bundle) -> TlsProbeBundle:
            return _bundle

    probe = ProbeTargetIdentity(
        requested_host=args.host, port=args.port or 443, sni_sent=args.sni, probe_vantage=args.vantage
    )
    adapter = TlsEndpointAdapter(
        base_confidence=args.confidence, confidence_basis=basis, probe_runner=runner
    )
    target = ScanTarget(
        target_id=args.target_id,
        locator=f"{args.host}:{args.port or 443}",
        probe=probe,
        consent=args.consent,
    )
    return adapter, target


BUILDERS: dict[str, Callable[[argparse.Namespace, ConfidenceBasis], tuple[Adapter, ScanTarget]]] = {
    SemgrepSourceAdapter.adapter_id: _build_semgrep,
    CertificateAdapter.adapter_id: _build_certs,
    ConfigChainAdapter.adapter_id: _build_config,
    K8sSecretAdapter.adapter_id: _build_k8s_secret,
    PackagesAdapter.adapter_id: _build_packages,
    ImagesAdapter.adapter_id: _build_images,
    HsmPkcs11Adapter.adapter_id: _build_hsm,
    KmsAdapter.adapter_id: _build_kms,
    BinaryAdapter.adapter_id: _build_binary,
    TlsEndpointAdapter.adapter_id: _build_tls,
}


def _run_document(result: AdapterRunResult) -> dict[str, Any]:
    """Serialise a run for scoring and for a human reader.

    `fields` is a list rather than a map because the scorer works field by
    field: the headline metric counts fields reported as observed that the
    answer key says could only be inferred, declared or unknown.
    """
    findings = []
    for finding in result.findings:
        fields = []
        for name, value in finding.fields.items():
            entry: dict[str, Any] = {
                "field": name,
                "value": value.value,
                "epistemic_state": value.state.value,
                "evidence_refs": list(value.evidence_refs),
            }
            if value.resolution is not None:
                entry["resolution_status"] = value.resolution.status.value
                entry["resolution_reason"] = value.resolution.reason
            if value.rule_id is not None:
                entry["rule_id"] = value.rule_id
                entry["derived_from"] = list(value.derived_from)
            fields.append(entry)
        findings.append(
            {
                "finding_id": finding.finding_id,
                "surface": finding.surface,
                "evidence_refs": list(finding.evidence_refs),
                "fields": fields,
            }
        )

    return {
        "adapter_id": result.adapter_id,
        "support_level": result.support_level.value,
        "target_id": result.target.target_id,
        "outcome": result.outcome.value,
        "failure_reason": result.failure_reason,
        "observed_at": result.context.observed_at.isoformat(),
        "coverage": {
            "scanned": list(result.coverage.scanned),
            "skipped": list(result.coverage.skipped),
        },
        "visibility": [
            {
                "dimension": entry.dimension.value,
                "support_level": entry.support_level.value,
                "detail": entry.detail,
            }
            for entry in result.visibility
        ],
        "evidence": [
            {
                "evidence_id": evidence.evidence_id,
                "source_tool": evidence.source_tool,
                "tool_version": evidence.tool_version,
                "location": evidence.location,
                "base_confidence": evidence.base_confidence,
                "confidence_basis": {
                    "source": evidence.confidence_basis.source,
                    "justification": evidence.confidence_basis.justification,
                    "table_key": evidence.confidence_basis.table_key,
                    "citation": evidence.confidence_basis.citation,
                },
                "raw_ref": evidence.raw_ref,
            }
            for evidence in result.evidence
        ],
        "raw_captures": [
            {
                "raw_ref": capture.raw_ref,
                "source_tool": capture.source_tool,
                "tool_version": capture.tool_version,
                "sha256": capture.sha256,
            }
            for capture in result.raw_captures
        ],
        "findings": findings,
    }


def _scan(args: argparse.Namespace) -> int:
    builder = BUILDERS.get(args.adapter)
    if builder is None:
        print(
            f"unknown adapter {args.adapter!r}; available: {sorted(BUILDERS)}",
            file=sys.stderr,
        )
        return 2

    # No cited source-tool confidence table exists (OI-004 / ADR-002), so the
    # value is supplied here with its justification rather than held as a
    # default inside the adapter, and it travels with every evidence item.
    basis = ConfidenceBasis(
        source="ADAPTER_DECLARED",
        justification=args.confidence_justification,
    )

    try:
        adapter, target = builder(args, basis)
    except CliUsageError as exc:
        print(f"{args.adapter}: {exc}", file=sys.stderr)
        return 2

    result = adapter.run(target)
    document = _run_document(result)

    output = json.dumps(document, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(
            f"{result.adapter_id}: {result.outcome.value}, {len(result.findings)} finding(s) "
            f"from {len(result.coverage.scanned)} item(s) examined -> {args.out}"
        )
    else:
        print(output)
    return 0


# --- correlate: one asset view over several scans in one process ---------------

#: Every flag `scan`'s parser defines, with the same default argparse itself
#: would give it. A correlation plan entry only has to state what differs
#: from these -- exactly like typing a shorter `scan` command line that
#: relies on argparse's own defaults for everything else.
_PLAN_ENTRY_DEFAULTS: dict[str, Any] = {
    "input": None,
    "out": None,
    "live": False,
    "property_key": [],
    "active_profile": None,
    "keystore_password": None,
    "offline_db_path": None,
    "pkcs11_module": None,
    "pin": None,
    "authenticated": False,
    "pkcs11_slots_input": None,
    "pkcs11_objects_input": None,
    "pkcs11_mechanisms_input": None,
    "rules_path": None,
    "yara_input": None,
    "readelf_header_input": None,
    "readelf_dynamic_input": None,
    "host": None,
    "port": None,
    "sni": None,
    "vantage": None,
    "consent": False,
    "openssl_bin": None,
    "sslyze_input": None,
    "negotiated_input": None,
    "classical_only_input": None,
    "kms_endpoint_url": None,
    "kms_region": None,
    "kms_list_keys_input": None,
    "kms_describe_key_input": [],
    "kms_public_key_input": [],
}


def _args_from_plan_entry(entry: dict[str, Any]) -> argparse.Namespace:
    """One correlation-plan entry -> the same `argparse.Namespace` shape
    `scan`'s own builders already consume, so a plan entry and a `scan`
    command line are two spellings of exactly the same thing -- no second
    code path to keep in sync with BUILDERS."""
    for required in ("adapter", "target_id", "confidence", "confidence_justification"):
        if required not in entry:
            raise CliUsageError(f"plan entry missing required key {required!r}: {entry}")
    merged = {**_PLAN_ENTRY_DEFAULTS, **entry}
    return argparse.Namespace(**merged)


def _correlate_document(report: CorrelationReport) -> dict[str, Any]:
    """Serialise a CorrelationReport the same way `_run_document` serialises
    an AdapterRunResult: fields as a list (not a dict) for a scorer's sake,
    every epistemic state spelled out, nothing summarised away."""

    def asset_document(asset) -> dict[str, Any]:
        fields = []
        for name, value in asset.fields.items():
            entry: dict[str, Any] = {
                "field": name,
                "value": value.value,
                "epistemic_state": value.state.value,
                "evidence_refs": list(value.evidence_refs),
            }
            if value.resolution is not None:
                entry["resolution_status"] = value.resolution.status.value
                entry["resolution_reason"] = value.resolution.reason
            fields.append(entry)
        return {
            "asset_id": asset.asset_id,
            "scope_anchor": asset.scope_anchor,
            "algorithm_family": asset.algorithm_family,
            "parameters": asset.parameters,
            "purpose": asset.purpose,
            "finding_refs": list(asset.finding_refs),
            "fields": fields,
        }

    return {
        "source_adapter_ids": list(report.source_adapter_ids),
        "assets": [asset_document(asset) for asset in report.assets],
        "relationships": [
            {
                "type": relationship.type,
                "source_entity": relationship.source_entity,
                "target_entity": relationship.target_entity,
                "evidence_basis": relationship.evidence_basis.value,
                "epistemic_state": relationship.epistemic_state.value,
                "rule_id": relationship.rule_id,
                "evidence_refs": list(relationship.evidence_refs),
            }
            for relationship in report.relationships
        ],
        "shares_public_key_unclaimed": [list(pair) for pair in report.shares_public_key_unclaimed],
    }


def _agility_document(agility) -> dict[str, Any]:
    """build-plan.md P14, serialised: each of the three adopted fields with
    its own value, epistemic state and evidence_refs -- never collapsed into
    one summary field."""
    def field(fv) -> dict[str, Any]:
        return {
            "value": fv.value.value if hasattr(fv.value, "value") else fv.value,
            "state": fv.state.value,
            "evidence_refs": list(fv.evidence_refs),
        }

    return {
        "algorithm_selection": field(agility.algorithm_selection),
        "hybrid_capable": field(agility.hybrid_capable),
        "provider_pluggable": field(agility.provider_pluggable),
    }


def _graph_document(graph: EvidenceGraph) -> dict[str, Any]:
    """P15's graph view, serialised. Every edge carries its `strength` field
    verbatim -- nothing here decides which edges are shown or hides the
    distinction between claimed and unclaimed."""
    return {
        "nodes": [
            {
                "asset_id": node.asset_id,
                "algorithm_family": node.algorithm_family,
                "purpose": node.purpose,
                "scope_anchor": node.scope_anchor,
                "agility": _agility_document(node.agility),
            }
            for node in graph.nodes
        ],
        "edges": [
            {
                "source": edge.source,
                "target": edge.target,
                "strength": edge.strength.value,
                "type": edge.type,
                "evidence_basis": edge.evidence_basis,
                "rule_id": edge.rule_id,
                "epistemic_state": edge.epistemic_state,
                "note": edge.note,
            }
            for edge in graph.edges
        ],
        "gaps": [
            {"from_layer": gap.from_layer, "to_layer": gap.to_layer, "why": gap.why}
            for gap in graph.gaps
        ],
    }


def _run_plan(plan_path: str) -> list[AdapterRunResult] | int:
    """Run every scan spec in a JSON plan file. Returns the results, or an
    exit code (after printing why) when the plan cannot be run. Shared by
    `correlate` and `assemble` so a plan means the same thing to both."""
    try:
        plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"could not read plan file {plan_path!r}: {type(exc).__name__}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"plan file {plan_path!r} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(plan, list) or not plan:
        print(f"plan file {plan_path!r} must be a non-empty JSON list of scan specs", file=sys.stderr)
        return 2

    results: list[AdapterRunResult] = []
    for index, entry in enumerate(plan):
        try:
            entry_args = _args_from_plan_entry(entry)
        except CliUsageError as exc:
            print(f"plan entry {index}: {exc}", file=sys.stderr)
            return 2
        builder = BUILDERS.get(entry_args.adapter)
        if builder is None:
            print(f"plan entry {index}: unknown adapter {entry_args.adapter!r}", file=sys.stderr)
            return 2
        basis = ConfidenceBasis(
            source="ADAPTER_DECLARED", justification=entry_args.confidence_justification
        )
        try:
            adapter, target = builder(entry_args, basis)
        except CliUsageError as exc:
            print(f"plan entry {index} ({entry_args.adapter}): {exc}", file=sys.stderr)
            return 2
        results.append(adapter.run(target))
    return results


def _assemble(args: argparse.Namespace) -> int:
    """build-plan.md P21: scans -> ledger subjects, in the exact file shape
    `ledger-run --subjects` and the dashboard read."""
    results = _run_plan(args.plan)
    if isinstance(results, int):
        return results
    try:
        declarations = Declarations.load(args.declarations) if args.declarations else Declarations()
    except (OSError, ValueError) as exc:
        print(f"declarations file {args.declarations!r}: {exc}", file=sys.stderr)
        return 2

    assembly = assemble(results, declarations=declarations)
    Path(args.out).write_text(
        json.dumps(assembly.to_subjects_document(), indent=2) + "\n", encoding="utf-8"
    )
    declared = sum(1 for s in assembly.subjects if s.binding_key)
    print(
        f"{len(results)} scan(s) -> {len(assembly.subjects)} ledger subject(s) "
        f"({declared} with a declared data class), {len(assembly.unassembled)} unassembled -> {args.out}"
    )
    for item in assembly.unassembled:
        print(f"  unassembled [{item.adapter_id}] {item.finding_id or '-'}: {item.reason}")
    return 0


def _correlate(args: argparse.Namespace) -> int:
    results = _run_plan(args.plan)
    if isinstance(results, int):
        return results

    try:
        report = correlate(results)
    except ForbiddenEdgeError as exc:
        print(f"correlation refused: {exc}", file=sys.stderr)
        return 3

    if args.format == "graph":
        document = _graph_document(build_graph(report))
        summary = (
            f"{len(results)} scan(s) -> {len(report.assets)} node(s), "
            f"{len(document['edges'])} edge(s) ({sum(1 for e in document['edges'] if e['strength'] == 'claimed')} claimed, "
            f"{sum(1 for e in document['edges'] if e['strength'] == 'unclaimed')} unclaimed), "
            f"{len(document['gaps'])} named gap(s)"
        )
    else:
        document = _correlate_document(report)
        summary = (
            f"{len(results)} scan(s) -> {len(report.assets)} asset(s), "
            f"{len(report.relationships)} relationship(s)"
        )

    output = json.dumps(document, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        print(f"{summary} -> {args.out}")
    else:
        print(output)
    return 0


# --- run store: evaluate a ledger, save it, list runs, diff two of them ----
#
# build-plan.md P13. `store/` is a real repository behind the RunStore
# interface `risk/run.py::evaluate_run` already left open; nothing here
# decides a band -- `ledger-run` calls the same `evaluate_run` the API calls,
# and `diff` calls the same `diff_runs` tested in tests/unit/store/.


def _load_ledger_subjects(path: str) -> list[LedgerSubject]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = document["subjects"] if isinstance(document, dict) else document
    return [LedgerSubject.model_validate(row) for row in rows]


def _ledger_run(args: argparse.Namespace) -> int:
    try:
        subjects = _load_ledger_subjects(args.subjects)
    except OSError as exc:
        print(f"could not read subjects file {args.subjects!r}: {type(exc).__name__}", file=sys.stderr)
        return 2
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"subjects file {args.subjects!r} is malformed: {exc}", file=sys.stderr)
        return 2

    try:
        scenario = Scenario.load(args.scenario)
    except NoCitedScenarioError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        policy = Policy(
            capture_assumption=CaptureAssumption(
                mode=CaptureMode(args.capture), since=args.capture_since
            ),
            rollout_Y_default=Lifetime(days=args.rollout_y_days),
            accept_inferred_inputs=args.accept_inferred,
        )
    except ValueError as exc:
        print(f"policy: {exc}", file=sys.stderr)
        return 2

    as_of = args.as_of or date.today()
    result = evaluate_run(subjects, scenario=scenario, policy=policy, as_of=as_of)
    run = Run.from_result(result, target_id=args.target_id)

    store = JsonlRunStore(args.store_dir)
    store.save(run)
    print(
        f"{run.run_id}: {len(run.records)} row(s), {len(run.grover_flags)} grover flag(s), "
        f"{len(run.skipped)} skipped -> {args.store_dir}"
    )
    return 0


def _runs(args: argparse.Namespace) -> int:
    store = JsonlRunStore(args.store_dir)
    summaries = store.list_runs(target_id=args.target_id)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "run_id": s.run_id,
                        "target_id": s.target_id,
                        "scenario_id": s.scenario_id,
                        "as_of": s.as_of.isoformat(),
                        "recorded_at": s.recorded_at.isoformat(),
                        "row_count": s.row_count,
                    }
                    for s in summaries
                ],
                indent=2,
            )
        )
        return 0
    if not summaries:
        print(f"no runs in {args.store_dir}")
        return 0
    for s in summaries:
        print(
            f"{s.run_id}  {s.recorded_at.isoformat()}  target={s.target_id}  "
            f"scenario={s.scenario_id}  as_of={s.as_of.isoformat()}  rows={s.row_count}"
        )
    return 0


def _diff(args: argparse.Namespace) -> int:
    store = JsonlRunStore(args.store_dir)
    try:
        old = store.load(getattr(args, "from"))
        new = store.load(args.to)
    except (NoSuchRunError, InvalidRunIdError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    result = diff_runs(old, new)
    if args.json:
        print(
            json.dumps(
                {
                    "from_run_id": result.from_run_id,
                    "to_run_id": result.to_run_id,
                    "rows": [
                        {
                            "usage_context_id": row.usage_context_id,
                            "diff_class": row.diff_class.value,
                            "old_band": row.old_band.value if row.old_band else None,
                            "new_band": row.new_band.value if row.new_band else None,
                            "reason": row.reason,
                        }
                        for row in result.rows
                    ],
                },
                indent=2,
            )
        )
        return 0

    counts: dict[str, int] = {}
    for row in result.rows:
        counts[row.diff_class.value] = counts.get(row.diff_class.value, 0) + 1
    print(f"{old.run_id} -> {new.run_id}: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    for row in result.rows:
        if row.diff_class == DiffClass.UNCHANGED and not args.show_unchanged:
            continue
        print(f"  [{row.diff_class.value:9s}] {row.usage_context_id}: {row.reason}")
    return 0


# --- signed export: key generation and offline verification (OI-013) ------


def _keygen(args: argparse.Namespace) -> int:
    path = Path(args.out)
    if path.exists() and not args.force:
        print(f"{path} already exists; pass --force to overwrite it", file=sys.stderr)
        return 2
    key = generate_signing_key()
    path.write_bytes(private_key_pem(key))
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX permission bits
    public = key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    import base64

    fingerprint = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
    print(f"wrote Ed25519 private key -> {path}")
    print(f"public key (base64url, for out-of-band distribution to a verifier): {fingerprint}")
    print(
        "set ECDAT_SIGNING_KEY_PATH to this file's path before running "
        "`ecdat correlate`/serving the API to sign exports with it."
    )
    return 0


def _verify_export(args: argparse.Namespace) -> int:
    try:
        document = json.loads(Path(args.file).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"could not read {args.file!r}: {type(exc).__name__}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"{args.file!r} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        verify_bom(document)
    except MissingSignatureError as exc:
        print(f"unsigned: {exc}", file=sys.stderr)
        return 1
    except SignatureVerificationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    key_id = document["signature"].get("keyId", "(no keyId)")
    print(f"signature valid -- keyId={key_id!r}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ecdat", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run one adapter over one target")
    scan.add_argument("--adapter", required=True, choices=sorted(ADAPTERS))
    scan.add_argument(
        "--input",
        help="recorded tool output to replay, or (with --live) the real target -- meaning "
        "depends on --adapter; see each builder's error message for what it expects",
    )
    scan.add_argument("--target-id", required=True, help="identifier for the scanned target")
    scan.add_argument("--out", help="write the run document here (default: stdout)")
    scan.add_argument(
        "--confidence",
        type=float,
        required=True,
        help="base confidence for this tool's evidence; there is no cited table "
        "yet (OI-004), so it must be supplied and justified explicitly",
    )
    scan.add_argument(
        "--confidence-justification",
        required=True,
        help="why this confidence value was chosen; recorded with every evidence item",
    )
    scan.add_argument(
        "--live",
        action="store_true",
        help="packages-trivy / source-semgrep / images-cbomkit-theia / hsm-pkcs11 / "
        "binary-yara-readelf / tls-endpoint only: actually shell out to the real tool instead of "
        "replaying --input (tls-endpoint --live is openssl only -- see --openssl-bin and this "
        "module's docstring; packages-trivy/source-semgrep --live can be routed through "
        "ECDAT_TOOL_LAUNCHER/ECDAT_<TOOL>_LAUNCHER, e.g. WSL on Windows -- see "
        "adapters/live_launcher.py)",
    )

    # config-chain-spring
    scan.add_argument(
        "--property-key",
        action="append",
        default=[],
        help="config-chain-spring only: a Spring property key to resolve; repeatable",
    )
    scan.add_argument(
        "--active-profile", help="config-chain-spring only: the active Spring profile, if known"
    )

    # certs-x509
    scan.add_argument(
        "--keystore-password",
        help="certs-x509 only: PKCS#12 keystore password, if needed (held in memory only, "
        "never logged, never written to the run document)",
    )

    # packages-trivy --live
    scan.add_argument(
        "--offline-db-path", help="packages-trivy --live only: offline vulnerability-DB cache directory"
    )

    # hsm-pkcs11
    scan.add_argument("--pkcs11-module", help="hsm-pkcs11 --live only: path to the PKCS#11 module (.so)")
    scan.add_argument(
        "--pin",
        help="hsm-pkcs11 --live only: token PIN, passed only to the subprocess argv, never "
        "logged or written to the run document",
    )
    scan.add_argument(
        "--authenticated",
        action="store_true",
        help="hsm-pkcs11 replay mode only: mark --pkcs11-objects-input as having come from an "
        "authenticated (--login) listing",
    )
    scan.add_argument("--pkcs11-slots-input", help="hsm-pkcs11 replay mode: recorded --list-slots output")
    scan.add_argument("--pkcs11-objects-input", help="hsm-pkcs11 replay mode: recorded --list-objects output")
    scan.add_argument(
        "--pkcs11-mechanisms-input", help="hsm-pkcs11 replay mode: recorded --list-mechanisms output"
    )

    # kms-aws
    scan.add_argument(
        "--kms-endpoint-url",
        help="kms-aws --live only: override the AWS endpoint (e.g. a LocalStack URL such as "
        "http://localhost:4566). Omit entirely to read a real AWS account.",
    )
    scan.add_argument("--kms-region", help="kms-aws only: the AWS region to use")
    scan.add_argument("--kms-list-keys-input", help="kms-aws replay mode: recorded `aws kms list-keys` output")
    scan.add_argument(
        "--kms-describe-key-input",
        action="append",
        default=[],
        help="kms-aws replay mode: recorded `aws kms describe-key` output for one key; repeatable",
    )
    scan.add_argument(
        "--kms-public-key-input",
        action="append",
        default=[],
        help="kms-aws replay mode: recorded `aws kms get-public-key` output for one asymmetric "
        "key; repeatable, optional",
    )

    # binary-yara-readelf
    scan.add_argument(
        "--rules-path",
        help=f"binary-yara-readelf --live only: path to the YARA rule file "
        f"(default: {_DEFAULT_RULES_PATH})",
    )
    scan.add_argument("--yara-input", help="binary-yara-readelf replay mode: recorded `yara -s` output")
    scan.add_argument(
        "--readelf-header-input", help="binary-yara-readelf replay mode: recorded `readelf -h` output"
    )
    scan.add_argument(
        "--readelf-dynamic-input", help="binary-yara-readelf replay mode: recorded `readelf -d` output"
    )

    # tls-endpoint
    scan.add_argument("--host", help="tls-endpoint only: requested host")
    scan.add_argument("--port", type=int, help="tls-endpoint only: requested port (default 443)")
    scan.add_argument("--sni", help="tls-endpoint only: SNI sent")
    scan.add_argument("--vantage", help="tls-endpoint only: probe vantage (Lock §5 row 1)")
    scan.add_argument(
        "--consent",
        action="store_true",
        help="tls-endpoint only: consent to probe this target (required by ScanTarget itself)",
    )
    scan.add_argument(
        "--openssl-bin",
        help="tls-endpoint --live only: path to the openssl binary to shell out to (default: "
        "ECDAT_OPENSSL_BIN env var, else bare 'openssl' on PATH -- never the interpreter's own "
        "linked OpenSSL, see adapters/tls/adapter.py::resolve_openssl_bin). Must be >= 3.5.0 to "
        "negotiate a hybrid group at all; below that, or if it cannot be started, every hybrid "
        "field is reported UNKNOWN with a visibility note naming what was found.",
    )
    scan.add_argument("--sslyze-input", help="tls-endpoint replay mode: recorded sslyze JSON output")
    scan.add_argument(
        "--negotiated-input", help="tls-endpoint replay mode: recorded `openssl s_client` negotiated-group output"
    )
    scan.add_argument(
        "--classical-only-input",
        help="tls-endpoint replay mode: recorded classical-only `openssl s_client` probe output",
    )

    scan.set_defaults(func=_scan)

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="run several scans from a JSON plan file and produce one asset view",
    )
    correlate_parser.add_argument(
        "--plan",
        required=True,
        help="JSON file: a list of scan specs, each the same keys as `scan`'s own flags "
        "(adapter, target_id, confidence, confidence_justification required; everything "
        "else optional, defaulting the same way `scan` itself defaults it)",
    )
    correlate_parser.add_argument("--out", help="write the correlation report here (default: stdout)")
    correlate_parser.add_argument(
        "--format",
        choices=["report", "graph"],
        default="report",
        help="'report' (default): the flattened asset/relationship document. "
        "'graph' (build-plan.md P15): nodes, typed epistemically-labelled edges "
        "(claimed vs unclaimed), and the named gaps this engine refuses to draw.",
    )
    correlate_parser.set_defaults(func=_correlate)

    ledger_run = subparsers.add_parser(
        "ledger-run",
        help="evaluate a ledger over a subjects file under one scenario, and save the run "
        "(build-plan.md P13)",
    )
    ledger_run.add_argument(
        "--subjects",
        required=True,
        help="JSON file of LedgerSubjects -- same schema as "
        "tests/fixtures/ledger/subjects.json ({'subjects': [...]} or a bare list)",
    )
    ledger_run.add_argument("--target-id", required=True, help="identifier for the scanned target")
    ledger_run.add_argument("--scenario", required=True, help="a scenario id from data/scenarios.yaml")
    ledger_run.add_argument(
        "--capture",
        default=CaptureMode.SINCE_CONFIRMED.value,
        choices=[m.value for m in CaptureMode],
        help="capture_assumption mode (§5.4); default SINCE_CONFIRMED, the conservative reading",
    )
    ledger_run.add_argument(
        "--capture-since",
        type=date.fromisoformat,
        default=None,
        help="required date when --capture=SINCE_DATE",
    )
    ledger_run.add_argument(
        "--rollout-y-days",
        type=int,
        required=True,
        help="rollout window Y in days; no cited default exists (data/scenarios.yaml), so it "
        "must be supplied explicitly, exactly like the dashboard's own control",
    )
    ledger_run.add_argument("--accept-inferred", action="store_true")
    ledger_run.add_argument("--as-of", type=date.fromisoformat, default=None, help="default: today")
    ledger_run.add_argument(
        "--store-dir", required=True, help="directory a JsonlRunStore reads and writes runs in"
    )
    ledger_run.set_defaults(func=_ledger_run)

    runs_parser = subparsers.add_parser("runs", help="list runs in a store (build-plan.md P13)")
    runs_parser.add_argument("--store-dir", required=True)
    runs_parser.add_argument("--target-id", default=None, help="only list runs for this target")
    runs_parser.add_argument("--json", action="store_true")
    runs_parser.set_defaults(func=_runs)

    diff_parser = subparsers.add_parser(
        "diff", help="compare two runs: NEW/CHANGED/REMOVED/MIGRATED/REGRESSED/UNCHANGED (P13)"
    )
    diff_parser.add_argument("--store-dir", required=True)
    diff_parser.add_argument("--from", dest="from", required=True, help="older run_id")
    diff_parser.add_argument("--to", required=True, help="newer run_id")
    diff_parser.add_argument("--show-unchanged", action="store_true")
    diff_parser.add_argument("--json", action="store_true")
    diff_parser.set_defaults(func=_diff)

    assemble_parser = subparsers.add_parser(
        "assemble",
        help="run a scan plan and turn the findings into ledger subjects (build-plan.md P21)",
    )
    assemble_parser.add_argument("--plan", required=True, help="the same JSON plan `correlate` reads")
    assemble_parser.add_argument(
        "--declarations",
        help="YAML of data-class declarations: bindings: [{surface|asset, data_class, declared_by}]",
    )
    assemble_parser.add_argument("--out", required=True, help="write the subjects file here")
    assemble_parser.set_defaults(func=_assemble)

    keygen_parser = subparsers.add_parser(
        "keygen", help="generate an Ed25519 signing key for signed CBOM export (OI-013)"
    )
    keygen_parser.add_argument("--out", required=True, help="path to write the PEM private key")
    keygen_parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    keygen_parser.set_defaults(func=_keygen)

    verify_parser = subparsers.add_parser(
        "verify-export", help="verify a signed CycloneDX export's JSF signature (OI-013)"
    )
    verify_parser.add_argument("--file", required=True, help="the exported CBOM JSON file")
    verify_parser.set_defaults(func=_verify_export)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
