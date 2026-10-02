"""Package-inventory adapter (P5; spec §3 row "Packages"; build-plan.md P5 ->
PAY-008).

Runs `trivy rootfs --scanners vuln --list-all-pkgs` (never `trivy fs`, which
recorded evidence shows returns zero language-specific files for a
standalone fat jar -- see tests/fixtures/recorded/trivy/0.74.0/README.md)
and emits one Finding per package trivy reports.

**This adapter emits capability only, never usage** (CLAUDE.md: "Package
presence = capability, never usage. purpose defaults to UNKNOWN, never
guessed."). It deliberately never writes a `purpose`, `function`,
`algorithm` or `in_use`/`usage` field, and it never correlates a package
into a CryptoAsset -- a fat jar bundling a cryptography library is evidence
that the library is *present*, and this adapter stops exactly there. The
recorded fat-jar fixture makes the point concretely: it contains
`org.bouncycastle:bcprov-jdk18on`, and nothing on this observation surface
can say whether any source file in the artifact imports it. Turning package
presence into a usage claim is a later, separate correlation step
(`function.classifier`), explicitly out of scope here.

`support_level = DETECT_ONLY`, not `full` or `partial`: this adapter detects
that a package exists and says nothing about whether it resolves correctly,
whether it is reachable, or how it is used. Declaring anything higher would
claim coverage nobody implemented (Lock §4: the declared level feeds the
visibility matrix).

The tool-runner is injected exactly as `tls.adapter.TlsEndpointAdapter`
injects `probe_runner`: a `ScanRunner` callable taking the `ScanTarget` and
returning a small dataclass of raw text, so tests replay a recorded fixture
directly and the subprocess boundary stays a single, explicit seam rather
than being buried inside `_scan`. `live_scan_runner()` builds a `ScanRunner`
that actually shells out, with the pinned flags CLAUDE.md's subprocess
security defaults require: "trivy: --skip-db-update with configured offline
DB path; --timeout."
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.live_launcher import (
    IdentityPathTranslator,
    PathTranslator,
    build_launched_argv,
    resolve_launcher_prefix,
    resolve_path_translator,
    resolve_tool_bin,
)
from ecdat.adapters.packages.parser import ParsedPackage, parse
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

SOURCE_TOOL = "trivy"

#: A sane per-invocation ceiling, not a confidence value or a cited fact:
#: just the default wall-clock budget for one `trivy rootfs` call when the
#: caller does not override it. CLAUDE.md: "per-target timeout" is a hard
#: rule; the exact number is an engineering default, overridable per call.
DEFAULT_TIMEOUT_SECONDS = 300

#: A cap on how much stdout a single invocation may hand back before this
#: process gives up reading it (CLAUDE.md subprocess default: "output size
#: cap"). 64 MiB comfortably exceeds the recorded fixtures (each well under
#: 100 KiB) while still bounding a runaway or hostile tool.
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class TrivyInvocationError(RuntimeError):
    """A live `trivy` subprocess exited non-zero or produced no output.

    Carries only a description, never the captured stdout/stderr: tool
    output that failed to parse is exactly the kind of text CLAUDE.md's
    "never echo what you choked on" convention exists to keep out of an
    exception message.
    """


@dataclass(frozen=True)
class TrivyScanBundle:
    """Raw output of one trivy invocation, before parsing.

    Mirrors `tls.adapter.TlsProbeBundle`'s shape: a dataclass of raw text
    the adapter has not looked at yet, so a test can construct one directly
    from a recorded fixture without ever touching a subprocess.
    """

    stdout_json: str | None = None
    #: Translates a path trivy printed in `stdout_json` back into this
    #: process's own namespace (e.g. WSL `/mnt/c/...` -> `C:\...`). Defaults
    #: to identity (no-op) for replay bundles built directly from a recorded
    #: fixture, which never carry a foreign-namespace path.
    path_translator: PathTranslator | None = None


#: A callable that runs trivy against one target. Injected so that tests
#: replay recorded output and so the subprocess boundary is explicit rather
#: than buried -- the same reasoning `tls.adapter.ProbeRunner` documents.
ScanRunner = Callable[[ScanTarget], TrivyScanBundle]


def build_trivy_argv(
    locator: str,
    *,
    timeout_seconds: int,
    offline_db_path: str | None = None,
    trivy_bin: str = "trivy",
) -> list[str]:
    """The pinned argv for one live trivy invocation.

    `rootfs`, never `fs` -- `fs` mode returns zero language-specific files
    for a standalone jar (recorded fixture README, verified against two
    separate invocations: the jar directly and its containing directory).
    `--skip-db-update` plus an offline `--cache-dir` is CLAUDE.md's pinned
    subprocess default for trivy; `--list-all-pkgs` is what makes trivy
    enumerate every package rather than only ones with known vulnerabilities
    (P5 wants presence, not just CVE hits). `--format json` is required
    explicitly -- trivy's default output is a human-readable table
    regardless of whether stdout is a TTY (confirmed live 2026-09-20: a
    real invocation without this flag produced a table and this adapter's
    JSON parse failed on it; this was missing when the argv was first
    written and only surfaced once `ecdat scan --live` was actually wired
    up and run for real, not just against a fixture that happened to
    already be JSON).

    A pure function so the live-invocation shape can be asserted without
    ever shelling out (see tests/unit/adapters/test_packages.py).
    """
    argv = [
        trivy_bin, "rootfs", "--format", "json",
        "--scanners", "vuln", "--list-all-pkgs", "--skip-db-update",
    ]
    if offline_db_path:
        argv += ["--cache-dir", offline_db_path]
    argv += ["--timeout", f"{timeout_seconds}s", locator]
    return argv


def live_scan_runner(
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    offline_db_path: str | None = None,
    launcher_prefix: list[str] | None = None,
    trivy_bin: str | None = None,
    path_translator: PathTranslator | None = None,
    subprocess_runner: Callable[..., "subprocess.CompletedProcess[str]"] = subprocess.run,
) -> ScanRunner:
    """Build a `ScanRunner` that actually shells out to trivy.

    Kept as a factory returning a plain callable, never the adapter's
    default, so a `PackagesAdapter` can never be constructed with a live
    subprocess path by accident -- exactly as `TlsEndpointAdapter` requires
    `probe_runner` as a mandatory keyword argument with no default. Network
    egress for the invoked process is a deployment-level control (an
    offline-only container network, the same boundary the recorded trivy
    fixtures note for the sibling test environment), not something this
    function can enforce from inside a single `subprocess.run` call; what
    this function does enforce is the pinned, no-DB-fetch flag set above,
    the wall-clock timeout, and the output-size cap below.

    `launcher_prefix`/`trivy_bin`/`path_translator` default to resolving
    from `ECDAT_TRIVY_LAUNCHER`/`ECDAT_TOOL_LAUNCHER`, `ECDAT_TRIVY_BIN` and
    the inferred translator (see `adapters.live_launcher`) when not passed
    explicitly -- e.g. on a Windows dev machine where trivy only runs inside
    WSL (OI-009), `ECDAT_TRIVY_LAUNCHER="wsl -e"` routes every invocation
    through WSL with no code change here. `subprocess_runner` is injectable
    so tests can assert the exact composed argv without ever shelling out.
    """
    resolved_prefix = launcher_prefix if launcher_prefix is not None else resolve_launcher_prefix(
        "trivy"
    )
    resolved_bin = trivy_bin if trivy_bin is not None else resolve_tool_bin("trivy", "trivy")
    resolved_translator = (
        path_translator
        if path_translator is not None
        else resolve_path_translator("trivy", resolved_prefix)
    )

    def _run(target: ScanTarget) -> TrivyScanBundle:
        tool_locator = resolved_translator.to_tool(target.locator)
        tool_offline_db_path = (
            resolved_translator.to_tool(offline_db_path) if offline_db_path else None
        )
        tool_argv = build_trivy_argv(
            tool_locator,
            timeout_seconds=timeout_seconds,
            offline_db_path=tool_offline_db_path,
            trivy_bin=resolved_bin,
        )
        argv = build_launched_argv(resolved_prefix, tool_argv)
        try:
            completed = subprocess_runner(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"trivy timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise TrivyInvocationError(f"could not start trivy: {type(exc).__name__}") from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise TrivyInvocationError("trivy stdout exceeded the output-size cap")
        if completed.returncode != 0:
            raise TrivyInvocationError(f"trivy exited {completed.returncode}")
        return TrivyScanBundle(
            stdout_json=completed.stdout,
            path_translator=resolved_translator,
        )

    return _run


class PackagesAdapter(Adapter):
    adapter_id = "packages-trivy"

    #: DETECT_ONLY, not full/partial: this adapter detects that a package is
    #: present and resolves nothing about whether it is used, reachable, or
    #: correctly installed. `full`/`partial` would claim coverage this
    #: adapter does not implement (Lock §4: the declared level feeds the
    #: visibility matrix).
    support_level = SupportLevel.DETECT_ONLY
    dimensions = (VisibilityDimension.DEPENDENCY,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        scan_runner: ScanRunner,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited
        source-tool confidence row exists for trivy package presence
        (data/base_confidence.yaml usable_row_count == 0), so the caller
        supplies a value together with its own justification, exactly as
        certs/adapter.py and source/semgrep.py require."""
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._scan_runner = scan_runner

    # --- emission ------------------------------------------------------------

    def _fields(self, package: ParsedPackage, evidence_id: str) -> dict[str, FieldValue]:
        """Every field is KNOWN or UNKNOWN: trivy either reported it or did
        not, and none of them is a judgement, so none of them is derived.

        No `purpose`, `function`, `algorithm` or `in_use`/`usage` field is
        emitted here, ever -- that is the one mistake this whole adapter
        exists to avoid (CLAUDE.md: "Package presence = capability, never
        usage. purpose defaults to UNKNOWN, never guessed.").
        """
        refs = (evidence_id,)

        def known(value):
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=refs)

        def known_or_unknown(value):
            # Absent is UNKNOWN, not empty: "trivy reported no licenses for
            # this package" and "we did not look" must not collapse
            # (certs/adapter.py's known_or_unknown carries the same rule).
            return (
                known(value)
                if value not in (None, (), "")
                else FieldValue(value=None, state=EpistemicState.UNKNOWN)
            )

        return {
            "name": known(package.name),
            "version": known_or_unknown(package.version),
            "purl": known_or_unknown(package.purl),
            "licenses": known_or_unknown(package.licenses),
            "file_path": known_or_unknown(package.file_path),
            "analyzed_by": known_or_unknown(package.analyzed_by),
        }

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        observed_at = self._clock()
        bundle = self._scan_runner(target)

        if not bundle.stdout_json or not bundle.stdout_json.strip():
            raise TrivyInvocationError("trivy produced no output for this target")

        document = json.loads(bundle.stdout_json)
        parsed = parse(document)
        translator = bundle.path_translator or IdentityPathTranslator()
        if parsed.artifact_name:
            parsed = replace(parsed, artifact_name=translator.from_tool(parsed.artifact_name))
        if parsed.packages:
            parsed = replace(
                parsed,
                packages=tuple(
                    replace(pkg, file_path=translator.from_tool(pkg.file_path))
                    if pkg.file_path
                    else pkg
                    for pkg in parsed.packages
                ),
            )

        raw_ref = f"trivy://{target.locator}"
        raw_captures = (
            RawCapture(
                raw_ref=raw_ref,
                source_tool=SOURCE_TOOL,
                tool_version=parsed.trivy_version or "unknown",
                sha256=hashlib.sha256(bundle.stdout_json.encode("utf-8")).hexdigest(),
                captured_at=observed_at,
            ),
        )

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        # What trivy itself says it examined -- ArtifactName is present even
        # on the zero-package document (TRAP-07 fixture), so coverage.scanned
        # is never empty just because nothing was found (harness §7.3:
        # "silence != scanned").
        scanned_target = parsed.artifact_name or target.locator
        surface = f"packages:{scanned_target}"

        for index, package in enumerate(parsed.packages):
            evidence_id = f"{self.adapter_id}:{index}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=SOURCE_TOOL,
                    tool_version=parsed.trivy_version or "unknown",
                    location=package.file_path or scanned_target,
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{index}",
                    surface=surface,
                    evidence_refs=(evidence_id,),
                    fields=self._fields(package, evidence_id),
                )
            )

        detail = (
            f"{target.target_id}: trivy rootfs scanned {scanned_target!r}, "
            f"reported {len(findings)} package(s). Presence only -- no field "
            "here states or implies that any package is actually used."
        )

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            coverage=Coverage(scanned=(scanned_target,)),
            visibility=(
                VisibilityEntry(
                    dimension=VisibilityDimension.DEPENDENCY,
                    support_level=self.support_level,
                    detail=detail,
                ),
            ),
            raw_captures=raw_captures,
            evidence=tuple(evidence),
            findings=tuple(findings),
        )

        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result
