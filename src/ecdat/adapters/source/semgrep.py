"""Source-surface adapter: Semgrep JSON -> Findings + Evidence.

Reads output produced by ECDAT's own rules (`rules/semgrep/crypto-inventory-java.yaml`).
It does not run Semgrep; it parses output recorded under
tests/fixtures/recorded/, because CLAUDE.md forbids writing a parser for tool
output that has not been recorded first.

What this adapter is careful NOT to claim, and why:

* An algorithm that arrives through configuration is not observable here. The
  rules separate a literal argument from a non-literal one, and only a literal
  makes the algorithm field observed. A non-literal one leaves the field UNKNOWN
  with an UNRESOLVED resolution naming the expression to resolve, which is the
  configuration adapter's input (harness §14 CFG-001: resolution yields INFERRED,
  never observed).
* A literal transformation string fixes the string, not every parameter of the
  operation -- provider defaults can decide parameters the string does not name.
  So no parameter field is emitted from a call site at all.
* Purpose is never derivable from an API call (CLAUDE.md: purpose defaults to
  UNKNOWN, never guessed).
* Reachability is not observable: Lock §7 OQ-5 fixes `reachable` at UNKNOWN,
  with no reachability analysis anywhere in scope.
* Key sizes are not observable from a call site, even when a parameter is named
  after one.

The matched source line Semgrep returns is used transiently, to tell a value
written at the call site from one the engine propagated there, and is then
dropped: source text is the route by which key material would reach the store,
the CLI, an export or a snapshot.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    AdapterTimeout,
    Coverage,
    RawCapture,
    ScanTarget,
    _utc_now,
)
from ecdat.adapters.live_launcher import (
    IdentityPathTranslator,
    PathTranslator,
    build_launched_argv,
    resolve_launcher_prefix,
    resolve_path_translator,
    resolve_tool_bin,
)
from ecdat.model.epistemic import EpistemicState, Resolution, ResolutionStatus
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry

SOURCE_TOOL = "semgrep"

#: Versions whose JSON shape we have actually recorded and parsed. Output from
#: any other version is refused rather than parsed on the assumption that the
#: shape did not change.
RECORDED_VERSIONS = frozenset({"1.99.0"})

#: Rule id (final segment of Semgrep's check_id) -> what that match means.
#: Keying on the rule id rather than on a service name in the matched text is
#: deliberate: the rule already encodes whether the captured argument names an
#: algorithm, a protocol or a trust service, so the adapter never has to
#: re-derive that by matching strings.
_ALGORITHM_LITERAL = "crypto-call-literal-algorithm"
_ALGORITHM_NONLITERAL = "crypto-call-nonliteral-algorithm"
_PROTOCOL_LITERAL = "crypto-call-literal-protocol"
_PROTOCOL_NONLITERAL = "crypto-call-nonliteral-protocol"
_TRUST_SERVICE_LITERAL = "crypto-call-literal-trust-service"
_PROVIDER_ARGUMENT = "crypto-call-explicit-provider-argument"
_CONFIG_BINDING = "crypto-config-property-binding-declaration"

_UNRESOLVED_NONLITERAL = (
    "algorithm argument is not a literal at the call site; "
    "resolution requires the configuration chain"
)


class UnrecordedToolOutput(ValueError):
    """The output came from a tool version whose shape we have not recorded."""


class SemgrepInvocationError(RuntimeError):
    """A live `semgrep` subprocess exited non-zero or produced no output.

    Carries only a description, never the captured stdout/stderr -- same
    convention as `packages.adapter.TrivyInvocationError`.
    """


#: A sane per-invocation ceiling for one live `semgrep` call -- an
#: engineering default (CLAUDE.md: "per-target timeout" is the hard rule,
#: the number is not a cited fact), matching `packages.adapter`'s trivy
#: default.
DEFAULT_TIMEOUT_SECONDS = 300

#: CLAUDE.md subprocess default: "output size cap". Semgrep JSON can run
#: larger than trivy's per finding, so this is a looser cap than trivy's,
#: not a cited number.
MAX_OUTPUT_BYTES = 128 * 1024 * 1024

#: CLAUDE.md security defaults for subprocesses: "semgrep: --metrics=off,
#: SEMGREP_SEND_METRICS=off, --config rules/semgrep only, --timeout per
#: file, --max-target-bytes." This is the one and only rules config a live
#: invocation may use -- never `--config=auto`, which pulls Registry
#: content over the network (see the recorded-fixture README's note on
#: `e1_supplemental_*` having used `--config=auto`: that was a separate,
#: explicitly non-pinned experiment, not this adapter's own rules).
DEFAULT_RULES_CONFIG = "rules/semgrep"

#: CLAUDE.md: "--max-target-bytes" is a required pinned flag; this is the
#: engineering default, not a cited number.
DEFAULT_MAX_TARGET_BYTES = "5MB"

#: Per-file timeout in seconds, passed as semgrep's own `--timeout`.
DEFAULT_PER_FILE_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class SemgrepScanBundle:
    """Raw output of one semgrep invocation, before parsing.

    Mirrors `packages.adapter.TrivyScanBundle`: a dataclass of raw text the
    adapter has not looked at yet, so a test can construct one directly from
    a recorded fixture without ever touching a subprocess.
    """

    stdout_json: str | None = None
    #: Translates a path semgrep printed in `stdout_json` back into this
    #: process's own namespace. Defaults to identity for replay bundles
    #: built directly from a recorded fixture.
    path_translator: PathTranslator | None = None


#: A callable that runs semgrep against one target. Injected exactly as
#: `packages.adapter.ScanRunner` is, so the subprocess boundary is an
#: explicit seam and tests never shell out.
ScanRunner = Callable[[ScanTarget], SemgrepScanBundle]


def build_semgrep_argv(
    locator: str,
    *,
    rules_config: str = DEFAULT_RULES_CONFIG,
    per_file_timeout_seconds: int = DEFAULT_PER_FILE_TIMEOUT_SECONDS,
    max_target_bytes: str = DEFAULT_MAX_TARGET_BYTES,
    semgrep_bin: str = "semgrep",
) -> list[str]:
    """The pinned argv for one live semgrep invocation (CLAUDE.md security
    defaults for subprocesses, quoted above `DEFAULT_RULES_CONFIG`).

    A pure function, tested directly without shelling out, exactly as
    `packages.adapter.build_trivy_argv` is.
    """
    return [
        semgrep_bin,
        "--config", rules_config,
        "--json",
        "--metrics=off",
        "--timeout", str(per_file_timeout_seconds),
        "--max-target-bytes", max_target_bytes,
        locator,
    ]


def live_scan_runner(
    *,
    rules_config: str = DEFAULT_RULES_CONFIG,
    per_file_timeout_seconds: int = DEFAULT_PER_FILE_TIMEOUT_SECONDS,
    max_target_bytes: str = DEFAULT_MAX_TARGET_BYTES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    launcher_prefix: list[str] | None = None,
    semgrep_bin: str | None = None,
    path_translator: PathTranslator | None = None,
    subprocess_runner: Callable[..., "subprocess.CompletedProcess[str]"] = subprocess.run,
) -> ScanRunner:
    """Build a `ScanRunner` that actually shells out to semgrep.

    Never the adapter's default -- `SemgrepSourceAdapter` only gains a live
    subprocess path when a caller explicitly passes this, exactly as
    `packages.adapter.live_scan_runner` requires for
    `PackagesAdapter.scan_runner`.

    `SEMGREP_SEND_METRICS=off` is set on the subprocess environment (the
    pinned `--metrics=off` flag disables metrics from this invocation;
    CLAUDE.md lists both, so both are set here) rather than mutating this
    process's own `os.environ`, so a live scan run never has a side effect
    outside the one subprocess call.

    `launcher_prefix`/`semgrep_bin`/`path_translator` default to resolving
    from `ECDAT_SEMGREP_LAUNCHER`/`ECDAT_TOOL_LAUNCHER`, `ECDAT_SEMGREP_BIN`
    and the inferred translator (see `adapters.live_launcher`) -- e.g. on a
    Windows dev machine where semgrep only runs inside WSL (OI-009, semgrep
    issue #1330: "Semgrep does not support Windows yet"),
    `ECDAT_SEMGREP_LAUNCHER="wsl -e"` routes every invocation through WSL
    with no code change here.
    """
    import os as _os

    resolved_prefix = (
        launcher_prefix if launcher_prefix is not None else resolve_launcher_prefix("semgrep")
    )
    resolved_bin = semgrep_bin if semgrep_bin is not None else resolve_tool_bin(
        "semgrep", "semgrep"
    )
    resolved_translator = (
        path_translator
        if path_translator is not None
        else resolve_path_translator("semgrep", resolved_prefix)
    )

    def _run(target: ScanTarget) -> SemgrepScanBundle:
        tool_locator = resolved_translator.to_tool(target.locator)
        tool_rules_config = resolved_translator.to_tool(rules_config)
        tool_argv = build_semgrep_argv(
            tool_locator,
            rules_config=tool_rules_config,
            per_file_timeout_seconds=per_file_timeout_seconds,
            max_target_bytes=max_target_bytes,
            semgrep_bin=resolved_bin,
        )
        argv = build_launched_argv(resolved_prefix, tool_argv)
        env = dict(_os.environ, SEMGREP_SEND_METRICS="off")
        try:
            completed = subprocess_runner(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"semgrep timed out after {timeout_seconds}s") from exc
        except OSError as exc:
            raise SemgrepInvocationError(
                f"could not start semgrep: {type(exc).__name__}"
            ) from None

        if len(completed.stdout.encode("utf-8", errors="ignore")) > MAX_OUTPUT_BYTES:
            raise SemgrepInvocationError("semgrep stdout exceeded the output-size cap")
        # Semgrep exits 1 when findings are reported (not an error) and 0
        # when clean; other nonzero codes are real failures.
        if completed.returncode not in (0, 1):
            raise SemgrepInvocationError(f"semgrep exited {completed.returncode}")
        return SemgrepScanBundle(stdout_json=completed.stdout, path_translator=resolved_translator)

    return _run


def _rule_id(check_id: str) -> str:
    """Semgrep prefixes check_id with the config path it was loaded from, so
    only the final segment is stable across machines and layouts."""
    return check_id.rsplit(".", 1)[-1]


def _metavar(result: dict[str, Any], name: str) -> str | None:
    entry = result.get("extra", {}).get("metavars", {}).get(name)
    if entry is None:
        return None
    content = entry.get("abstract_content")
    return content if isinstance(content, str) else None


def _strip_quotes(value: str) -> str:
    """Some rules capture the quotes with the value and some do not, depending
    on whether the pattern put the quotes around the metavariable."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _observed(value: Any, evidence_id: str) -> FieldValue:
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=(evidence_id,))


def _unknown(evidence_id: str, resolution: Resolution | None = None) -> FieldValue:
    return FieldValue(
        value=None,
        state=EpistemicState.UNKNOWN,
        resolution=resolution,
        evidence_refs=(evidence_id,),
    )


class SemgrepSourceAdapter(Adapter):
    adapter_id = "source-semgrep"
    #: Java call sites only -- not other languages, not reachability, not key
    #: sizes. `full` would overstate what this ruleset can see (Lock §4: the
    #: declared level feeds the visibility matrix).
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.SOURCE,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        scan_runner: ScanRunner | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        """`base_confidence` is injected, never defaulted: no cited source-tool
        confidence table exists (OI-004 / ADR-002), so the value is a caller's
        declared choice that travels with its own justification.

        `scan_runner` is optional and `None` by default: with no runner,
        `target.locator` is read directly as a recorded semgrep JSON file
        (this adapter's original, and CI's, replay behaviour -- unchanged).
        Passing a `ScanRunner` (e.g. `live_scan_runner()`) switches `_scan`
        to invoke it instead, exactly as `packages.adapter.PackagesAdapter`
        takes its `scan_runner`, except here it stays optional so every
        existing replay caller and test needs no change.
        """
        super().__init__(clock=clock)
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis
        self._scan_runner = scan_runner

    def parse(
        self,
        raw: dict[str, Any],
        *,
        raw_ref: str,
        path_translator: PathTranslator | None = None,
    ) -> tuple[tuple[Finding, ...], tuple[Evidence, ...], Coverage]:
        version = raw.get("version")
        if version not in RECORDED_VERSIONS:
            raise UnrecordedToolOutput(
                f"semgrep {version!r} output has not been recorded under "
                f"tests/fixtures/recorded/; recorded versions: {sorted(RECORDED_VERSIONS)}"
            )

        translator = path_translator or IdentityPathTranslator()

        paths = raw.get("paths") or {}
        coverage = Coverage(
            scanned=tuple(translator.from_tool(p) for p in (paths.get("scanned") or ())),
            skipped=tuple(
                translator.from_tool(entry.get("path", ""))
                for entry in (paths.get("skipped") or ())
                if isinstance(entry, dict)
            ),
        )

        # Every result's `path` is translated back out of the tool's own
        # namespace (a no-op under the default identity translator) *before*
        # grouping, so a live WSL run's findings carry the same
        # Windows-relative paths a replay run over the same target would --
        # the harness joins findings to ground truth on this path.
        results = raw.get("results") or ()
        if not isinstance(translator, IdentityPathTranslator):
            results = [
                {**result, "path": translator.from_tool(result["path"])} for result in results
            ]

        # One call site can be matched by more than one rule -- an explicit
        # provider argument is additive evidence about the same site, not a
        # second asset -- so results are grouped by their exact span first.
        grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
        for result in results:
            key = (result["path"], result["start"]["line"], result["start"]["col"])
            grouped.setdefault(key, []).append(result)

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for index, (key, results) in enumerate(sorted(grouped.items())):
            path, line, _column = key
            evidence_id = f"{self.adapter_id}:{index}"
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_tool=SOURCE_TOOL,
                    tool_version=version,
                    location=f"{path}:{line}",
                    base_confidence=self._base_confidence,
                    confidence_basis=self._confidence_basis,
                    raw_ref=raw_ref,
                )
            )
            fields = self._fields_for_call_site(results, path, line, evidence_id)
            if fields is None:
                evidence.pop()
                continue
            findings.append(
                Finding(
                    finding_id=f"{self.adapter_id}:{index}",
                    surface=VisibilityDimension.SOURCE.value,
                    evidence_refs=(evidence_id,),
                    fields=fields,
                )
            )
        return tuple(findings), tuple(evidence), coverage

    def _fields_for_call_site(
        self, results: list[dict[str, Any]], path: str, line: int, evidence_id: str
    ) -> dict[str, FieldValue] | None:
        rule_ids = {_rule_id(r["check_id"]) for r in results}
        by_rule = {_rule_id(r["check_id"]): r for r in results}

        fields: dict[str, FieldValue] = {
            "path": _observed(path, evidence_id),
            "line": _observed(line, evidence_id),
        }

        if _CONFIG_BINDING in rule_ids:
            prefix = _metavar(by_rule[_CONFIG_BINDING], "$PREFIX")
            if prefix is None:
                return None
            # Not a crypto asset: a declared binding between configuration and
            # code. It becomes useful only when the configuration adapter joins
            # it to an unresolved call site.
            fields["config_binding_prefix"] = _observed(_strip_quotes(prefix), evidence_id)
            return fields

        # Reachability is not observable here, and there is no reachability
        # analysis in scope (Lock §7 OQ-5). Recorded as UNKNOWN on every call
        # site so nothing downstream can read its absence as "in use".
        fields["reachable"] = _unknown(evidence_id)
        fields["purpose"] = _unknown(evidence_id)

        # The JCA class at the call site (`Cipher`, `Mac`, `Signature`, ...).
        # Read from the rule's `$1` capture (metavariable-regex group), which
        # the recorded 1.99.0 fixture carries; `$CLASS` repeats the token and
        # is the fallback. P21's bridge needs it: the crypto *function* comes
        # from which API is called, not from the algorithm string.
        for result in results:
            api_class = _metavar(result, "$1") or (
                (_metavar(result, "$CLASS") or "").split()[:1] or [None]
            )[0]
            if api_class:
                fields["api_class"] = _observed(api_class, evidence_id)
                break

        if _ALGORITHM_LITERAL in rule_ids:
            result = by_rule[_ALGORITHM_LITERAL]
            captured = _metavar(result, "$ALGO")
            if captured is None:
                return None
            value = _strip_quotes(captured)
            fields["algorithm"] = _observed(value, evidence_id)
            # Semgrep propagates constants, so a value can be reported for a
            # call site that does not literally contain it. The matched line is
            # inspected here and deliberately not kept.
            matched_line = result.get("extra", {}).get("lines", "")
            fields["algorithm_literal_at_call_site"] = _observed(
                value in matched_line, evidence_id
            )
        elif _ALGORITHM_NONLITERAL in rule_ids:
            result = by_rule[_ALGORITHM_NONLITERAL]
            argument = _metavar(result, "$ARG")
            if argument is None:
                return None
            fields["algorithm"] = _unknown(
                evidence_id,
                Resolution(status=ResolutionStatus.UNRESOLVED, reason=_UNRESOLVED_NONLITERAL),
            )
            # Kept so the configuration adapter knows what to resolve; without
            # it the call site could never be resolved later.
            fields["algorithm_argument"] = _observed(argument, evidence_id)
        elif _PROTOCOL_LITERAL in rule_ids:
            captured = _metavar(by_rule[_PROTOCOL_LITERAL], "$PROTO")
            if captured is None:
                return None
            fields["protocol"] = _observed(_strip_quotes(captured), evidence_id)
        elif _PROTOCOL_NONLITERAL in rule_ids:
            argument = _metavar(by_rule[_PROTOCOL_NONLITERAL], "$ARG")
            if argument is None:
                return None
            fields["protocol"] = _unknown(
                evidence_id,
                Resolution(status=ResolutionStatus.UNRESOLVED, reason=_UNRESOLVED_NONLITERAL),
            )
            fields["protocol_argument"] = _observed(argument, evidence_id)
        elif _TRUST_SERVICE_LITERAL in rule_ids:
            captured = _metavar(by_rule[_TRUST_SERVICE_LITERAL], "$SERVICE")
            if captured is None:
                return None
            fields["trust_service"] = _observed(_strip_quotes(captured), evidence_id)
        elif _PROVIDER_ARGUMENT not in rule_ids:
            return None

        if _PROVIDER_ARGUMENT in rule_ids:
            provider = _metavar(by_rule[_PROVIDER_ARGUMENT], "$PROVIDER")
            if provider is not None:
                # The provider *requested* at this call site. Whether that is
                # the provider that executes is a different question this
                # surface cannot answer, so the field is named for the argument.
                fields["provider_argument"] = _observed(_strip_quotes(provider), evidence_id)

        return fields

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        translator: PathTranslator | None = None
        if self._scan_runner is not None:
            bundle = self._scan_runner(target)
            if not bundle.stdout_json or not bundle.stdout_json.strip():
                raise SemgrepInvocationError("semgrep produced no output for this target")
            payload = bundle.stdout_json.encode("utf-8")
            raw = json.loads(bundle.stdout_json)
            raw_ref = f"semgrep://{target.locator}"
            translator = bundle.path_translator
        else:
            path = Path(target.locator)
            payload = path.read_bytes()
            raw = json.loads(payload.decode("utf-8"))
            raw_ref = path.name

        findings, evidence, coverage = self.parse(raw, raw_ref=raw_ref, path_translator=translator)
        capture = RawCapture(
            raw_ref=raw_ref,
            source_tool=SOURCE_TOOL,
            tool_version=raw["version"],
            sha256=hashlib.sha256(payload).hexdigest(),
            captured_at=self._clock(),
        )
        return AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=self._clock()),
            coverage=coverage,
            visibility=(self._visibility(target, coverage, findings),),
            raw_captures=(capture,),
            evidence=evidence,
            findings=findings,
        )

    def _visibility(
        self, target: ScanTarget, coverage: Coverage, findings: tuple[Finding, ...]
    ) -> VisibilityEntry:
        """What this run can honestly claim about the target.

        The distinction that matters: zero findings after examining files is a
        result; zero findings after examining nothing is not. Reporting the
        second as the first is the failure harness §7.3 tests for.
        """
        if not coverage.looked_at_anything:
            detail = (
                f"{target.target_id}: no file was examined -- this ruleset covers Java "
                "only, so the target is not covered by this adapter"
            )
        else:
            detail = (
                f"{target.target_id}: {len(coverage.scanned)} file(s) examined, "
                f"{len(findings)} call site(s) inventoried"
            )
        return VisibilityEntry(
            dimension=VisibilityDimension.SOURCE,
            support_level=self.support_level,
            detail=detail,
        )
