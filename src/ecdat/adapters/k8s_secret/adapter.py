"""Kubernetes Secret adapter (generic deployment-manifest surface; not tied
to any one deployment or vendor).

Reads plain YAML Kubernetes manifests -- a directory or a single file -- and
emits one Finding per `data`/`stringData` entry of every `kind: Secret`
document it finds. It exists because a Secret manifest is one of the places
a private key or a certificate ends up sitting in plaintext-adjacent form
(base64 is encoding, not encryption) outside the artefact surface `certs`
already covers, and CLAUDE.md is explicit that a manifest holding key
material is "a real risk signal" worth reporting -- as a location and a
fingerprint, never as the bytes themselves.

**What this adapter does NOT do, deliberately:**

* **It does not render Helm templates or run kustomize.** A file under a
  directory that also holds a `Chart.yaml`, or named `kustomization.yaml`,
  or a file whose content contains Go template delimiters (`{{ ... }}`,
  which is not valid YAML and would otherwise show up as a parse failure)
  is reported as DETECTED but not parsed for secret content -- Lock §4's
  visibility-matrix honesty requirement applies as much to "we saw a
  template but did not evaluate it" as it does to an unsupported file
  format. Actually rendering a chart or overlay would require invoking helm
  or kustomize as an external tool with its own version, flags and trust
  boundary, which is out of this adapter's scope.
* **It does not decrypt SealedSecret or resolve ExternalSecret.** Both
  `kind`s are recognised and reported as present, but their content is
  never the plaintext at rest (see `parser.DETECT_ONLY_KINDS`), so every
  content field for those documents stays UNKNOWN.
* **It does not judge severity.** "A plaintext private key is sitting in
  this manifest" is the fact this adapter reports; deciding that is bad, or
  how bad, is a downstream (risk/ledger) concern.
* **It emits no key material, no base64 values, and no decoded secret
  bytes**, and proves it exactly the way `certs.adapter.CertificateAdapter`
  does: every finding is serialised and run through the shared secret guard
  before the result leaves this module.

Certificate content found inside a Secret is described by
`adapters.certs.parser` directly (not re-implemented here), so a
certificate seen inside a Secret and the same certificate seen as a bare
file on disk carry the identical `der_sha256`/`spki_sha256` and correlate
as the same object through `ecdat.correlation.engine` without any
Secret-specific code there.

`base_confidence` is injected, exactly as every other direct-read adapter
in this codebase does it (OI-004 / ADR-002: no cited source-tool confidence
table exists yet).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Callable

from ecdat.adapters.base import (
    Adapter,
    AdapterOutcome,
    AdapterRunResult,
    Coverage,
    RawCapture,
    ScanTarget,
)
from ecdat.adapters.k8s_secret.parser import (
    DetectedOnlyManifest,
    K8sManifestParseError,
    ParsedSecretManifest,
    SecretKeyObservation,
    parse_manifest_text,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis, Evidence
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding
from ecdat.model.topology import ObservationContext
from ecdat.model.visibility import SupportLevel, VisibilityDimension, VisibilityEntry
from ecdat.security.secrets import scan_for_secrets

#: Files this adapter will even try to open as a k8s manifest.
_MANIFEST_SUFFIXES = frozenset({".yaml", ".yml"})

#: Filenames that are themselves an unrendered kustomize overlay entry
#: point, never a concrete manifest.
_KUSTOMIZE_FILENAMES = frozenset({"kustomization.yaml", "kustomization.yml"})

#: A crude but honest Helm-template sniff: Go template delimiters are not
#: legal YAML, so a file containing them cannot be a rendered manifest --
#: reporting it as "unparseable YAML" would be true but less useful than
#: naming what it actually looks like.
_HELM_TEMPLATE_MARKER = "{{"


def _library_version() -> str:
    import yaml as _yaml

    return _yaml.__version__


class K8sSecretAdapter(Adapter):
    adapter_id = "k8s-secret"

    #: PARTIAL: plain YAML `kind: Secret` (and detect-only reporting of
    #: SealedSecret/ExternalSecret) is read; Helm charts and kustomize
    #: overlays are detected but not rendered. Declaring FULL would assert
    #: template-evaluation coverage this adapter does not have.
    support_level = SupportLevel.PARTIAL
    dimensions = (VisibilityDimension.DEPLOYMENT,)

    def __init__(
        self,
        *,
        base_confidence: float,
        confidence_basis: ConfidenceBasis,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(**({"clock": clock} if clock else {}))
        self._base_confidence = base_confidence
        self._confidence_basis = confidence_basis

    # --- file discovery / classification -------------------------------------

    def _is_helm_chart_dir(self, directory: Path) -> bool:
        return (directory / "Chart.yaml").is_file() or (directory / "Chart.yml").is_file()

    def _template_kind(self, path: Path, root: Path, text: str) -> str | None:
        """"helm", "kustomize", or None (an ordinary manifest). Detected
        without parsing YAML, so it works even on content Go templating has
        made invalid YAML."""
        if path.name in _KUSTOMIZE_FILENAMES:
            return "kustomize"
        # Any ancestor directory up to (and including) root that holds a
        # Chart.yaml marks everything under it as chart content, "templates/"
        # or not -- a chart's values.yaml is template input, not a manifest,
        # even though it carries no {{ }} itself (DEV entry records this).
        candidate = path.parent
        while True:
            if self._is_helm_chart_dir(candidate):
                return "helm"
            if candidate == root or candidate.parent == candidate:
                break
            candidate = candidate.parent
        if _HELM_TEMPLATE_MARKER in text:
            return "helm"
        return None

    def _candidates(self, root: Path) -> tuple[list[Path], list[str]]:
        if root.is_file():
            if root.suffix.lower() in _MANIFEST_SUFFIXES:
                return [root], []
            return [], [f"{root}: unrecognised extension {root.suffix or '(none)'}"]

        attempt: list[Path] = []
        skipped: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() in _MANIFEST_SUFFIXES:
                attempt.append(path)
            else:
                skipped.append(f"{path}: unrecognised extension {path.suffix or '(none)'}")
        return attempt, skipped

    # --- field construction ---------------------------------------------------

    def _secret_key_fields(
        self, manifest: ParsedSecretManifest, key: SecretKeyObservation, evidence_id: str
    ) -> dict[str, FieldValue]:
        refs = (evidence_id,)

        def known(value):
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=refs)

        def known_or_unknown(value):
            return (
                known(value)
                if value not in (None, (), "")
                else FieldValue(value=None, state=EpistemicState.UNKNOWN)
            )

        fields: dict[str, FieldValue] = {
            "manifest_path": known(manifest.location),
            "secret_name": known_or_unknown(manifest.name),
            "secret_namespace": known_or_unknown(manifest.namespace),
            "secret_type": known_or_unknown(manifest.secret_type),
            "key": known(key.key),
            "source_field": known(key.source_field),
            "content_kind": known(key.content_kind),
        }

        if key.content_kind == "certificate" and key.certificates:
            # Only ever the first certificate: `data.tls.crt`/`ca.crt` name a
            # single logical value in ground truth's `key` scheme (`data.<key>`),
            # and a chain's later entries are a different fact (a chain, not
            # this leaf) that a repeated-key scheme cannot express without
            # inventing a location syntax nothing in this repo defines. Every
            # certificate this observation actually parsed is still visible in
            # `note` below, never silently dropped.
            certificate = key.certificates[0]
            fields.update(
                {
                    "der_sha256": known(certificate.der_sha256),
                    "spki_sha256": known(certificate.spki_sha256),
                    "subject": known(certificate.subject),
                    "issuer": known(certificate.issuer),
                    "public_key_algorithm": known(certificate.public_key_algorithm),
                    "public_key_size": known_or_unknown(certificate.public_key_size),
                    "public_key_curve": known_or_unknown(certificate.public_key_curve),
                }
            )
            if len(key.certificates) > 1:
                fields["note"] = known(
                    f"{len(key.certificates)} certificates present at this key; only the first is described"
                )
        elif key.content_kind == "private_key":
            fields.update(
                {
                    "contains_private_key_material": known(True),
                    "key_algorithm": known_or_unknown(key.key_algorithm),
                    "key_size": known_or_unknown(key.key_size),
                    "key_curve": known_or_unknown(key.key_curve),
                }
            )
        elif key.content_kind == "undecodable":
            fields["note"] = known(key.note or "value could not be decoded/parsed")

        return fields

    def _detect_only_fields(self, manifest: DetectedOnlyManifest, evidence_id: str) -> dict[str, FieldValue]:
        refs = (evidence_id,)

        def known(value):
            return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=refs)

        def known_or_unknown(value):
            return (
                known(value)
                if value not in (None, (), "")
                else FieldValue(value=None, state=EpistemicState.UNKNOWN)
            )

        return {
            "manifest_path": known(manifest.location),
            "kind": known(manifest.kind),
            "secret_name": known_or_unknown(manifest.name),
            "secret_namespace": known_or_unknown(manifest.namespace),
            "content_kind": known("not-inspectable"),
            # The value at rest for these kinds is never the plaintext (see
            # parser.DETECT_ONLY_KINDS docstring) -- there is nothing to read,
            # so every content-shaped field this adapter could otherwise emit
            # is UNKNOWN rather than fabricated as absent-therefore-false.
            "contains_private_key_material": FieldValue(value=None, state=EpistemicState.UNKNOWN),
        }

    # --- scan ------------------------------------------------------------------

    def _scan(self, target: ScanTarget) -> AdapterRunResult:
        root = Path(target.locator)
        observed_at = self._clock()

        if not root.exists():
            raise FileNotFoundError(target.locator)

        attempt, skipped = self._candidates(root)
        scanned: list[str] = []
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        library_version = _library_version()
        template_notes: list[str] = []

        for path in attempt:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                skipped.append(f"{path}: unreadable ({type(error).__name__})")
                continue

            template_kind = self._template_kind(path, root, text)
            if template_kind is not None:
                template_notes.append(f"{path} ({template_kind}, not rendered)")
                continue

            try:
                secrets, detect_only, notes = parse_manifest_text(text, location=str(path))
            except K8sManifestParseError as error:
                skipped.append(str(error))
                continue

            if not secrets and not detect_only:
                # Read, understood, and genuinely holds nothing this adapter
                # covers (e.g. a Deployment or a Service manifest). Still
                # counted as scanned: silence is not "did not look" (TRAP-07).
                scanned.append(str(path))
                continue

            scanned.append(str(path))
            raw_ref = f"file://{path}"

            for manifest in secrets:
                for key in manifest.keys:
                    evidence_id = f"{self.adapter_id}:{len(evidence)}"
                    evidence.append(
                        Evidence(
                            evidence_id=evidence_id,
                            source_tool="pyyaml+python-cryptography",
                            tool_version=library_version,
                            location=f"{path}#{manifest.doc_index}:{key.source_field}.{key.key}",
                            base_confidence=self._base_confidence,
                            confidence_basis=self._confidence_basis,
                            raw_ref=raw_ref,
                        )
                    )
                    finding_key = hashlib.sha256(
                        f"{path}:{manifest.doc_index}:{key.source_field}.{key.key}".encode("utf-8")
                    ).hexdigest()[:16]
                    findings.append(
                        Finding(
                            finding_id=f"{self.adapter_id}:{finding_key}",
                            surface=f"k8ssecret:{path}:{key.source_field}.{key.key}",
                            evidence_refs=(evidence_id,),
                            fields=self._secret_key_fields(manifest, key, evidence_id),
                        )
                    )

            for manifest in detect_only:
                evidence_id = f"{self.adapter_id}:{len(evidence)}"
                evidence.append(
                    Evidence(
                        evidence_id=evidence_id,
                        source_tool="pyyaml+python-cryptography",
                        tool_version=library_version,
                        location=f"{path}#{manifest.doc_index}",
                        base_confidence=self._base_confidence,
                        confidence_basis=self._confidence_basis,
                        raw_ref=raw_ref,
                    )
                )
                finding_key = hashlib.sha256(f"{path}:{manifest.doc_index}:detect-only".encode("utf-8")).hexdigest()[:16]
                findings.append(
                    Finding(
                        finding_id=f"{self.adapter_id}:{finding_key}",
                        surface=f"k8ssecret:{path}:{manifest.kind}",
                        evidence_refs=(evidence_id,),
                        fields=self._detect_only_fields(manifest, evidence_id),
                    )
                )

        raw_captures = tuple(
            RawCapture(
                raw_ref=f"file://{path}",
                source_tool="pyyaml+python-cryptography",
                tool_version=library_version,
                sha256=hashlib.sha256(Path(path).read_text(encoding="utf-8").encode("utf-8")).hexdigest(),
                captured_at=observed_at,
            )
            for path in scanned
        )

        detail_parts = [
            f"{target.target_id}: read {len(scanned)} manifest file(s), skipped {len(skipped)}.",
            "Only plain YAML kind: Secret is decoded; SealedSecret/ExternalSecret are detected "
            "but never decrypted/resolved.",
        ]
        if template_notes:
            detail_parts.append(
                f"{len(template_notes)} Helm/kustomize template file(s) detected, not rendered: "
                + "; ".join(sorted(template_notes))
            )
        visibility = [
            VisibilityEntry(
                dimension=VisibilityDimension.DEPLOYMENT,
                support_level=self.support_level,
                detail=" ".join(detail_parts),
            )
        ]

        result = AdapterRunResult(
            adapter_id=self.adapter_id,
            support_level=self.support_level,
            target=target,
            outcome=AdapterOutcome.COMPLETED,
            context=ObservationContext(observed_at=observed_at),
            coverage=Coverage(scanned=tuple(scanned), skipped=tuple(skipped)),
            visibility=tuple(visibility),
            raw_captures=raw_captures,
            evidence=tuple(evidence),
            findings=tuple(findings),
        )

        # The gate, on the way out -- this adapter routinely decodes private
        # key bytes in memory, so it proves it emitted none rather than
        # merely asserting it (same pattern as certs.adapter.CertificateAdapter).
        scan_for_secrets(
            result.model_dump_json(), context=f"{self.adapter_id} result for {target.target_id}"
        )
        return result
