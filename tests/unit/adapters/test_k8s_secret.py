"""Kubernetes Secret adapter (DEV-014).

Every manifest here is synthesised by the test itself in tmp_path -- a
throwaway EC key and a self-signed certificate built with `cryptography` --
never a fixture read from the sibling harness checkout (ecdat tests must not
reference harness files; CLAUDE.md).
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ecdat.adapters.base import AdapterOutcome, ScanTarget
from ecdat.adapters.k8s_secret.adapter import K8sSecretAdapter
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.security.secrets import SecretLeakError, scan_for_secrets

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for Secret-manifest parsing (OI-004); a value read "
        "directly from a manifest is a direct observation, not an inference."
    ),
)


def adapter(**kw):
    return K8sSecretAdapter(base_confidence=0.9, confidence_basis=BASIS, **kw)


def _throwaway_key_and_cert() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "throwaway-test-cert")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _field_map(finding):
    return {name: value for name, value in finding.fields.items()}


def _finding_by_key(result, key: str):
    for finding in result.findings:
        fields = _field_map(finding)
        if "key" in fields and fields["key"].value == key:
            return finding
    raise AssertionError(f"no finding for key={key!r}: {[f.finding_id for f in result.findings]}")


def test_tls_secret_reports_private_key_metadata_never_bytes(tmp_path):
    key_pem, cert_pem = _throwaway_key_and_cert()
    manifest = tmp_path / "pay-tls-secret.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: pay-tls-secret\n"
        "  namespace: payments\n"
        "type: kubernetes.io/tls\n"
        "data:\n"
        f"  tls.key: \"{_b64(key_pem)}\"\n"
        f"  tls.crt: \"{_b64(cert_pem)}\"\n",
        encoding="utf-8",
    )

    target = ScanTarget(target_id="t", locator=str(manifest))
    result = adapter().run(target)

    assert result.outcome == AdapterOutcome.COMPLETED
    key_finding = _finding_by_key(result, "tls.key")
    fields = _field_map(key_finding)
    assert fields["content_kind"].value == "private_key"
    assert fields["contains_private_key_material"].value is True
    assert fields["contains_private_key_material"].state == EpistemicState.KNOWN
    assert fields["key_algorithm"].value == "EC"
    assert fields["key_curve"].value == "secp256r1"
    assert fields["secret_name"].value == "pay-tls-secret"
    assert fields["secret_namespace"].value == "payments"

    cert_finding = _finding_by_key(result, "tls.crt")
    cert_fields = _field_map(cert_finding)
    assert cert_fields["content_kind"].value == "certificate"
    assert len(cert_fields["der_sha256"].value) == 64

    # The hard rule, proven rather than asserted: nothing in the serialised
    # result contains the private key bytes, PEM armour, or the base64 blob.
    dump = result.model_dump_json()
    assert "BEGIN EC PRIVATE KEY" not in dump
    assert _b64(key_pem) not in dump
    scan_for_secrets(dump, context="test")  # must not raise


def test_opaque_and_string_data_entries(tmp_path):
    manifest = tmp_path / "app-secret.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: app-secret\n"
        "type: Opaque\n"
        "data:\n"
        f"  db-password: \"{_b64(b'not-a-cert-or-key')}\"\n"
        "stringData:\n"
        "  plain-note: hello\n",
        encoding="utf-8",
    )

    result = adapter().run(ScanTarget(target_id="t", locator=str(manifest)))
    assert result.outcome == AdapterOutcome.COMPLETED

    opaque = _field_map(_finding_by_key(result, "db-password"))
    assert opaque["content_kind"].value == "opaque"
    assert opaque["source_field"].value == "data"

    string_entry = _field_map(_finding_by_key(result, "plain-note"))
    assert string_entry["content_kind"].value == "opaque"
    assert string_entry["source_field"].value == "stringData"

    dump = result.model_dump_json()
    assert "not-a-cert-or-key" not in dump
    scan_for_secrets(dump, context="test")


def test_undecodable_base64_is_reported_not_raised(tmp_path):
    manifest = tmp_path / "broken-secret.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: broken\n"
        "data:\n"
        "  thing: \"not*valid*base64!!\"\n",
        encoding="utf-8",
    )
    result = adapter().run(ScanTarget(target_id="t", locator=str(manifest)))
    assert result.outcome == AdapterOutcome.COMPLETED
    finding = _finding_by_key(result, "thing")
    fields = _field_map(finding)
    assert fields["content_kind"].value == "undecodable"
    assert fields["note"].state == EpistemicState.KNOWN


def test_sealed_secret_is_detect_only_never_decoded(tmp_path):
    manifest = tmp_path / "sealed.yaml"
    manifest.write_text(
        "apiVersion: bitnami.com/v1alpha1\n"
        "kind: SealedSecret\n"
        "metadata:\n"
        "  name: sealed-thing\n"
        "spec:\n"
        "  encryptedData:\n"
        "    tls.key: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEq...\n",
        encoding="utf-8",
    )
    result = adapter().run(ScanTarget(target_id="t", locator=str(manifest)))
    assert result.outcome == AdapterOutcome.COMPLETED
    (finding,) = result.findings
    fields = _field_map(finding)
    assert fields["kind"].value == "SealedSecret"
    assert fields["content_kind"].value == "not-inspectable"
    assert fields["contains_private_key_material"].state == EpistemicState.UNKNOWN


def test_helm_chart_directory_is_detected_not_rendered(tmp_path):
    chart_dir = tmp_path / "mychart"
    chart_dir.mkdir()
    (chart_dir / "Chart.yaml").write_text("name: mychart\nversion: 0.1.0\n", encoding="utf-8")
    templates = chart_dir / "templates"
    templates.mkdir()
    (templates / "secret.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: {{ .Values.name }}\n"
        "data:\n"
        "  tls.key: {{ .Values.key | b64enc }}\n",
        encoding="utf-8",
    )
    result = adapter().run(ScanTarget(target_id="t", locator=str(tmp_path)))
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    detail = " ".join(entry.detail for entry in result.visibility)
    assert "not rendered" in detail
    assert "secret.yaml" in detail


def test_kustomization_file_is_detected_not_rendered(tmp_path):
    (tmp_path / "kustomization.yaml").write_text(
        "resources:\n  - secret.yaml\n", encoding="utf-8"
    )
    result = adapter().run(ScanTarget(target_id="t", locator=str(tmp_path)))
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    detail = " ".join(entry.detail for entry in result.visibility)
    assert "kustomize" in detail


def test_non_secret_manifest_still_counts_as_scanned(tmp_path):
    """TRAP-07 style: silence is not 'did not look'."""
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n", encoding="utf-8"
    )
    result = adapter().run(ScanTarget(target_id="t", locator=str(manifest)))
    assert result.outcome == AdapterOutcome.COMPLETED
    assert result.findings == ()
    assert str(manifest) in result.coverage.scanned


def test_key_material_leak_would_be_caught_by_the_guard():
    """Proves the guard this adapter relies on actually fires on a real key,
    independent of this adapter's own behaviour."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    try:
        scan_for_secrets(pem, context="test")
        raise AssertionError("expected SecretLeakError")
    except SecretLeakError:
        pass
