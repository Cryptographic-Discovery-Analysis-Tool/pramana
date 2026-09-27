"""The CLI wiring (cli.py) for all nine adapters.

Every test here drives `main()` the way a real invocation would (an argv
list), against REAL recorded fixtures already committed under
tests/fixtures/recorded/ -- not synthesised JSON -- so a broken builder
(wrong bundle field, wrong runner signature) fails here the same way it
would on the command line, not just when called directly from Python as the
adapters' own unit tests do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from ecdat.cli import ADAPTERS, BUILDERS, main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "recorded"

SEMGREP_INPUT = FIXTURES / "semgrep" / "1.99.0" / "ecdat-rules" / "tier-a-java.raw.json"
TRIVY_INPUT = FIXTURES / "trivy" / "0.74.0" / "e1_supplemental_payment-gateway-fatjar.raw.json"
THEIA_INPUT = FIXTURES / "theia" / "edge-2026-09-19" / "edge-lb.sample.json"
YARA_INPUT = FIXTURES / "yara" / "4.5.0" / "libcrypto.match.verbose.txt"
READELF_HEADER_INPUT = FIXTURES / "readelf" / "tier_a_edge_lb.libcrypto.header.txt"
READELF_DYNAMIC_INPUT = FIXTURES / "readelf" / "tier_a_edge_lb.libcrypto.soname.txt"
PKCS11_SLOTS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-slots.txt"
PKCS11_OBJECTS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-objects-authenticated.txt"
PKCS11_MECHANISMS_INPUT = FIXTURES / "pkcs11-tool" / "opensc-0.25.0" / "list-mechanisms.txt"
SSLYZE_INPUT = FIXTURES / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
KMS_FIXTURES = FIXTURES / "aws-kms" / "localstack-3.0.2"
KMS_LIST_KEYS_INPUT = KMS_FIXTURES / "list-keys.json"
KMS_DESCRIBE_SYMMETRIC_INPUT = KMS_FIXTURES / "describe-key-symmetric.json"
KMS_DESCRIBE_ECC_INPUT = KMS_FIXTURES / "describe-key-ecc.json"
KMS_PUBLIC_KEY_ECC_INPUT = KMS_FIXTURES / "get-public-key-ecc.json"
NEGOTIATED_INPUT = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.negotiated.txt"
CLASSICAL_ONLY_INPUT = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.classical_only.txt"

COMMON = [
    "--target-id", "t", "--confidence", "0.9",
    "--confidence-justification", "test invocation, no cited table exists yet",
]


def _run(argv: list[str], out_path: Path, capsys) -> dict:
    exit_code = main(["scan", *COMMON, "--out", str(out_path), *argv])
    assert exit_code == 0, capsys.readouterr().err
    return json.loads(out_path.read_text(encoding="utf-8"))


# --- registry completeness ----------------------------------------------------


def test_every_declared_adapter_has_a_cli_builder():
    """The whole point of this task: no adapter exists that the CLI cannot
    reach. If an eleventh adapter is ever added without a BUILDERS entry,
    this fails immediately instead of silently leaving it unreachable."""
    assert set(ADAPTERS) == set(BUILDERS)
    assert len(ADAPTERS) == 10


# --- adapters that read a local path directly ----------------------------------


def test_semgrep_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "source-semgrep", "--input", str(SEMGREP_INPUT)],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "source-semgrep"
    assert document["outcome"] == "completed"
    assert document["findings"]


def test_certs_via_cli(tmp_path, capsys):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli-test")])
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
    cert_path = tmp_path / "cert.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    document = _run(
        ["--adapter", "certs-x509", "--input", str(cert_path)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "certs-x509"
    assert document["outcome"] == "completed"
    assert len(document["findings"]) == 1


def test_config_via_cli(tmp_path, capsys):
    resources = tmp_path / "src" / "main" / "resources"
    resources.mkdir(parents=True)
    (resources / "application.yml").write_text(
        "pay:\n  keywrap:\n    transformation: RSA/ECB/OAEPWithSHA-256AndMGF1Padding\n",
        encoding="utf-8",
    )
    document = _run(
        [
            "--adapter", "config-chain-spring",
            "--input", str(tmp_path),
            "--property-key", "pay.keywrap.transformation",
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "config-chain-spring"
    (finding,) = document["findings"]
    resolved = next(f for f in finding["fields"] if f["field"] == "resolved_value")
    assert resolved["epistemic_state"] == "INFERRED"
    assert resolved["value"] == "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"


def test_config_without_property_key_is_a_usage_error(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "config-chain-spring", "--input", str(tmp_path)]) == 2


# --- adapters that wrap a tool behind a runner (replay mode) -------------------


def test_packages_replay_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "packages-trivy", "--input", str(TRIVY_INPUT)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "packages-trivy"
    assert document["outcome"] == "completed"
    assert document["findings"]
    assert all(
        f not in field["field"]
        for field in document["findings"][0]["fields"]
        for f in ("purpose", "function", "in_use")
    )


def test_images_replay_via_cli(tmp_path, capsys):
    document = _run(
        ["--adapter", "images-cbomkit-theia", "--input", str(THEIA_INPUT)], tmp_path / "out.json", capsys
    )
    assert document["adapter_id"] == "images-cbomkit-theia"
    assert document["outcome"] == "completed"
    states = {f["epistemic_state"] for finding in document["findings"] for f in finding["fields"]}
    assert "KNOWN" not in states


def test_binary_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "binary-yara-readelf",
            "--yara-input", str(YARA_INPUT),
            "--readelf-header-input", str(READELF_HEADER_INPUT),
            "--readelf-dynamic-input", str(READELF_DYNAMIC_INPUT),
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "binary-yara-readelf"
    assert document["outcome"] == "completed"
    (finding,) = document["findings"]
    fields = {f["field"]: f for f in finding["fields"]}
    assert "AES" in str(fields["embedded_constant_families"]["value"])


def test_binary_replay_requires_at_least_one_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "binary-yara-readelf"]) == 2


def test_hsm_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "hsm-pkcs11",
            "--pkcs11-slots-input", str(PKCS11_SLOTS_INPUT),
            "--pkcs11-objects-input", str(PKCS11_OBJECTS_INPUT),
            "--pkcs11-mechanisms-input", str(PKCS11_MECHANISMS_INPUT),
            "--authenticated",
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "hsm-pkcs11"
    assert document["outcome"] == "completed"
    assert document["findings"]


def test_kms_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "kms-aws",
            "--kms-list-keys-input", str(KMS_LIST_KEYS_INPUT),
            "--kms-describe-key-input", str(KMS_DESCRIBE_SYMMETRIC_INPUT),
            "--kms-describe-key-input", str(KMS_DESCRIBE_ECC_INPUT),
            "--kms-public-key-input", str(KMS_PUBLIC_KEY_ECC_INPUT),
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "kms-aws"
    assert document["outcome"] == "completed"
    assert len(document["findings"]) == 2
    ecc = next(
        f for f in document["findings"]
        if any(fl["field"] == "key_spec" and fl["value"] == "ECC_NIST_P256" for fl in f["fields"])
    )
    spki = next(fl for fl in ecc["fields"] if fl["field"] == "spki_sha256")
    assert spki["value"] == "9018f0999a68c4d5a5df4c94f5a77b607f7418b6ea396018e17c828b0667893f"
    assert spki["epistemic_state"] == "KNOWN"


def test_kms_replay_requires_list_keys_input():
    assert main(["scan", *COMMON, "--adapter", "kms-aws"]) == 2


def test_tls_replay_via_cli(tmp_path, capsys):
    document = _run(
        [
            "--adapter", "tls-endpoint",
            "--host", "172.18.0.3",
            "--port", "8443",
            "--sni", "pay-edge",
            "--vantage", "cli-test",
            "--consent",
            "--sslyze-input", str(SSLYZE_INPUT),
            "--negotiated-input", str(NEGOTIATED_INPUT),
            "--classical-only-input", str(CLASSICAL_ONLY_INPUT),
        ],
        tmp_path / "out.json",
        capsys,
    )
    assert document["adapter_id"] == "tls-endpoint"
    assert document["outcome"] == "completed"
    (finding,) = document["findings"]
    group = next(f for f in finding["fields"] if f["field"] == "negotiated_group")
    assert group["value"] == "X25519MLKEM768"


def test_tls_without_vantage_is_a_usage_error():
    assert main(
        [
            "scan", *COMMON, "--adapter", "tls-endpoint",
            "--host", "h", "--sslyze-input", str(SSLYZE_INPUT),
        ]
    ) == 2


# --- tls-endpoint --live (DEV-004 + DEV-013 openssl-only path) -----------------
#
# No real subprocess or network is touched: `subprocess.run` inside
# adapters/tls/adapter.py is monkeypatched to a fake that dispatches on argv
# and returns the exact bytes of a real recorded openssl invocation from
# tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/ (see that
# directory's README.md for the real commands these were captured from) --
# so the CLI wiring, the runner's argv construction, and the parser are all
# exercised together, the way a real `--live` invocation would use them,
# without ever shelling out for real (CLAUDE.md: "no network in tests").

_GROUP_PROBE_DIR = (
    FIXTURES / "openssl" / "3.5.4" / "hybrid_groups_probe"
)
_OPENSSL_VERSION_35 = (_GROUP_PROBE_DIR / "openssl_version.txt").read_text(encoding="utf-8")
_OPENSSL_VERSION_TOO_OLD = "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\n"


def _hybrid_recording(name: str) -> str:
    return (_GROUP_PROBE_DIR / "hybrid_server" / f"probe_{name}.txt").read_text(encoding="utf-8")


def _refused_recording() -> str:
    # Any recorded refusal works as a stand-in for a group this fixture set
    # never individually recorded (the pre-standardisation draft group) --
    # the CLI-wiring tests below don't assert on that one field's value.
    return (_GROUP_PROBE_DIR / "hybrid_server" / "probe_secp256r1.txt").read_text(encoding="utf-8")


def _install_fake_openssl(monkeypatch, *, version_text: str | None, missing: bool = False):
    """Monkeypatch `subprocess.run` inside the TLS adapter module so every
    `openssl` invocation the live runner makes is answered from a real
    recording instead of a live process. `version_text=None` or
    `missing=True` simulates a binary that cannot be started at all."""
    import subprocess as _subprocess

    from ecdat.adapters.tls import adapter as tls_adapter_module

    class _FakeCompleted:
        def __init__(self, stdout: str, returncode: int = 0) -> None:
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    def fake_run(argv, **kwargs):
        if missing:
            raise FileNotFoundError(f"no such file: {argv[0]}")
        if "version" in argv:
            if version_text is None:
                raise FileNotFoundError(f"no such file: {argv[0]}")
            return _FakeCompleted(version_text)
        if "-groups" not in argv:
            return _FakeCompleted(_hybrid_recording("full_offer"))
        group_arg = argv[argv.index("-groups") + 1]
        if ":" in group_arg:
            # classical-only control probe (DEV-004): several groups offered
            # at once -- the hybrid server still accepts plain X25519.
            return _FakeCompleted(_hybrid_recording("X25519"))
        try:
            return _FakeCompleted(_hybrid_recording(group_arg))
        except OSError:
            return _FakeCompleted(_refused_recording())

    monkeypatch.setattr(tls_adapter_module.subprocess, "run", fake_run)
    assert tls_adapter_module.subprocess is _subprocess  # sanity: same module object


_LIVE_TLS_ARGV = [
    "--adapter", "tls-endpoint",
    "--host", "127.0.0.1",
    "--port", "14443",
    "--vantage", "test:fake-openssl",
    "--consent",
    "--live",
]


def test_tls_live_scan_wiring_produces_hybrid_findings(monkeypatch, tmp_path, capsys):
    _install_fake_openssl(monkeypatch, version_text=_OPENSSL_VERSION_35)
    document = _run(_LIVE_TLS_ARGV, tmp_path / "out.json", capsys)

    assert document["adapter_id"] == "tls-endpoint"
    assert document["outcome"] == "completed"
    (finding,) = document["findings"]
    by_field = {f["field"]: f for f in finding["fields"]}

    assert by_field["negotiated_group"]["value"] == "X25519MLKEM768"
    assert by_field["negotiated_group"]["epistemic_state"] == "KNOWN"
    assert by_field["classical_still_accepted"]["value"] is True
    assert by_field["hybrid_kex_supported"]["value"] is True
    assert by_field["hybrid_kex_supported"]["epistemic_state"] == "KNOWN"
    assert "X25519MLKEM768" in by_field["hybrid_kex_accepted_groups"]["value"]
    assert by_field["group_accepted_X25519MLKEM768"]["value"] is True

    # sslyze was never invoked by the live path -- its fields stay absent,
    # never guessed, and the gap is stated in words.
    assert "der_sha256" not in by_field
    assert "supported_curves" not in by_field
    assert any("sslyze: not run" in s for s in document["coverage"]["skipped"])


def test_tls_live_reports_unknown_when_openssl_is_too_old(monkeypatch, tmp_path, capsys):
    """Below MIN_OPENSSL_VERSION the live runner refuses to probe anything at
    all (the all-or-nothing gate `live_tls_probe_runner` documents) -- no
    finding is produced, coverage.skipped says why, and the visibility entry
    names the version it actually found. Never a guessed/assumed capability."""
    _install_fake_openssl(monkeypatch, version_text=_OPENSSL_VERSION_TOO_OLD)
    document = _run(_LIVE_TLS_ARGV, tmp_path / "out.json", capsys)

    assert document["outcome"] == "completed"
    assert document["findings"] == []
    assert any(
        "requires openssl >=" in s for s in document["coverage"]["skipped"]
    )
    detail = document["visibility"][0]["detail"]
    assert "3.0.13" in detail
    assert "requires openssl >=" in detail


def test_tls_live_reports_unknown_when_openssl_is_missing(monkeypatch, tmp_path, capsys):
    _install_fake_openssl(monkeypatch, version_text=None, missing=True)
    document = _run(_LIVE_TLS_ARGV, tmp_path / "out.json", capsys)

    assert document["outcome"] == "completed"
    assert document["findings"] == []
    detail = document["visibility"][0]["detail"]
    assert "could not be started" in detail
    assert "ECDAT_OPENSSL_BIN" in detail


def test_tls_live_honours_explicit_openssl_bin(monkeypatch, tmp_path, capsys):
    """--openssl-bin threads through to the argv the live runner shells out
    with, exactly like the other --live adapters' own configurable-path
    flags (e.g. --rules-path, --pkcs11-module)."""
    seen_argv: list[list[str]] = []
    _install_fake_openssl(monkeypatch, version_text=_OPENSSL_VERSION_35)

    from ecdat.adapters.tls import adapter as tls_adapter_module

    real_fake_run = tls_adapter_module.subprocess.run

    def recording_run(argv, **kwargs):
        seen_argv.append(argv)
        return real_fake_run(argv, **kwargs)

    monkeypatch.setattr(tls_adapter_module.subprocess, "run", recording_run)

    document = _run(
        [*_LIVE_TLS_ARGV, "--openssl-bin", "/opt/openssl-3.5/bin/openssl"],
        tmp_path / "out.json",
        capsys,
    )
    assert document["outcome"] == "completed"
    assert seen_argv, "the fake subprocess was never invoked"
    assert all(argv[0] == "/opt/openssl-3.5/bin/openssl" for argv in seen_argv)


# --- live-mode argument requirements (no real subprocess touched) --------------


def test_packages_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "packages-trivy", "--live"]) == 2


def test_hsm_live_requires_pkcs11_module(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "hsm-pkcs11", "--live"]) == 2


def test_binary_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "binary-yara-readelf", "--live"]) == 2


def test_images_live_requires_input(tmp_path):
    assert main(["scan", *COMMON, "--adapter", "images-cbomkit-theia", "--live"]) == 2


def test_unknown_adapter_is_rejected():
    with pytest.raises(SystemExit):
        main(["scan", *COMMON, "--adapter", "not-a-real-adapter"])
