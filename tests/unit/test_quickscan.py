"""`ecdat quickscan` (DEV-018): discovery, skip-when-tool-missing, an
end-to-end pass over a tiny synthetic folder, and the `--json` shape.

No real semgrep/trivy binary and no network: `discover()` is pure filesystem
inspection, and every synthetic-folder test below has neither a package
manifest nor a source file in it, so `_plan_entries` never reaches the
tool-availability check for those two adapters at all -- the dedicated
`test_tool_unavailable_is_skipped_with_reason` below drives that path
directly by monkeypatching `shutil.which` instead of depending on whatever
happens to be on the machine running the suite.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from ecdat import quickscan as qs
from ecdat.cli import main


def _write_cert(path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quickscan-test")])
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
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _write_rsa_cert(path, *, cn="rsa-test", with_key_usage=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    )
    if with_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    certificate = builder.sign(key, hashes.SHA256())
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _write_ec_cert(path, *, curve=ec.SECP256R1(), cn="ec-test", key_agreement=True):
    key = ec.generate_private_key(curve)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=not key_agreement,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=key_agreement,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _write_k8s_secret(path):
    path.write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: demo\ntype: Opaque\n"
        "data:\n  password: cGFzc3dvcmQ=\n",
        encoding="utf-8",
    )


def _write_spring_config(path):
    path.write_text(
        "server:\n  ssl:\n    protocol: TLSv1.2\n    enabled-protocols: TLSv1.2\n",
        encoding="utf-8",
    )


def _synthetic_folder(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_cert(tmp_path / "certs" / "leaf.pem")
    (tmp_path / "k8s").mkdir()
    _write_k8s_secret(tmp_path / "k8s" / "secret.yaml")
    (tmp_path / "config").mkdir()
    _write_spring_config(tmp_path / "config" / "application.yml")
    return tmp_path


# --- discovery -----------------------------------------------------------------


def test_discover_finds_each_signal_independently(tmp_path):
    _synthetic_folder(tmp_path)
    found = qs.discover(tmp_path)
    assert found == {
        "certs-x509": True,
        "k8s-secret": True,
        "config-chain-spring": True,
        "packages-trivy": False,
        "source-semgrep": False,
    }


def test_discover_empty_folder_finds_nothing(tmp_path):
    (tmp_path / "empty.txt").write_text("nothing crypto-shaped here", encoding="utf-8")
    assert qs.discover(tmp_path) == {
        "certs-x509": False,
        "k8s-secret": False,
        "config-chain-spring": False,
        "packages-trivy": False,
        "source-semgrep": False,
    }


def test_discover_yaml_without_kind_secret_is_not_a_secret(tmp_path):
    (tmp_path / "values.yaml").write_text("replicaCount: 3\n", encoding="utf-8")
    assert qs.discover(tmp_path)["k8s-secret"] is False


def test_discover_recognises_package_manifest_and_source_file(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    (tmp_path / "App.java").write_text("class App {}", encoding="utf-8")
    found = qs.discover(tmp_path)
    assert found["packages-trivy"] is True
    assert found["source-semgrep"] is True


def test_discover_skips_vcs_and_build_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    _write_cert(tmp_path / ".git" / "hidden.pem")
    assert qs.discover(tmp_path)["certs-x509"] is False


# --- skip-when-tool-missing ------------------------------------------------------


def test_tool_unavailable_is_skipped_with_reason(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("cryptography\n", encoding="utf-8")
    monkeypatch.setattr(qs.shutil, "which", lambda _name: None)

    found = qs.discover(tmp_path)
    entries, rows = qs._plan_entries(tmp_path, found, live_tls=())

    trivy_entries = [e for e in entries if e["adapter"] == "packages-trivy"]
    assert trivy_entries == []
    trivy_row = next(r for r in rows if r.adapter_id == "packages-trivy")
    assert trivy_row.run is False
    assert "trivy not found on PATH" in trivy_row.reason


def test_live_tls_without_openssl_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(qs.shutil, "which", lambda _name: None)
    found = qs.discover(tmp_path)
    entries, rows = qs._plan_entries(tmp_path, found, live_tls=("example.invalid:443",))
    assert [e for e in entries if e["adapter"] == "tls-endpoint"] == []
    tls_row = next(r for r in rows if r.adapter_id == "tls-endpoint")
    assert tls_row.run is False
    assert "openssl not found" in tls_row.reason


# --- confidence: never invented, never bypasses the >=20 char rule --------------


def test_default_justification_meets_the_twenty_char_rule():
    assert len(qs.QUICKSCAN_CONFIDENCE_JUSTIFICATION.strip()) >= 20


def test_plan_entries_never_omit_confidence_fields(tmp_path):
    found = qs.discover(_synthetic_folder(tmp_path))
    entries, _rows = qs._plan_entries(tmp_path, found, live_tls=())
    assert entries
    for entry in entries:
        assert entry["confidence"] == qs.QUICKSCAN_DEFAULT_CONFIDENCE
        assert entry["confidence_justification"] == qs.QUICKSCAN_CONFIDENCE_JUSTIFICATION


# --- end-to-end on a tiny synthetic folder ---------------------------------------


def test_end_to_end_on_synthetic_folder(tmp_path):
    _synthetic_folder(tmp_path)
    out_dir = tmp_path / "out"
    result = qs.run_quickscan(str(tmp_path), out_dir=str(out_dir))

    ran = {row.adapter_id for row in result.discovery if row.run}
    assert ran == {"certs-x509", "k8s-secret", "config-chain-spring"}
    assert {r.adapter_id for r in result.scan_results} == ran
    assert all(r.outcome.value == "completed" for r in result.scan_results)

    # Never faked, never replayed from a fixture: no adapter ran that this
    # folder gave no evidence for.
    skipped = {row.adapter_id: row.reason for row in result.discovery if not row.run}
    assert skipped["packages-trivy"] == "no package manifest/jar found"
    assert skipped["source-semgrep"] == "no source file found"

    # ledger/risk/sector/CBOM stage is opt-in (no cited rollout_Y default)
    assert result.ledger_skip_reason is not None
    assert result.cbom_signed is None
    assert (out_dir / "quickscan_plan.json").is_file()
    assert (out_dir / "correlate.json").is_file()
    assert (out_dir / "recommendations.json").is_file()
    assert not (out_dir / "cbom.json").is_file()

    text = result.summary_text()
    assert "certs-x509" in text
    assert "packages-trivy" in text


def test_end_to_end_with_rollout_y_enables_ledger_and_cbom(tmp_path):
    _synthetic_folder(tmp_path)
    out_dir = tmp_path / "out"
    result = qs.run_quickscan(str(tmp_path), out_dir=str(out_dir), rollout_y_days=3650)

    assert result.ledger_skip_reason is None
    assert result.cbom_signed is False  # no ECDAT_SIGNING_KEY_PATH configured in tests
    assert (out_dir / "ledger_records.json").is_file()
    assert (out_dir / "cbom.json").is_file()
    document = json.loads((out_dir / "cbom.json").read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert "signature" not in document


def test_end_to_end_no_matching_files_runs_nothing(tmp_path):
    (tmp_path / "readme.txt").write_text("nothing here", encoding="utf-8")
    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"))
    assert result.scan_results == ()
    assert result.correlation_document is None
    assert all(not row.run for row in result.discovery)


def test_run_quickscan_rejects_a_non_directory(tmp_path):
    missing = tmp_path / "does-not-exist"
    try:
        qs.run_quickscan(str(missing))
    except NotADirectoryError:
        pass
    else:
        raise AssertionError("expected NotADirectoryError")


# --- --json output shape ---------------------------------------------------------


def test_json_document_shape(tmp_path):
    _synthetic_folder(tmp_path)
    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"))
    document = result.to_json_document()
    for key in (
        "out_dir",
        "elapsed_seconds",
        "discovery",
        "adapters",
        "asset_count",
        "quantum_vulnerable_count",
        "top_risk",
        "recommendation_count",
        "ledger_skip_reason",
        "sector",
        "sector_skip_reason",
        "cbom_signed",
        "cbom_skip_reason",
        "written_files",
    ):
        assert key in document
    json.dumps(document)  # must be JSON-serialisable, no float("nan")/Path leaks
    assert len(document["discovery"]) == 5
    for row in document["discovery"]:
        assert set(row) == {"adapter", "ran", "reason"}


# --- CLI wiring --------------------------------------------------------------


def test_cli_quickscan_text(tmp_path, capsys):
    _synthetic_folder(tmp_path)
    exit_code = main(["quickscan", str(tmp_path), "--out", str(tmp_path / "out")])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "pramana quickscan" in out


def test_cli_quickscan_json(tmp_path, capsys):
    _synthetic_folder(tmp_path)
    exit_code = main(["quickscan", str(tmp_path), "--out", str(tmp_path / "out"), "--json"])
    assert exit_code == 0
    document = json.loads(capsys.readouterr().out)
    assert "written_files" in document


def test_cli_quickscan_rejects_missing_path(tmp_path, capsys):
    exit_code = main(["quickscan", str(tmp_path / "nope")])
    assert exit_code == 2
    assert "not a directory" in capsys.readouterr().err


# --- regression: quantum-vulnerable classification must canonicalize EC ---------
#
# Coordinator-reported bug: `quantum-vulnerable: 0` on a folder containing an
# RSA cert and an EC (P-256) cert/key. Root cause: `algorithm_family` for an
# EC asset is the literal string "EC" (adapters/certs/parser.py's
# `_public_key_description`), which has no row in
# data/crypto_families.yaml (that file classifies EC by curve, e.g. "P-256").
# `is_shor_broken("EC")` raised `NoCitedFamilyError`, and the old code
# silently treated that as "not vulnerable" instead of resolving the real
# curve through `canonical_family()` first.


def test_classify_family_rsa_is_vulnerable():
    canonical, vulnerable = qs._classify_family("RSA", None)
    assert canonical == "RSA"
    assert vulnerable is True


def test_classify_family_ec_p256_resolves_via_curve_alias_and_is_vulnerable():
    # cryptography's own curve.name for P-256 is "secp256r1"; canonical_family()
    # aliases it to "P-256", which data/crypto_families.yaml cites shor_broken.
    canonical, vulnerable = qs._classify_family("EC", "secp256r1")
    assert canonical == "P-256"
    assert vulnerable is True


def test_classify_family_ec_curve_with_no_alias_is_unclassified_not_zero():
    # secp384r1 (P-384) has no family_aliases row today -- honestly
    # unclassified, never silently "not vulnerable".
    canonical, vulnerable = qs._classify_family("EC", "secp384r1")
    assert vulnerable is None
    assert "secp384r1" in canonical


def test_quantum_vulnerable_count_end_to_end_rsa_and_ec(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_rsa_cert(tmp_path / "certs" / "rsa.pem", cn="rsa-leaf")
    _write_ec_cert(tmp_path / "certs" / "ec.pem", cn="ec-leaf", key_agreement=True)

    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"))
    counts = qs._family_counts(result)
    # Both RSA and EC/P-256 are cited Shor-broken rows -- the count must not
    # be 0 (the reported bug) and must not silently drop the EC one.
    assert counts["vulnerable"] >= 2
    assert counts["unclassified"] == 0

    document = result.to_json_document()
    assert document["quantum_vulnerable_count"] >= 2


def test_quantum_vulnerable_count_unclassified_curve_is_reported_separately(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_ec_cert(tmp_path / "certs" / "p384.pem", curve=ec.SECP384R1(), cn="p384-leaf")

    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"))
    counts = qs._family_counts(result)
    assert counts["unclassified"] >= 1
    assert counts["vulnerable"] == 0


# --- regression: human-readable asset labels, not raw internal ids -------------
#
# Coordinator-reported bug: the top-risk list showed ids like
# `certdir:..\ecdat-harness\targets|keyUsage|digitalSignature` -- an absolute,
# backslash-heavy internal id, not a name a demo audience can read.


def test_cert_label_index_is_relative_path_plus_cn_plus_algorithm(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_rsa_cert(tmp_path / "certs" / "leaf.pem", cn="my-service.internal")

    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"))
    labels = qs._cert_label_index(result.scan_results, tmp_path)
    assert labels, "expected at least one cert label"
    (label,) = labels.values()
    assert "CN=my-service.internal" in label
    assert "RSA" in label
    # relative, forward-slash, no drive letter or leading ".." absolute mix
    assert "certs/leaf.pem" in label.replace("\\", "/")
    assert str(tmp_path).replace("\\", "/") not in label.replace("\\", "/")


def test_top_risk_uses_label_not_raw_usage_context_id(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_ec_cert(tmp_path / "certs" / "leaf.pem", cn="edge.internal", key_agreement=False)

    result = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out"), rollout_y_days=730)
    rows = qs._asset_risk_rows(result)
    assert rows
    for row in rows:
        assert "certdir:" not in row["label"]
        assert "CN=edge.internal" in row["label"]


# --- --context: reuses the existing Declarations format, never invents a lifetime -----


def test_resolve_context_path_example_keyword():
    resolved = qs._resolve_context_path("example")
    assert resolved == qs._EXAMPLE_CONTEXT_PATH
    assert resolved.is_file()


def test_resolve_context_path_arbitrary_file(tmp_path):
    custom = tmp_path / "my-context.yaml"
    assert qs._resolve_context_path(str(custom)) == custom


def test_load_context_substitutes_target_without_corrupting_windows_paths(tmp_path):
    context_file = tmp_path / "ctx.yaml"
    context_file.write_text(
        "bindings:\n  - surface: \"certdir:{target}\"\n    data_class: TEST.A_15Y\n"
        "    declared_by: test\n",
        encoding="utf-8",
    )
    target = tmp_path / "some folder"
    target.mkdir()
    declarations = qs._load_context(context_file, target=target, live_tls=())
    assert declarations.bindings[0].surface == f"certdir:{target}"


def test_context_hint_present_only_when_ledger_ran_without_context(tmp_path):
    _synthetic_folder(tmp_path)

    no_ledger = qs.run_quickscan(str(tmp_path), out_dir=str(tmp_path / "out1"))
    assert no_ledger.context_hint is None  # ledger stage itself didn't run

    with_ledger_no_context = qs.run_quickscan(
        str(tmp_path), out_dir=str(tmp_path / "out2"), rollout_y_days=730
    )
    assert with_ledger_no_context.context_hint is not None
    assert "--context" in with_ledger_no_context.context_hint

    with_context = qs.run_quickscan(
        str(tmp_path), out_dir=str(tmp_path / "out3"), rollout_y_days=730, context="example"
    )
    assert with_context.context_hint is None


def test_context_example_binds_a_data_class_to_the_ledger_subject(tmp_path):
    (tmp_path / "certs").mkdir()
    _write_rsa_cert(tmp_path / "certs" / "leaf.pem", with_key_usage=True)

    result = qs.run_quickscan(
        str(tmp_path), out_dir=str(tmp_path / "out"), rollout_y_days=730, context="example"
    )
    subjects_doc = json.loads((result.out_dir / "ledger_subjects.json").read_text(encoding="utf-8"))
    bound = [s for s in subjects_doc["subjects"] if s.get("binding_key")]
    assert bound, "expected at least one subject bound to a declared data class"
    assert bound[0]["binding_key"] == "TEST.A_15Y"


def test_cli_quickscan_context_and_capture_and_accept_inferred_flags(tmp_path, capsys):
    (tmp_path / "certs").mkdir()
    _write_rsa_cert(tmp_path / "certs" / "leaf.pem")
    exit_code = main(
        [
            "quickscan",
            str(tmp_path),
            "--out",
            str(tmp_path / "out"),
            "--rollout-y-days",
            "730",
            "--context",
            "example",
            "--capture",
            "SINCE_POSSIBLE",
            "--accept-inferred",
            "--json",
        ]
    )
    assert exit_code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ledger_skip_reason"] is None
    assert document["context_hint"] is None
