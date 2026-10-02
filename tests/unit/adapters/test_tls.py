"""TLS endpoint adapter (P4; spec §3 row "TLS", §5.7).

Every fixture here was recorded from the live Tier A endpoint on 2026-09-19
(docs/build-box.md), not synthesised.
"""
import json
from datetime import date
from pathlib import Path

import pytest

from ecdat.adapters.base import AdapterContractError, AdapterOutcome, ScanTarget
from ecdat.adapters.tls.adapter import (
    NASSL_CEILING_NOTE,
    TlsEndpointAdapter,
    TlsProbeBundle,
    migration_evidence_from,
)
from ecdat.adapters.tls.parser import (
    NASSL_KEY_TYPES,
    parse_negotiated,
    parse_sslyze,
    sslyze_can_see_group,
)
from ecdat.model.epistemic import EpistemicState
from ecdat.model.evidence import ConfidenceBasis
from ecdat.model.topology import ProbeTargetIdentity

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
SSLYZE_JSON = FIXTURES / "sslyze" / "6.2.0" / "tier_a_edge_lb.raw.json"
NEGOTIATED = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.negotiated.txt"
CLASSICAL = FIXTURES / "openssl" / "3.5.8" / "tier_a_edge_lb.classical_only.txt"

BASIS = ConfidenceBasis(
    source="ADAPTER_DECLARED",
    justification=(
        "No cited row exists for TLS probe confidence (OI-004); an observed "
        "handshake is the strongest evidence class for a network surface."
    ),
)

PROBE = ProbeTargetIdentity(
    requested_host="172.18.0.3",
    port=8443,
    sni_sent="pay-edge",
    probe_vantage="docker:payments-internal",
)
TARGET = ScanTarget(
    target_id="tier-a-edge-lb", locator="172.18.0.3:8443", consent=True, probe=PROBE
)


def bundle(**kw):
    defaults = dict(
        sslyze_json=SSLYZE_JSON.read_text(encoding="utf-8"),
        negotiated_text=NEGOTIATED.read_text(encoding="utf-8"),
        classical_only_text=CLASSICAL.read_text(encoding="utf-8"),
    )
    defaults.update(kw)
    return TlsProbeBundle(**defaults)


def adapter(probes):
    return TlsEndpointAdapter(
        base_confidence=0.95,
        confidence_basis=BASIS,
        probe_runner=lambda target: probes,
    )


def run(**kw):
    return adapter(bundle(**kw)).run(TARGET)


# --- parsers, against recorded live output ----------------------------------


def test_negotiated_group_is_read_from_the_handshake():
    handshake = parse_negotiated(NEGOTIATED.read_text(encoding="utf-8"))
    assert handshake.established is True
    assert handshake.protocol == "TLSv1.3"
    assert handshake.group == "X25519MLKEM768"
    assert handshake.group_source == "Negotiated TLS1.3 group"
    assert handshake.is_hybrid_group is True


def test_a_classical_negotiation_is_read_from_the_other_line():
    """OpenSSL reports a classical agreement as `Peer Temp Key`, not as a
    negotiated group. Reading only one line would lose half the cases."""
    handshake = parse_negotiated(CLASSICAL.read_text(encoding="utf-8"))
    assert handshake.established is True
    assert handshake.group == "X25519"
    assert handshake.group_source == "Peer Temp Key"
    assert handshake.is_hybrid_group is False


def test_sslyze_reports_suites_curves_and_the_chain():
    observation = parse_sslyze(json.loads(SSLYZE_JSON.read_text(encoding="utf-8")))
    assert observation.completed
    assert observation.sslyze_version == "6.2.0"
    assert observation.accepted_cipher_suites["tls_1_2_cipher_suites"] == (
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    )
    assert "TLS_AES_256_GCM_SHA384" in observation.accepted_cipher_suites[
        "tls_1_3_cipher_suites"
    ]
    assert observation.leaf_subject == "CN=pay-edge,O=Harness Payments"
    assert len(observation.chain_subjects) == 2


def test_sslyze_leaf_hash_is_canonicalised_the_same_way_certs_x509_computes_it():
    """The value this test asserts was independently computed by loading the
    real on-disk pay-edge certificate (ecdat-harness/harness/build/out/
    pay-edge/cert.pem) through CertificateAdapter's own parser and reading
    off its der_sha256 -- same real object, two different surfaces, byte-for-
    byte the same hex hash. That equality is what makes cross-surface
    correlation (correlation/engine.py) honest for this field."""
    observation = parse_sslyze(json.loads(SSLYZE_JSON.read_text(encoding="utf-8")))
    # Values re-verified against the harness's now-deterministic PKI
    # (see "Deterministic PKI" in ecdat-harness/README.md) via
    # `openssl x509 ... -outform DER | sha256sum` (der_sha256) and
    # `openssl x509 ... -pubkey | openssl pkey -pubin -outform DER | sha256sum`
    # (spki_sha256) against the on-disk pay-edge leaf certificate.
    assert observation.leaf_der_sha256 == (
        "4824805cd0e41ccb711b0da60eb833ff047695c452b416013d8a0853c0cc7bb0"
    )
    assert observation.leaf_spki_sha256 == (
        "133afc2d59061ec4a826fbc664de07721bc086f5c05946dac254e70d3a935200"
    )


def test_sslyze_did_not_see_the_hybrid_group_it_was_negotiating():
    """The measured fact behind OI-017, asserted against both fixtures at
    once: OpenSSL negotiated X25519MLKEM768 with this endpoint, and sslyze
    scanning the same endpoint lists only classical curves."""
    observation = parse_sslyze(json.loads(SSLYZE_JSON.read_text(encoding="utf-8")))
    handshake = parse_negotiated(NEGOTIATED.read_text(encoding="utf-8"))

    assert handshake.group == "X25519MLKEM768"
    assert "X25519MLKEM768" not in observation.supported_curves
    assert observation.supported_curves == (
        "X25519",
        "X448",
        "secp256r1",
        "secp384r1",
        "secp521r1",
    )


def test_the_nassl_ceiling_is_a_recorded_fact():
    assert "MLKEM" not in " ".join(NASSL_KEY_TYPES).upper()
    assert sslyze_can_see_group("X25519") is True
    assert sslyze_can_see_group("X25519MLKEM768") is False


def test_empty_probe_output_raises_rather_than_reporting_a_clean_endpoint():
    from ecdat.adapters.tls.parser import TlsProbeParseError

    with pytest.raises(TlsProbeParseError):
        parse_negotiated("   ")


# --- the adapter -------------------------------------------------------------


def test_a_probe_target_is_required():
    """Lock §5 row 1: host, port, SNI and vantage are recorded per probe."""
    with pytest.raises(AdapterContractError, match="ProbeTargetIdentity"):
        adapter(bundle())._scan(ScanTarget(target_id="t", locator="host:443"))


def test_a_probe_without_consent_cannot_even_be_constructed():
    with pytest.raises(ValueError, match="consent"):
        ScanTarget(target_id="t", locator="h:443", probe=PROBE)


def test_the_finding_carries_sni_and_vantage():
    (finding,) = run().findings
    assert finding.fields["sni_sent"].value == "pay-edge"
    assert finding.fields["probe_vantage"].value == "docker:payments-internal"
    assert finding.surface == "tls:172.18.0.3:8443"


def test_the_finding_records_both_probes():
    (finding,) = run().findings
    assert finding.fields["negotiated_group"].value == "X25519MLKEM768"
    assert finding.fields["classical_still_accepted"].value is True


def test_the_finding_carries_a_der_sha256_field_named_like_certs_x509s():
    """Named identically to certs-x509's own der_sha256/spki_sha256 fields
    on purpose -- correlation/engine.py's cross-surface identity match looks
    for exactly this field name and picks this Finding up automatically,
    with no engine change needed for a second surface to participate."""
    (finding,) = run().findings
    # Values re-verified against the harness's now-deterministic PKI
    # (see "Deterministic PKI" in ecdat-harness/README.md) via
    # `openssl x509 ... -outform DER | sha256sum` (der_sha256) and
    # `openssl x509 ... -pubkey | openssl pkey -pubin -outform DER | sha256sum`
    # (spki_sha256) against the on-disk pay-edge leaf certificate.
    assert finding.fields["der_sha256"].value == (
        "4824805cd0e41ccb711b0da60eb833ff047695c452b416013d8a0853c0cc7bb0"
    )
    assert finding.fields["der_sha256"].state == EpistemicState.KNOWN
    assert finding.fields["spki_sha256"].value == (
        "133afc2d59061ec4a826fbc664de07721bc086f5c05946dac254e70d3a935200"
    )


def test_no_sslyze_probe_leaves_der_sha256_absent_not_fabricated():
    result = run(sslyze_json=None)
    (finding,) = result.findings
    assert "der_sha256" not in finding.fields


def test_the_visibility_entry_states_what_sslyze_could_not_see():
    """R-UNSEEN, in the matrix: a curve list from sslyze is evidence about the
    curves it knows and nothing else."""
    result = run()
    detail = result.visibility[0].detail
    assert NASSL_CEILING_NOTE in detail
    assert "OI-017" in detail
    assert "docker:payments-internal" in detail


def test_without_the_openssl_probe_the_group_is_unknown_not_absent():
    result = run(negotiated_text=None)
    (finding,) = result.findings
    assert finding.fields["negotiated_group"].state == EpistemicState.UNKNOWN
    assert any("negotiated group is unobserved" in s for s in result.coverage.skipped)


def test_the_result_passes_the_secret_guard():
    from ecdat.security.secrets import find_secrets

    assert find_secrets(run().model_dump_json()) == ()


def test_outcome_is_completed_and_evidence_is_referenced():
    result = run()
    assert result.outcome == AdapterOutcome.COMPLETED
    assert len(result.evidence) == 3
    assert {e.source_tool for e in result.evidence} == {"sslyze", "openssl s_client"}


# --- the bridge to the ledger (§5.7) -----------------------------------------


def test_hybrid_negotiated_but_classical_still_accepted_does_not_stop_the_clock():
    """The case that matters. A tool that stopped the clock here would mark a
    bleeding surface as migrated."""
    evidence = migration_evidence_from(run(), observed_on=date(2026, 9, 19))
    assert evidence.negotiated_group == "X25519MLKEM768"
    assert evidence.classical_still_accepted is True
    assert evidence.status == EpistemicState.KNOWN
    assert evidence.stops_the_clock is False


def test_a_refused_classical_probe_does_stop_the_clock():
    refused = "Connecting to 172.18.0.3\nerrno=104\n"
    evidence = migration_evidence_from(
        run(classical_only_text=refused), observed_on=date(2026, 9, 19)
    )
    assert evidence.classical_still_accepted is False
    assert evidence.stops_the_clock is True


def test_an_untested_classical_path_is_inferred_and_stops_nothing():
    """Never observed is not the same as observed-refused. Assuming classical
    still works keeps the clock running, which is the safe direction."""
    evidence = migration_evidence_from(
        run(classical_only_text=None), observed_on=date(2026, 9, 19)
    )
    assert evidence.status == EpistemicState.INFERRED
    assert evidence.classical_still_accepted is True
    assert evidence.stops_the_clock is False


def test_no_negotiated_group_produces_no_migration_evidence_at_all():
    """A default here would invent a migration observation nobody made."""
    assert migration_evidence_from(run(negotiated_text=None), observed_on=date(2026, 9, 19)) is None


def test_migration_evidence_carries_its_vantage_and_evidence_refs():
    evidence = migration_evidence_from(run(), observed_on=date(2026, 9, 19))
    assert evidence.vantage == "docker:payments-internal"
    assert evidence.evidence_refs
