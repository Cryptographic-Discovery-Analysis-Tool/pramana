"""India sector-specific compliance views (SIH26164).

Built on the same frozen §6 helpers as test_policy.py, so every record here
is a real ledger evaluation; the sector lens only re-groups what
`risk/policy.py` already decided.
"""
from datetime import date

import pytest

from ecdat.model.usage_context import CryptoFunction
from ecdat.risk import confidentiality_ledger
from ecdat.risk.policy import PolicyStatus
from ecdat.risk.sector import (
    SectorTrafficLight,
    UnknownSectorError,
    available_sectors,
    load_sector_profiles,
    sector_profile,
    sector_report,
)

from .test_exposure_ledger import AS_OF, context, inputs, stop_at, temporal, x


def _record(algorithm, asset="PAY-001", migrations=(), as_of=None):
    kw = dict(
        usage_context=context(CryptoFunction.KEY_ESTABLISHMENT, algorithm, asset=asset),
        temporal=temporal(confirmed=date(2021, 1, 1)),
        binding=x("TEST.X_25Y"),
        migrations=migrations,
    )
    if as_of is not None:
        kw["as_of"] = as_of
    return confidentiality_ledger.evaluate(inputs(**kw))


def test_four_sectors_load_and_are_all_usable():
    assert set(available_sectors()) == {"bfsi", "telecom", "cii", "government_enterprise"}


def test_unknown_sector_raises():
    with pytest.raises(UnknownSectorError):
        sector_profile("healthcare")


def test_every_sector_mapping_names_its_source():
    for profile in load_sector_profiles():
        assert profile.citation
        assert profile.quote
        for policy_ref in profile.policies:
            assert policy_ref.citation
            assert policy_ref.quote


def test_bfsi_and_telecom_and_cii_use_the_accelerated_india_dst_cii_dates():
    for sector_key in ("bfsi", "telecom", "cii"):
        record = _record("X25519", asset="A-1")
        (status,) = sector_report([record], sector_key=sector_key)
        cii_annotations = [a for a in status.annotations if a.policy_key == "IN_DST_CII"]
        assert cii_annotations, sector_key


def test_government_enterprise_uses_the_baseline_enterprise_dates_not_cii():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="government_enterprise")
    keys = {a.policy_key for a in status.annotations}
    assert keys == {"IN_DST_ENTERPRISE"}


def test_bfsi_carries_undated_obligations_sebi_and_rbi():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="bfsi")
    obligation_keys = {o.policy_key for o in status.obligations}
    assert obligation_keys == {"IN_SEBI_CSCRF", "IN_RBI_CYBERSEC_MD", "IN_RBI_QSAFE"}
    # Obligations never appear as dated annotations -- they have no milestone.
    assert not [a for a in status.annotations if a.policy_key in obligation_keys]


def test_telecom_carries_undated_tec_obligation():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="telecom")
    assert {o.policy_key for o in status.obligations} == {"IN_TEC_PQC"}


def test_traffic_light_overdue_when_nearest_open_deadline_has_passed():
    """as_of injected well past IN_DST_CII's 2029-12-31 full_migration date
    (never reading date.today())."""
    record = _record("X25519", asset="A-1", as_of=date(2031, 1, 1))
    (status,) = sector_report([record], sector_key="cii")
    assert status.status == SectorTrafficLight.OVERDUE
    assert "passed" in status.reason


def test_traffic_light_at_risk_with_a_wide_at_risk_window():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="cii", at_risk_days=100000)
    # With an enormous at_risk window every open deadline counts as at_risk.
    assert status.status == SectorTrafficLight.AT_RISK


def test_traffic_light_on_track_with_a_realistic_at_risk_window():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="cii")
    assert status.status == SectorTrafficLight.ON_TRACK


def test_traffic_light_on_track_when_migration_met_every_deadline():
    record = _record("X25519", asset="A-1", migrations=(stop_at(date(2026, 6, 1)),))
    (status,) = sector_report([record], sector_key="cii")
    assert status.status == SectorTrafficLight.ON_TRACK
    assert any(a.status == PolicyStatus.MET for a in status.annotations)


def test_traffic_light_no_deadline_for_a_post_quantum_family():
    record = _record("ML-KEM", asset="A-1")
    (status,) = sector_report([record], sector_key="cii")
    assert status.status == SectorTrafficLight.NO_DEADLINE
    assert all(a.status == PolicyStatus.NOT_APPLICABLE for a in status.annotations)


def test_asset_with_multiple_records_takes_the_worst_status():
    on_track = _record("X25519", asset="A-1")
    no_deadline = _record("ML-KEM", asset="A-1")
    (status,) = sector_report([on_track, no_deadline], sector_key="cii")
    assert status.status == SectorTrafficLight.ON_TRACK
    assert set(status.record_ids) == {on_track.record_id, no_deadline.record_id}


def test_multiple_assets_produce_one_row_each_sorted_by_asset_id():
    r_b = _record("X25519", asset="B-1")
    r_a = _record("X25519", asset="A-1")
    statuses = sector_report([r_b, r_a], sector_key="cii")
    assert [s.asset_id for s in statuses] == ["A-1", "B-1"]


def test_global_policies_are_opt_in():
    record = _record("X25519", asset="A-1")
    without_global = sector_report([record], sector_key="cii", include_global=False)[0]
    with_global = sector_report([record], sector_key="cii", include_global=True)[0]
    without_keys = {a.policy_key for a in without_global.annotations}
    with_keys = {a.policy_key for a in with_global.annotations}
    assert "NIST_IR_8547_IPD" not in without_keys
    assert "NIST_IR_8547_IPD" in with_keys


def test_as_of_comes_from_the_record_never_the_clock():
    record = _record("X25519", asset="A-1")
    (status,) = sector_report([record], sector_key="cii")
    assert status.as_of == AS_OF == record.as_of
