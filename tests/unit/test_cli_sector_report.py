"""`ecdat sector-report` (SIH26164).

Drives `main()` with real argv against the same fixture ledger-run and the
dashboard use (tests/fixtures/ledger/subjects.json).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.cli import main

SUBJECTS = str(
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "ledger" / "subjects.json"
)


def _run(extra: list[str]) -> int:
    return main(
        [
            "sector-report",
            "--subjects",
            SUBJECTS,
            "--scenario",
            "Z_central",
            "--rollout-y-days",
            "365",
            "--as-of",
            "2026-09-18",
            *extra,
        ]
    )


def test_sector_report_bfsi_json(capsys):
    code = _run(["--sector", "bfsi", "--json"])
    assert code == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows
    for row in rows:
        assert row["sector"] == "bfsi"
        assert row["status"] in {"on_track", "at_risk", "overdue", "no_deadline"}
        obligation_keys = {o["policy"] for o in row["obligations"]}
        assert obligation_keys == {"IN_SEBI_CSCRF", "IN_RBI_CYBERSEC_MD", "IN_RBI_QSAFE"}


def test_sector_report_text_output_lists_obligations(capsys):
    code = _run(["--sector", "telecom"])
    assert code == 0
    out = capsys.readouterr().out
    assert "sector=telecom" in out
    assert "obligation, no deadline: IN_TEC_PQC" in out


def test_sector_report_unknown_sector_rejected_by_argparse():
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "sector-report",
                "--subjects",
                SUBJECTS,
                "--sector",
                "healthcare",
                "--scenario",
                "Z_central",
                "--rollout-y-days",
                "365",
            ]
        )
    assert excinfo.value.code == 2


def test_sector_report_include_global_adds_non_india_rows(capsys):
    code = _run(["--sector", "cii", "--include-global", "--json"])
    assert code == 0
    rows = json.loads(capsys.readouterr().out)
    policy_keys = {a["policy"] for row in rows for a in row["annotations"]}
    assert "NIST_IR_8547_IPD" in policy_keys
