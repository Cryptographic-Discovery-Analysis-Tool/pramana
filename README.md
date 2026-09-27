# Pramāṇa

Cryptographic discovery and post-quantum migration decision support.

Built for Smart India Hackathon problem statement **SIH26164**.

---

## Requirements

- Python 3.12+
- Node 20+ (dashboard only)
- Docker (optional, for live scanning of the test environment)

## Install and test

```bash
pip install -e ".[dev,api]"
```

```bash
python -m pytest -q
```

## Dashboard

```bash
cd ui/dashboard && npm install && npm run build && cd ../..
```

```bash
python tools/dev/run_dashboard.py
```

Then open <http://127.0.0.1:8000>. The API requires a bearer token; the dev
launcher configures a local-only one. Set `ECDAT_API_TOKENS` for any other
deployment.

## Command line

```bash
python -m ecdat.cli --help
```

## India sector-specific compliance views

Pramāṇa can show a run's inventory against the deadlines and obligations a
cited source says apply to a particular Indian sector: **BFSI**, **Telecom**,
**Critical Information Infrastructure (CII)**, or **Government / general
enterprise**. Each asset gets a traffic light (`on_track` / `at_risk` /
`overdue` / `no_deadline`) against the nearest open deadline for that sector,
plus any undated obligations (e.g. SEBI CSCRF's crypto-agility requirement,
the RBI Q-SAFE committee's CBOM review) shown separately as "obligation, no
deadline" -- exactly like `risk/policy.py`'s existing P22 overlay, this never
changes a row's exposure band; it only lays a regulator's calendar on top of
what the ledger already decided. The sector-to-policy mapping is itself a
cited claim, in `data/sector_profiles.yaml`, checked by
`tools/ci/check_data_citations.py` the same as every other `data/` registry.

CLI:

```bash
python -m ecdat.cli sector-report \
  --subjects tests/fixtures/ledger/subjects.json \
  --sector bfsi --scenario Z_central --rollout-y-days 365 --as-of 2026-09-18
```

API: `GET /api/sectors` lists the four sectors and what each cites;
`GET /api/sector-report?sector=bfsi&scenario=Z_central&rollout_y_days=365`
(same required query parameters as `/api/ledger`, plus `sector` and the
optional `include_global`/`at_risk_days`) returns the per-asset traffic light.

Dashboard: the "Sector view" tab has a sector picker and an "also show
global (non-India) deadlines" toggle.

## Why "Pramāṇa"

Sanskrit: *the means by which one arrives at valid knowledge.*

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
