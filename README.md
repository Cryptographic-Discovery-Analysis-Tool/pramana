# Pramāṇa

Cryptographic discovery and post-quantum migration decision support.

Built for Smart India Hackathon problem statement **SIH26164**.

---

## Quick start

```bash
pip install -e ".[dev,api]"
ecdat quickscan /path/to/a/folder --sector bfsi
```

`quickscan` is the fastest way to see Pramāṇa do something: point it at a folder and it
auto-discovers which adapters apply (certificates/keystores, Kubernetes `kind: Secret`
manifests, Spring config, package manifests/jars if `trivy` is on `PATH`, source files if
`semgrep` is on `PATH`), runs them, correlates the findings into one asset view, generates
purpose-based recommendations, and (once you add `--rollout-y-days N`, since no cited default
exists for that number) also produces exposure bands, a sector traffic-light view and a
CycloneDX CBOM export -- all in one command, in seconds on a small folder. An adapter whose
tool is not installed is skipped with a one-line reason, never faked. Add `--json` for
machine-readable output, `--out DIR` to choose where artifacts land (default
`./pramana-out/<timestamp>`), and `--live-tls host:port ...` to also probe live TLS endpoints.
Bands/sector view stay honestly `UNBOUNDED`/`no_deadline` until you also declare a data-class
lifetime with `--context example` (or your own file -- see
`examples/quickscan-context.example.yaml`); `--capture SINCE_POSSIBLE`/`--accept-inferred` may
be needed too for a capability-only finding (a bare certificate, never an observed handshake) to
band at all -- quickscan prints which and why when it can't.

See `ecdat quickscan --help`, and `## Command line` below for every other subcommand
(`scan`, `correlate`, `ledger-run`, `sector-report`, `cbom-import`, ...) `quickscan` builds on.

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

## Supplier/vendor CBOM intake

India's DST "Roadmap to Quantum Resiliency" makes vendor CBOM submission
mandatory from FY2027-28 (`docs/sources/India_DST_Quantum_Safe_Roadmap_2026.md`),
and RBI's Q-SAFE committee evaluates banks via CBOMs
(`docs/sources/IN_RBI_QSAFE_Committee_2026.md`). Pramāṇa can ingest a
supplier's CycloneDX CBOM as evidence about a *third party's* inventory:

1. **Validate.** The bundled CycloneDX 1.6 schema (`export/cyclonedx.py`).
   1.7 is honestly reported as unsupported rather than validated against the
   wrong schema (no 1.7 schema is vendored); malformed JSON is rejected with
   a clear error.
2. **Verify.** If the CBOM carries a JSF `signature`, it is checked with the
   existing `export/signing.py` module: `VERIFIED`, `UNVERIFIED` (no
   signature present), or `INVALID`. An invalid or missing signature is
   never treated as verified.
3. **Record provenance.** Supplier name, the file's own SHA-256, import
   time, signature status, and the CBOM's `serialNumber`/`version`.
4. **Epistemics.** Every declared component is `DECLARED`, never `KNOWN` --
   a supplier's claim about their own product is not something we observed
   ourselves (R-MONOTONE).
5. **Correlate.** Declared components are joined to our own scan inventory
   *only* by content-identity hash (`der_sha256` / `spki_sha256` -- the same
   two fields `correlation/engine.py` already treats as the sole legitimate
   cross-surface identity signal). A hash match with agreeing algorithm
   fields is `CORROBORATED`; a hash match with disagreeing fields (e.g. the
   supplier declares ML-KEM, we observed only X25519) is `CONFLICTING`, with
   both evidences kept. No hash match on either side is `DECLARED_ONLY` /
   `OBSERVED_ONLY` -- an honest coverage gap, never silently dropped.
6. **Report.** Per-supplier counts, which declared components are cited
   quantum-vulnerable (`data/crypto_families.yaml`), and, for an optional
   sector, which of that sector's cited obligations
   (`data/sector_profiles.yaml`) apply.

CLI:

```bash
python -m ecdat.cli cbom-import \
  --supplier "Acme Vendor" --file vendor.cdx.json \
  --plan tests/fixtures/correlation/demo_plan.json --sector bfsi --json
```

(`--plan` is optional; omit it to see the supplier's declared components on
their own, with everything `DECLARED_ONLY`.)

API: `POST /api/suppliers/import` (EXPORTER role) with a JSON body
`{"supplier": "...", "cbom_json": "<the CBOM file's exact text>", "sector": "bfsi"}`
returns the same provenance/coverage document.

Dashboard: the "Suppliers" tab uploads a CBOM file, shows its provenance and
signature status, and lists every correlation outcome (corroborated,
conflicting, declared-only, observed-only) with the declared vs. observed
value behind each one.

## Why "Pramāṇa"

Sanskrit: *the means by which one arrives at valid knowledge.*

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
