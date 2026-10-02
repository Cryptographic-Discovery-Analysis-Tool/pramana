# Report on Quantum-Safe Ecosystem in India — Roadmap to Quantum Resiliency

- **Publisher:** Government of India, Department of Science & Technology, National Quantum Mission
- **Date:** May 2026 (final report)
- **URL:** https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf
- **Retrieved:** 2026-09-23, 140 pages, SHA-256 `b9d2d53b2c03cfc47f9f4ce5ae0ceaebe1f46f50fccca8fc1cdbc70defd4d9ff`

Vendored as excerpts. Quotes extracted from the retrieved PDF text (pypdf);
the PDF's letter-spaced body text is shown here de-spaced, headings verbatim.

## Migration milestones (printed pp. 105–107)

- "Milestone 1: Building the Foundations - (CII: No later than 31 December 2027, Enterprises: No later than 31 December 2028)"
- "Milestone 2: Migration of High-Priority Systems – (CII: 31 December 2028, Enterprises: No later than 31 December 2030)"
- "Milestone 3: Full Migration – (CII : 31 December 2029, Enterprises: No later than 31 December 2033)"

## CBOM in procurement (printed p. 106, Milestone 1 activities)

De-spaced from the PDF text, exact words:

- "...from FY2026–2027, start requesting CBOMs and Quantum Resiliency Roadmap from
  vendors in the procurement policy and/or service agreements."
- "Starting FY2027–2028 mandate submission of CBOM from the vendors, through the
  procurement policy."

A CBOM becomes a mandated procurement artefact from FY2027–28 — the document
`export/cyclonedx.py` produces.

## PQC testing-lab infrastructure (printed p. 36, §9.0 Recommendations of the Task Force)

De-spaced from the PDF text, exact words:

- "Establish a National PQC Testing & Certification Program under
  TEC/STQC/BIS, operationalising Tier-1 and Tier-2 labs (As designated in
  Section 6.0) by December 2026."

Section 6.0 (printed p. 58) describes the tier model: Tier-1 labs do
"Level-1 testing" (functional correctness, standards conformance,
interoperability -- already-designated TEC/BIS labs may be upgraded for
this role); Tier-2 labs add Level-2 capability or liaise with Tier-1 for it;
Tier-3 is a later, sovereign-grade tier for CII protection (printed p. 38,
"Upgrade select labs to Tier-3 sovereign-grade ... by 2033 | CII by 2029").
Only the Tier-1/Tier-2 December-2026 date is vendored as a policy milestone
here; Tier-3 has no single stated date of its own (it inherits the
Long-Term-Actions heading's "By 2033 | CII by 2029" range, already covered
by the Milestone-3 full-migration dates above).

## Which sectors count as CII for the accelerated timeline (printed p. 36, §9.0)

De-spaced from the PDF text, exact words (re-fetched 2026-09-27, same SHA-256 as above,
confirming the same 140-page file):

> "CII sectors – government, strategic, defence, power, telecom, transport, and Banking,
> Financial Services and Insurance (BFSI) – will follow accelerated timelines:
> Foundations by 2027, High-Priority Migration by 2028, and Full PQC Adoption by 2029.
> Other enterprises will follow the baseline timelines of 2028, 2030, and 2033
> respectively."

This is the source `data/sector_profiles.yaml` cites for putting the `bfsi` and
`telecom` sector lenses on the `IN_DST_CII` accelerated dates (they are named here),
and for putting the `government_enterprise` (non-CII) lens on `IN_DST_ENTERPRISE`'s
baseline dates. Central/state government bodies that are themselves part of the named
"government" CII sub-sector belong under the `cii` sector lens, not
`government_enterprise` -- see the note in `data/sector_profiles.yaml`.

## Vendor CBOM mandatory FY2027-28 -- undated in data/policy_deadlines.yaml

Per "CBOM in procurement" above, FY2027-28 is a fiscal year, not a calendar date; no day
is stated. `risk/policy.py`'s `Milestone.date` is a calendar `date`, so no milestone
entry is added for it here (it would require guessing a day, which CLAUDE.md forbids).
It remains a documented gap, carried honestly rather than approximated.
