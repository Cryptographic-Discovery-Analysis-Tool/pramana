# RBI (Commercial Banks – Cybersecurity, Technology: Risk, Resilience and Assurance Framework) Directions, 2026

- **Publisher:** Reserve Bank of India (RBI), Department of Supervision
- **Reference:** RBI/DoS/2026-27/410
- **Date:** July 31, 2026 (effective on issuance; no glide path in the commencement clause)
- **Scope:** Banking companies other than small finance banks, payments banks and local
  area banks, plus corresponding new banks and the State Bank of India.
- **URL:** https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=13643
- **Retrieved:** 2026-09-27, via WebFetch (page is a JS-rendered ASPX view; content was
  fetched and summarized by the fetch tool rather than downloaded as a standalone PDF, so
  no file SHA-256 is recorded here -- unlike the vendored PDFs elsewhere in this
  directory. This is noted as a limitation, not concealed.)
- **Secondary corroboration:** KPMG summary
  https://kpmg.com/in/en/insights/2026/09/rbis-technology-focused-master-directions-issued-on-31-july-2026.html
  (retrieved 2026-09-27) confirms the title, reference, and 31 July 2026 issue date, and
  states the Directions replace the RBI Cyber Security Framework (June 2016) and the 2023
  IT Governance, Risk, Compliance and Assurance Master Direction.

## What it says about cryptography (paragraph 140)

The only paragraph addressing cryptographic controls, as returned by the fetch:

> "The key length, algorithms, cipher suites and applicable protocols used in
> transmission channels, processing of data and authentication purpose shall be strong."

The Direction also requires (per the same paragraph) adoption of "internationally
accepted and published standards that are not deprecated / demonstrated to be insecure /
vulnerable."

## Why no dated PQC milestone was added to data/policy_deadlines.yaml

Paragraph 140 states a standing, undated obligation ("shall be strong", "not deprecated")
applicable from the Direction's effective date (2026-07-31), not a future PQC-specific
compliance date. No mention of quantum computing, post-quantum cryptography, PQC, or a
cryptographic-inventory/migration deadline was found anywhere in the fetched content.
Per the same honest-absence convention as `IN_SEBI_CSCRF_2024.md`, this is recorded in
`data/policy_deadlines.yaml` as `usable: false` with `why_not_usable` pointing here,
rather than inventing a milestone date the source does not state. It is still recorded
in `data/sector_profiles.yaml` as an undated BFSI obligation (crypto-agility / no
deprecated algorithms), shown in sector views as "obligation, no deadline".

## Limitation

This source was reached only through the RBI website's own ASPX viewer via the fetch
tool's HTML-to-markdown pipeline; a raw PDF/HTML byte fetch and independent SHA-256 was
not obtained (direct `curl`/binary retrieval was not attempted from this environment).
If a future session can vendor the primary document as a file with a SHA-256, that
should replace this citation.
