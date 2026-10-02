# TEC 910018:2025 — Technical Report: Migration to Post Quantum Cryptography

- **Publisher:** Telecommunication Engineering Centre (TEC), Department of
  Telecommunications, Ministry of Communications, Government of India
- **Document number:** TEC 910018:2025, Release 1.0, January 2025 (per the PDF's own
  title page; the site listing/upload date is 2025-03-28)
- **URL:** https://tec.gov.in/pdf/TR/Final%20technical%20report%20on%20migration%20to%20PQC%2028-03-25.pdf
- **Retrieved:** 2026-09-27, PDF SHA-256
  `561a9fedd25b8def1b6a0f03375039209ae9e55543e984aa7bd6a61eb3f6c851` (34 pages)
- ISO 9001:2015.

## What it is

A technical/advisory report from a TEC committee, "compiled based on the contributions
received from the member of the committee ... based on the consensus built upon the
contributions of the member deliberated on the subject in the multiple rounds of
meeting" (Important Notice / Disclaimer page). It explains PQC migration concepts (CRQC,
harvest-now-decrypt-later, hybrid schemes) and lists PQC use cases by sector (Annexure-I,
p.34), including for the Telecom Sector:

> "Telecom Sector
> - To secure OSS (operation support system) and BSS (Business support system)
>   applications
> - Protection of Data in Transit
> - Integrity of Virtualized Network Function: to prevent tampering and unauthorized
>   access of network element."

## Why no dated obligation was added to data/policy_deadlines.yaml

A full read of the report (34 pages, extracted with `pypdf`) found no compliance date,
mandate, or "shall" requirement binding telecom operators or equipment vendors to a
calendar deadline. It is informational/advisory guidance from TEC, not a DoT circular or
mandate. No separate DoT mandate requiring PQC readiness for new telecom equipment from
2026 was found by web search either (searches turned up only the DST National Quantum
Mission roadmap's general CII timelines, which already cover telecom -- see
`India_DST_Quantum_Safe_Roadmap_2026.md`, p.36 CII sector list -- and general PQC industry
commentary, not a DoT-specific instrument). Recorded in `data/policy_deadlines.yaml` as
`usable: false`; recorded in `data/sector_profiles.yaml` as an undated telecom
obligation/use-case reference.
