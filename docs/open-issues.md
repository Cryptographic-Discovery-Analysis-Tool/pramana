# Open Issues

## OI-001 — Two of three canonical architecture docs are empty (2026-09-17)

**Status:** CLOSED (2026-09-18). See [ADR-004](decisions/ADR-004-supply-the-missing-canonical-architecture-docs.md).
The user supplied both source files; they are copied verbatim into
`docs/architecture/`, and `HASHES.lock` is regenerated. Text below is kept as
the historical record of why this was blocking.

**Status (as of 2026-09-17):** BLOCKING for any task that needs their content. NOT blocking for repo-skeleton/CI/tooling work.

CLAUDE.md's canonical-sources precedence order lists:
1. `docs/architecture/ECDAT_Architecture_Lock.md` — present, real content (16,618 bytes).
2. `docs/architecture/ECDAT_Architecture_Stress-Test_Directives.md` — **empty** (0 bytes). Only
   exists as a placeholder created during initial repo scaffolding; the actual directives text
   (referenced throughout the Lock as "Directive 3", "Directive 6"–"Directive 10", "Directive 12")
   has never been supplied to this repo.
3. `docs/architecture/ECDAT_Final_Architecture.md` — **empty** (0 bytes). Same situation — the
   Lock's §5 "Supersession map for `ECDAT_Final_Architecture.md`" amends a document this repo
   does not actually have a copy of.

**Why this matters:** per the anti-hallucination rules, content for these docs must never be
typed from memory or inferred from the Lock's references to them. Any task that requires reading
a specific Directive N or the pre-amendment Final Architecture text must STOP here first.

**Not currently blocking:** the 2026-09-17 task (repo skeleton, hash-vs-ADR CI check, harness-identifier
grep check, CycloneDX 1.6 schema download) does not require the content of either missing doc — it
only needs the three files to exist at the right paths, which they do. Proceeding with that work;
this entry stays open until the real source text for both docs is supplied.

**Resolution:** user must provide the actual source files for `ECDAT_Architecture_Stress-Test_Directives.md`
and `ECDAT_Final_Architecture.md`, or confirm the Lock is the sole surviving canonical doc and the
other two should be removed from the precedence list in CLAUDE.md.

## OI-002 — No harness-pinned JDK/BC/Node/OpenSSL build exists yet (2026-09-17)

**Status:** NOT blocking for the PRV-T1/T2/T3 evidence-gate experiments (2026-09-17 task), because
Lock §6.1 explicitly says these preliminary observations "do not satisfy the gate" for exactly this
reason and asks for them anyway. Blocking for ever calling PRV-001 LOCKED (harness §16.3 freeze gate
requires "the pinned JDK build", and harness §16.2 says "the harness pins one JDK build").

Lock §6.1: "the harness has not yet chosen its pinned JDK build (no payment-gateway image exists)."
No `ecdat-harness/targets/payments/payment-gateway` image, Dockerfile pin, or `harness/build/pki-lock.generated.json`
exists in the ecdat-harness repo as of this entry — confirmed by inspecting the repo tree.

**What this means for docs/experiments.md EXP-002/003/004 (PRV-T1/T2/T3):** those experiments ran
against whatever JDK/Node/OpenSSL/BC build happened to be installed on the machine that ran them
(recorded exactly, with full version strings, in each entry) — not against a harness-sanctioned pin.
Per Lock §6.1's own classification, this makes them **preliminary observations, not gate results**,
even though the commands and revised-test list match harness §16.1 "Revised tests" 1–3 exactly.

**Resolution:** once the harness builds the payment-gateway image and pins a JDK build (harness
build order, Lock §9 step 1), re-run PRV-T1/T2/T3 against that exact pinned build and record the
result as a gate result (not preliminary) in docs/experiments.md, citing the image digest.

## OI-003 — `CryptoAsset.scope_anchor` has no canonical definition (2026-09-17)

**Status:** NOT fully blocking — implemented as a minimal, explicitly-labeled ASSUMPTION field
rather than stopping the whole model-layer task, per CLAUDE.md's instruction to record and continue
where the gap doesn't require inventing load-bearing behaviour.

The 2026-09-17 model-layer task asks for "CryptoAsset (with scope_anchor)". The literal term
`scope_anchor` does not appear anywhere in `docs/architecture/ECDAT_Architecture_Lock.md` or
`ecdat-harness/docs/ECDAT_Synthetic_Enterprise_Test_Harness.md` (checked by exact grep, case
insensitive). It most plausibly belongs to Directive 3 (visibility/scope) or the Final
Architecture's Part 1 ("Targets") — both empty per [OI-001](#oi-001--two-of-three-canonical-architecture-docs-are-empty-2026-09-17).

The one adjacent canonical concept is harness §15.2 T5: a scan request declares an inventory scope
(`cmdb_scope: [payments, research]`); evidence inside that scope without an owner is
`UNATTRIBUTED`, evidence outside it is `OUT_OF_DECLARED_SCOPE`. `CryptoAsset.scope_anchor` is
implemented as `str | None` — an opaque declared-scope domain identifier (e.g. `"payments"`) an
asset can be checked against — grounded in that concept but **not verified** as the intended field.
No UNATTRIBUTED/OUT_OF_DECLARED_SCOPE logic is implemented against it (that's correlation-layer
work, out of scope here); the model layer only carries the field.

**Resolution:** confirm or correct `scope_anchor`'s intended shape once Directive 3 /
Final Architecture Part 1 is supplied.

**Re-read against Part 5 (2026-09-18).** Final Architecture Part 5 ("Asset resolution
(deliberately constrained)") turns out to be the load-bearing section, not Part 1.
It says, verbatim:

> "Canonical asset key = `(algorithm_family, parameters, purpose, scope_anchor)` where
> **scope_anchor is per-surface**: repo path, image + layer digest, host:port, or
> binary path."

This materially answers the open question. `scope_anchor` is not a declared-scope
domain identifier like `"payments"` (the harness §15.2 T5 `cmdb_scope` concept the
model layer's field was grounded in as an ASSUMPTION) — it is a **per-surface
locator used as part of the within-surface dedup key**: a repo path for source
findings, an `image:layer-digest` pair for image findings, a `host:port` for
network/TLS findings, a binary path for binary findings. Part 5 also states the
merge rule this key exists for: "Within a surface: merge aggressively... Across
surfaces: do not merge. Emit explicit relationship edges instead."

Part 1 ("Targets") does not define `scope_anchor` at all; it only lists the six
surfaces (source, libraries/dependencies, container images, certificates, TLS/network
endpoints, binaries), which is consistent with treating those six as the
`scope_anchor` value spaces Part 5 lists.

**Still open:** the currently-implemented `CryptoAsset.scope_anchor: str | None` is a
generic opaque string, not typed per-surface, and nothing in the model layer enforces
"repo path for source, image+digest for image, host:port for network, binary path for
binary" or drives within-surface-only merge from it. That is a real implementation
gap this ADR does not close — it is P6 (correlation / asset resolution) work,
tracked in `docs/build-plan.md`, not a model-layer fix. No code change is made here.

## OI-004 — Evidence `base_confidence` has no populated source table (2026-09-17)

**Status:** NOT blocking — `Evidence.base_confidence` is modelled as a plain `float` in `[0, 1]`,
range-validated only. No source-tool → confidence mapping is hardcoded anywhere in
`src/ecdat/model/`.

Lock §5 row "3 Findings & confidence": "The base confidence table applies to evidence items."
This is the only text that exists about it — the actual table (values per source tool) would live
in `docs/architecture/ECDAT_Final_Architecture.md` Part 3, which is empty (OI-001), or as curated
rows in `data/` (currently empty except `.gitkeep`, per the project's own convention that "every
row [in data/] has a citation field"). Per CLAUDE.md's anti-hallucination rule, no such mapping may
be typed from memory, so none was added. Callers (adapters, not yet built) must supply
`base_confidence` themselves until the table exists in `data/`.

**Re-scoped 2026-09-17, see [ADR-002](decisions/ADR-002-uncited-confidence-must-carry-its-own-justification.md).**
An exhaustive grep settles the factual part: `0.95` and `0.30` — the
"certificate 0.95 … package 0.30" ordering from an early slide draft — appear nowhere in this
repo, nowhere in the harness docs, and in none of the four recorded fixture READMEs. That
ordering has no citable basis and must not ship; the current deck no longer states it. The only
numeric confidence in any canonical source is the harness's own directory commentary
("confidence ~0.40 per Part 3"), which is explicitly approximate and forwards to the empty
Part 3 — it is recorded in `data/base_confidence.yaml` as `usable: false`, not adopted.

**Now closed:** `data/base_confidence.yaml` exists as a citation registry with
`usable_row_count: 0`; `ecdat.data.base_confidence.lookup()` raises rather than returning a
default; `Evidence.confidence_basis` is required, so an unexplained confidence cannot be
constructed; tests assert the slide ordering cannot be reintroduced and that no
`base_confidence = <number>` literal exists in `src/`.

**Still open (narrowed):** supply Part 3 or an equivalent decision giving literal per-source
values. Only then do rows flip to `usable: true` and adapters switch from `ADAPTER_DECLARED` to
`CITED_TABLE`. No model change is needed when that happens.

**Re-read against Part 3 (2026-09-18).** Final Architecture Part 3 ("Normalisation into
Findings + Evidence") is now supplied and does contain a per-source confidence table.
Verbatim:

| Evidence source | Base confidence | Why |
|---|---|---|
| Parsed certificate / keystore | ~0.95 | The algorithm is literally encoded in the artefact |
| TLS observation on the wire | ~0.90 | Directly observed in a live handshake |
| YARA crypto constant in binary | ~0.70 | Strong signal, but file-level and no usage context |
| Semgrep literal match | ~0.60 | Pattern matched; may be dead code, test code, or overridden |
| Binary symbol / string | ~0.40 | Presence, not use |
| Trivy package present | ~0.30 | Capability only |

Two things narrow how this table may actually be used, both stated by Part 3 itself,
directly above the table: it is introduced as a correction to "the earlier
beginner-facing draft labelled a Semgrep hit 'HIGH' — that is backwards", i.e. Part 3
is presenting **relative ordering with example values**, not a certified benchmark.
The row values are prefixed `~` (approximate) in the source, and Part 3's own closing
caveat says: "There is no published FP/FN benchmark for PQC *inventory* detection
specifically... Measure your own numbers on your demo corpus."

This is exactly the "certificate 0.95 … package 0.30" ordering ADR-002 searched for and
found nowhere in-repo — it was never fabricated, it simply lived in the one canonical
file (Part 3) that was empty at the time. The ADR-002 test asserting this ordering
"cannot be reintroduced" was correct given what existed then and must be revisited now
that a citable source for it exists.

**Resolution, updated:** `data/base_confidence.yaml` may now add these six rows with
`usable: true` and `citation: "ECDAT_Final_Architecture.md Part 3"`, each carrying
Part 3's own "engineering estimate; no published benchmark" framing verbatim in its
justification (CLAUDE.md amendment, "Rows sourced from Final Architecture Part 3 are
cited as 'engineering estimate, Part 3; no published benchmark' — usable, labelled").
The `source-semgrep` adapter's row is `~0.60` under this table, not the `0.5` placeholder
it currently ships with. **This is a code and data change (updating
`data/base_confidence.yaml`, flipping the semgrep adapter to `CITED_TABLE`, and
updating the ADR-002 regression test's fixture ordering) and is intentionally not done
in this task**, which is documentation-only per the user's instruction. Filed here so
it is the next concrete step, not lost.

## OI-005 — No canonical total order among epistemic states for R-DERIVE (2026-09-17)

**Status:** NOT blocking — implemented as an explicit, documented engineering decision
([ADR-001](decisions/ADR-001-epistemic-derivation-strength-order.md)), not a silent assumption.

Lock §3's R-DERIVE says a derived field "is never more certain than its weakest required input,"
but neither the Lock nor the harness gives a total order across all seven closed states
(KNOWN, UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE, INFERRED, DECLARED, CONFLICTING) — only isolated
pairwise facts (e.g. CFG-001: a derived value is "INFERRED, never KNOWN"). `derive()` needs a total
order to be computable and testable at all, so one was chosen and recorded in ADR-001, with the
weakest-of computation restricted to exactly the inputs a given rule actually depends on (harness
§14.3 state D: padding is CONFLICTING but is not a required input of the tier-derivation rule, so
tier stays INFERRED — this is existing canonical behaviour the chosen order must reproduce, and
the property tests in `tests/unit/test_field_value.py` check that it does).

**Resolution:** if Directive doc content later gives an explicit ordering, reconcile ADR-001
against it and update `derivation_strength()` accordingly.

**Re-read against Part 3 and Part 5 (2026-09-18).** Neither section addresses this.
Part 3 ("Normalisation into Findings + Evidence") discusses *confidence* (a float,
Part 3's own table — see [OI-004](#oi-004--evidence-base_confidence-has-no-populated-source-table-2026-09-17))
which is a different axis from *epistemic state* (the closed KNOWN/UNKNOWN/etc. enum)
and never mentions the enum or an ordering over it. Part 5 ("Asset resolution") is
about merge keys and cross-surface relationships (see [OI-003](#oi-003--cryptoassetscope_anchor-has-no-canonical-definition-2026-09-17))
and likewise never touches epistemic state ordering.

The only place the epistemic enum itself is discussed in either newly-supplied
document is the Stress-Test Directives, Directive 2 ("Make epistemic state
first-class"), which lists the same seven states CLAUDE.md's closed enum already
has and says "Do not represent epistemically important unknowns merely as NULL" —
it restates the *existence* of the closed enum, matching what is already
implemented, but gives no total order across it and does not mention R-DERIVE or
"weakest input" by name anywhere in its 196 lines.

**Still open, unchanged.** ADR-001's chosen order is neither contradicted nor
confirmed by either newly-supplied document. This entry stays open exactly as
before; no code change is made here.

## OI-006 — `shares-public-key` identity rule has no literal rule_id (2026-09-17)

**Status:** NOT blocking — simply left out of `src/ecdat/rules/registry.py` rather than invented.

Harness §15.2 T6 gives `IDENTITY-CERT-DER-001` as the literal rule_id for the `same-object`
identity rule (SHA-256 over canonical certificate DER), but never gives an equivalent literal
rule_id for the `shares-public-key` identity rule (SHA-256 over SubjectPublicKeyInfo DER), even
though both are defined in the same subsection. Since Relationship requires `rule_id` for every
content-identity edge (Lock §4 TOPO-001; harness §15.2 T1), no `shares-public-key` Relationship
can currently be constructed without an uncited rule_id — which the model correctly rejects.

**Resolution:** get a literal rule_id for the shares-public-key rule from the same source that
produced `IDENTITY-CERT-DER-001`, then register it in `src/ecdat/rules/registry.py`.

## OI-007 — No Docker on the harness build machine; Maven and haproxy also missing (2026-09-17)

**Status:** NOT blocking for the Tier A harness-scaffolding task (2026-09-17) — worked around
where possible, recorded honestly where not.

Building `ecdat-harness` Tier A (P3 task) needs Docker (for `harness/compose/docker-compose.yml`,
the payment-gateway/edge-lb Dockerfiles) and, for the payment-gateway Java fixture, a JVM build
tool. This machine has neither `docker` nor `mvn` on PATH, and no `haproxy` binary either.

**What was actually done about it:**
- **Maven:** downloaded Apache Maven 3.9.16 directly from `dlcdn.apache.org` into the session's
  scratchpad (not part of either repo) and used it to build and run the real payment-gateway jar.
  This is how `harness/eval/experiments.md`'s CFG-R1 results are real, not fabricated — but it
  means the fixture has only been proven to build with a manually-fetched Maven, not with the
  `maven:3.9.16-amazoncorretto-25-alpine` Docker image referenced in its own `Dockerfile` (that
  image tag was verified to exist via the Docker Hub API, but never actually pulled or built).
- **Docker / docker-compose:** `harness/compose/docker-compose.yml`, and both Dockerfiles, were
  written to spec and validated only as far as `PyYAML` parsing the compose file without error.
  Neither has been built or run. `H6`'s "internal network, no egress" and the whole
  containerised Tier A chain (image → keystore → edge-lb TLS) are therefore **unverified** beyond
  static review.
- **haproxy.cfg:** transcribed from harness §5.3 verbatim plus the generated `pay-edge.pem` path;
  never run through `haproxy -c` or an actual HAProxy process, since no binary is available here.

**Resolution:** on a machine with Docker available, run `docker compose -f harness/compose/docker-compose.yml build && up`
for the payment-gateway/edge-lb pair, confirm the internal network has no egress (H6), and confirm
HAProxy actually terminates TLS with the `pay-edge` cert as `haproxy.cfg` intends. Until then, treat
the containerized path as design-reviewed but not executed.

## OI-008 — Lock §6's E1/E3/E4/TOPO-X2 have no qualifying Tier A test material (2026-09-17)

**Status:** NOT fully blocking — the 2026-09-17 task ("run pinned semgrep, sslyze, trivy, openssl
against Tier A targets; record E1–E4 and TOPO-X1–X3") was executed for the parts that genuinely
overlap Tier A (TOPO-X1, TOPO-X3, and supplemental trivy/semgrep/openssl runs against real Tier A
artifacts — see `docs/experiments.md`). The parts that don't overlap are recorded here rather than
faked with substitute material relabelled as "Tier A."

Lock §6's own E1–E4/TOPO-X1–X3 experiment definitions each name specific test material:

| ID | Needs | Exists in Tier A? |
|---|---|---|
| E1 | a stripped Go binary | **No.** Tier A = payment-gateway + edge-lb + PKI + one trap + no-crypto control (harness §3/§13, confirmed against ground-truth: every `PAY-00X`/`INF-00X` asset with `tier: A` is `application: payment-gateway` or `application: edge-lb`/`pki`; none is Go). The harness's only Go target, `targets/research/datalake-sync`, is domain `research`, not Tier A. No Go toolchain exists on this machine either (`go` not on PATH) — even a non-Tier-A stripped Go binary couldn't be built here. |
| E2 | YARA | N/A to this task — YARA isn't one of the four tools this task named (semgrep, sslyze, trivy, openssl). Not attempted, not a Tier A gap per se. |
| E3 | a TLS endpoint that negotiates a **hybrid PQ group** | **No.** The only hybrid-group-capable target in the harness is `targets/infrastructure/pqc-edge` (`nginx.conf`) — domain `infrastructure`, Tier B (harness §3: "PQC edge" is explicitly listed under Tier B, not Tier A). Tier A's `edge-lb` (`haproxy.cfg`) offers only classical ciphers (`ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`). |
| E4 | a **weak certificate** (Lock's own framing: "seclevel on weak certificates") | **No.** Tier A's PKI (harness §6) is deliberately strong throughout: RSA-4096 root, ECDSA P-384 intermediate, ECDSA P-256 / RSA-2048 leaves. The harness's one deliberately-weak-crypto payments target, `settlement-batch` (DES-EDE3-CBC, RSA-1024 — harness §4 directory listing), is not tagged `tier: A` in any ground-truth asset and is absent from harness §13's explicit Tier A build list. |
| TOPO-X2 | BuildKit attestation retrieval | **No Docker on this machine** — already tracked as [OI-007](#oi-007--no-docker-on-the-harness-build-machine-maven-and-haproxy-also-missing-2026-09-17); BuildKit attestations require an actual `docker buildx build` run, which needs Docker regardless of tier scope. |

**What was done instead, and where it's recorded (`docs/experiments.md`):**
- E1: ran trivy against Tier A's actual payment-gateway fat jar (found trivy's `fs` mode can't see
  inside a standalone jar at all, `rootfs` mode can — real adapter-design evidence) and against
  `no-crypto-service`. Filed as `e1_supplemental_*`, explicitly not claimed as E1.
- E4: ran openssl seclevel mechanics against Tier A's real (strong) certs — showed `@SECLEVEL=4`
  rejects the P-256 ciphersuite locally before any handshake. Real evidence, but not "seclevel
  catching a weak cert," because there is no weak cert in Tier A.
- E3, E2, TOPO-X2: not attempted at all; no substitute material was fabricated for these.

**Why this wasn't fabricated instead:** CLAUDE.md's anti-hallucination rules and "false certainty
is the worst possible bug" — inventing a weak cert or a Go binary and filing it as "Tier A's E1/E4
result" would misrepresent what Tier A actually contains, and would corrupt any later comparison
against harness ground truth (which is scoped strictly by `tier: A` tags).

**Resolution:** E1 needs either (a) a Go toolchain on a build machine plus explicit sign-off to
test against `datalake-sync` (Tier B, out of this task's stated Tier A scope) or a purpose-built
Go binary, whichever the project lead prefers, or (b) the harness formally adding a Go binary to
Tier A (a Lock/harness-doc change, not something this task should do unilaterally, per CLAUDE.md
"don't widen scope"). E3 needs the harness to actually deploy `pqc-edge` (Tier B) and re-scope, or
an explicit decision that Tier A's classical edge-lb is an acceptable E3 substitute. E4 needs
`settlement-batch`'s weak certs, if it plants any (currently the file `src/settle.c` exists but was
not inspected for this task, which stayed in scope). TOPO-X2 needs Docker (OI-007's resolution).

## OI-009 — semgrep does not install on native Windows Python (2026-09-17)

**Status:** NOT blocking — worked around, recorded honestly.

`pip install semgrep==1.99.0` on this machine's native Windows Python
(`C:\Python314`) fails during the build step with `Exception: Semgrep does not
support Windows yet, please try again with WSL` (semgrep's own `setup.py`,
referencing semgrep issue #1330). This is a semgrep-project limitation, not
specific to this pin.

**What was done:** installed and ran semgrep 1.99.0 inside this machine's
existing WSL Ubuntu distribution instead (`wsl` was already configured on this
machine — `wsl --status` shows `Default Distribution: Ubuntu, Default Version:
2` — nothing new was installed at the OS level to work around this). The
WSL filesystem accesses the Windows repo checkout via `/mnt/c/...`.

**Resolution:** if a future adapter needs semgrep as a subprocess dependency
on a Windows dev machine, it must either shell out to WSL explicitly or the
project must standardize development on Linux/macOS/WSL for anything that
touches semgrep. Not an architecture decision — a tooling/environment note.

---

## OI-010 — §5.10 does not rank UNBOUNDED (2026-09-19)

**Status:** decided provisionally, needs a spec answer.

Pramana_Ledger_Spec.md §5.10 states the band order as "BLEEDING >
UNSAVABLE-stopped > SAVABLE > SAFE". UNBOUNDED is a band (§5.5) and is not in
that list, nor are the three authentication bands (§5.6).

**Provisional decision** (`src/ecdat/risk/record.py::_BAND_RANK`): UNBOUNDED
ranks below UNSAVABLE and above SAVABLE. An unbounded row might turn out to be
either, so it must not outrank a row we have proved is bleeding, and must not
be buried under rows we have proved are fine. Authentication bands rank by the
same principle: RESIGN_BEFORE_Z with UNSAVABLE, ROTATE_BEFORE_Z with
UNBOUNDED, SAFE_UNTIL_Z with SAFE.

**Why it matters:** the closure queue (§5.8) ranks tasks by worst reachable
band, so this ordering decides what an operator is told to do first. It is a
presentation decision, not a formula one -- no band changes -- but it should
be confirmed rather than inherited from this file.

---

## OI-011 — §6's `M=2030` row needs an `as_of` after M (2026-09-19)

**Status:** resolved in the test, recorded so it is not rediscovered.

§6 fixes `as_of = 2026-09-18` for the whole test set, and the row
"M=2030 vs M=2038, Z=2036, X=10y, since 2020" expects
"M=2030 -> UNSAVABLE [2026, 2030] STOPPED".

Those cannot both hold. `M` is defined (§5.5) as the earliest MigrationEvidence
with `status=Observed`, and a migration observed on 2030-01-01 is not evidence
available on 2026-09-18. Applying §5.5 literally at that `as_of` gives
`min(as_of, M) = 2026-09-18`, so the window would be [2026-01-01, 2026-09-18]
and `bleeding` would be true (`M > as_of`), i.e. BLEEDING, not UNSAVABLE.

**Resolution taken:** §5.5's formula is normative and is implemented
unchanged. The row is evaluated at `as_of = 2030-06-01`, which is the earliest
`as_of` at which its own M is observable; the expected window [2026-01-01,
2030-01-01] and band UNSAVABLE then both fall out of the unmodified formula.
See `tests/unit/risk/test_exposure_ledger.py::_m_case`.

**What a spec answer would look like:** either restate the row with its own
`as_of`, or state that `M` may be a *scheduled* migration date distinct from
observed MigrationEvidence -- which would be a real design change, because a
scheduled date is a declaration and §5.7 is explicit that declarations never
stop the clock.

---

## OI-012 — §9 VERIFY 3 resolved: schema-validated writer, not cyclonedx-python-lib (2026-09-19)

**Status:** CLOSED.

`Pramana_Ledger_Spec.md` §9 item 3 asks whether `cyclonedx-python-lib`
supports 1.6 `cryptoProperties`, and states the fallback itself: "else:
schema-validated JSON writer, already sufficient".

**Decision:** the schema-validated JSON writer, taken directly rather than
after testing the library. Reasons, in order:

1. The bundled `schemas/cyclonedx-1.6.schema.json` is the authority either
   way. A library that produced output failing that schema would be wrong,
   and one that passed it adds nothing we are not already checking.
2. §5.11 requires the exposure facts to travel as `pramana:*` properties, not
   as CycloneDX fields. Every library model would have to be escape-hatched
   into a generic property list regardless.
3. One fewer dependency in an air-gapped, source-delivered build.

`jsonschema>=4.18` is now a runtime dependency; nothing else was added.

**Consequence to watch:** we are responsible for 1.6 conformance ourselves. If
the spec revises, `schemas/` must be updated and the export tests re-run --
there is no library upgrade that would do it for us.

---

## OI-013 — RESOLVED 2026-09-21: signed export (JSF) is implemented

**Was:** OPEN, deliberately deferred, pending a key custody story (P17's RBAC
and audit log were the deferred prerequisite: "where a key lives, who can use
it" needed the same auth/audit infrastructure this repo did not have until
build-plan.md P17 landed).

**Resolution:** `export/signing.py`. Ed25519 keys only, JSF's "simple
signature" form, over RFC 8785 JCS-canonicalised bytes (`rfc8785`, pinned in
pyproject.toml -- a security-critical canonicalisation algorithm is not worth
reimplementing when a correct library exists, same reasoning as this
project's existing use of `jsonschema` and `cryptography`).
`schemas/jsf-0.82.schema.json` is the real schema, fetched once from
CycloneDX's own `specification` repo (Apache-2.0) and vendored the same way
`cyclonedx-1.6.schema.json` was -- the permissive `{"definitions":
{"signature": {}}}` stub `export/cyclonedx.py::_validator()` used before this
is gone; every `signature` this module emits is schema-checked for real.

**A real schema bug was caught doing this, not assumed:** with the real JSF
schema wired in, the first signed document failed validation. JSF's
`signature.algorithm` is a `oneOf` between a fixed enum (`"Ed25519"`, etc.)
and a `format: "uri"` branch for proprietary algorithms. `jsonschema`'s
default `Draft7Validator` does not check `format` unless given a
`FormatChecker` with the right checker installed (the `uri` format needs the
`rfc3987` package, which `jsonschema[format]` pulls in) -- without one,
`"Ed25519"` is *also* a syntactically valid (if meaningless) URI reference,
so it matches both `oneOf` branches and fails "exactly one must match."
Fixed by adding the `jsonschema[format]` extra and passing
`format_checker=Draft7Validator.FORMAT_CHECKER` to the validator
(`export/cyclonedx.py`).

**Key custody, minimum honest version, stated rather than implied:** the
private key is a file at a path named by `ECDAT_SIGNING_KEY_PATH`, never
logged, held in memory only for the duration of one `sign_bom()` call.
`ecdat keygen` generates one. Rotation is manual (generate, repoint the env
var, restart) -- automated rotation with overlap is real "hardening" work §8
already lists separately, not invented here. A verifier trusts only the bare
embedded Ed25519 public key -- no certificate chain, no external PKI; that
key's fingerprint has to reach a verifier some other way, which this module
does not solve and says so in its own docstring rather than implying more
trust than the mechanism provides.

**Wired into:** `ecdat keygen` / `ecdat verify-export` (CLI) and `GET
/api/export` (signs when `ECDAT_SIGNING_KEY_PATH` is configured, leaves the
export unsigned and says so via `X-Pramana-Signed: false` when it is not --
no silent default key). Verified live end to end: `ecdat keygen` -> sign ->
`ecdat verify-export` reports `signature valid`; a tampered copy of the same
file correctly reports `INVALID: signature does not verify`, exit 1.

Tests: `tests/unit/export/test_signing.py` (16: round-trip, tamper detection
on both the document and the signature value, wrong-key rejection, non-
Ed25519 rejection, real schema validation, no raw key ever appears in a
signed document) plus two in `test_app.py` (unsigned by default,
signed-and-verifying when a key is configured). 560 tests pass;
`check_data_citations.py` still passes.

**Not attempted:** automated key rotation, a certificate chain
(`certificatePath`), and any non-Ed25519 algorithm JSF's schema allows
(RS*/PS*/ES*/HS*) -- all real "hardening" work, deliberately out of this
close, same as the original deferral note already said.

---

## OI-007 — RESOLVED 2026-09-19: Docker, Maven and haproxy are available

The build box (`docs/build-box.md`) provides all three. What OI-007 said was
unverified is now executed, not just reviewed:

- `docker compose config` validates the Tier A compose file against real
  Docker (29.1.3), not PyYAML.
- Both Tier A images **build**: `payment-gateway` (Corretto 25 via the image's
  own `maven:3.9.16-amazoncorretto-25-alpine`) and `edge-lb`.
- The stack **runs**. HAProxy terminates TLS with the `pay-edge` certificate
  exactly as `haproxy.cfg` intends, confirmed by a real handshake.
- H6's "internal network, no egress" is real: the endpoint is unreachable
  from the host and must be probed from a container on the same network.

Still open from the original entry: BuildKit attestation retrieval (TOPO-X2)
has not been attempted.

## OI-009 — RESOLVED 2026-09-19: semgrep runs at its pinned version

semgrep 1.99.0 is installed on the build box and `semgrep --version` reports
`1.99.0`. The Windows limitation is unchanged and irrelevant now: scanning
happens on the box.

**Update 2026-09-27 (DEV-015): `ecdat scan --adapter source-semgrep --live`
now works on this Windows machine through WSL, generically.** The adapter-
level gap this original entry described -- `source-semgrep` had no live path
at all, and `packages-trivy --live` could not be routed through WSL -- is
closed. Working commands, from a Windows shell (Git Bash or PowerShell):

```bash
ECDAT_SEMGREP_LAUNCHER="wsl -e" python -m ecdat.cli scan \
  --adapter source-semgrep --live \
  --input "<harness>/targets/payments/payment-gateway/src" \
  --target-id tier-a --confidence 0.9 --confidence-justification "..."

ECDAT_TRIVY_LAUNCHER="wsl -e" python -m ecdat.cli scan \
  --adapter packages-trivy --live \
  --input "<directory containing the built payment-gateway fat jar>" \
  --target-id tier-a --confidence 0.9 --confidence-justification "..."
```

`ECDAT_SEMGREP_LAUNCHER`/`ECDAT_TRIVY_LAUNCHER` (or the generic
`ECDAT_TOOL_LAUNCHER`) prepend `wsl -e` to the pinned argv; Windows paths in
`--input` are translated to `/mnt/c/...` before being handed to the tool, and
every path either tool reports back is translated back to a Windows path
before a `Finding` is built -- see `adapters/live_launcher.py` and DEV-015.
Verified live this session: `source-semgrep --live` reproduced the recorded
`tier-a-java.raw.json` fixture's 5 findings exactly (same rule/file/line/
value for all five). `packages-trivy --live` was verified against the
zero-package negative control (`targets/controls/no-crypto-service`, 0
packages, offline against WSL's already-cached vulnerability DB); the
positive case against the real payment-gateway fat jar could not be verified
in this session because building that jar needs network access to Maven
Central, which this sandboxed session does not have (see DEV-015's
"Blocked" section) -- not a limitation of the live-scan wiring itself, which
the negative control already exercises end to end.

`harness/eval/run_ecdat.py --live` runs both adapters live (when the fat
jar is available for trivy) and prints a live-vs-replay comparison.

---

## OI-014 — Host OpenSSL is 3.0.13; the fixtures were recorded against 3.5.4 (2026-09-19)

**Status:** OPEN, with a measured workaround.

Ubuntu 24.04 ships OpenSSL 3.0.13. `tests/fixtures/recorded/openssl/3.5.4/`
was recorded against 3.5.4, so a parser validated there runs against a
different build here. Per CLAUDE.md that attaches a VisibilityEntry warning at
runtime and raises under `--strict` (used by scoring) — the intended
behaviour, and the reason this is recorded rather than patched over.

**Measured consequence, not assumed.** The host OpenSSL cannot speak the
hybrid group at all:

```
$ openssl s_client -groups X25519MLKEM768 -connect 127.0.0.1:1
Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed
... group 'X25519MLKEM768' cannot be set
$ openssl s_client -groups X25519 -connect 127.0.0.1:1
... connect:errno=111        # accepted the group, failed at the socket
```

The control matters: X25519 is accepted and fails only at the connection,
X25519MLKEM768 is rejected before any connection is attempted.

**Why it is not blocking.** The containers carry their own OpenSSL **3.5.8** —
both HAProxy (`haproxy -vv`) and the prober image — so hybrid negotiation is
observable inside the Docker network, which is where the endpoints live
anyway. Host-side `openssl` is only used for certificate parsing, where 3.0.13
is adequate.

**Resolution when it matters:** build a prober image pinned to OpenSSL 3.5.4
to match the fixtures, rather than upgrading the host. The probe should ship
its own TLS stack for exactly this reason — a scanner whose results depend on
the distribution it happens to run on is not reproducible.

---

## OI-015 — semgrep 1.99.0 is broken by setuptools >= 81 (2026-09-19)

**Status:** RESOLVED in `tools/provision/build-box.sh`; recorded because the
failure mode is silent.

`pip install semgrep==1.99.0` **succeeds**, and the resulting `semgrep`
binary then dies:

```
ModuleNotFoundError: No module named 'pkg_resources'
  semgrep/tracing.py -> opentelemetry.instrumentation.requests
  -> opentelemetry/instrumentation/dependencies.py -> from pkg_resources import (...)
```

semgrep 1.99.0 pulls `opentelemetry-instrumentation==0.46b0`, which imports
`pkg_resources`; setuptools 81 removed it. An install that reports success and
produces a broken binary is worse than one that fails, so the provisioning
script pins `setuptools<81` both before and after the semgrep install (its
dependency resolution can pull a newer one back in).

Unpin when semgrep's dependency tree stops reaching for `pkg_resources`.

---

## OI-016 — Tier A DOES negotiate a hybrid PQ group; OI-008's E3 row is wrong (2026-09-19)

**Status:** OPEN — the finding is measured; what to do with it is a decision.

OI-008's E3 row states: *"Tier A's `edge-lb` (`haproxy.cfg`) offers only
classical ciphers (`ECDHE-ECDSA-AES128-GCM-SHA256`,
`ECDHE-RSA-AES256-GCM-SHA384`)."* That was read off the configuration file.
The wire says otherwise.

**Measured**, three consecutive handshakes from a container on the internal
network, 2026-09-19:

```
Protocol version:        TLSv1.3
Ciphersuite:             TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group: X25519MLKEM768      (3/3 runs)
```

**Why.** HAProxy's `ciphers` directive governs TLS 1.2 and below. TLS 1.3
group selection was never constrained by `haproxy.cfg`, so it fell through to
the defaults of the OpenSSL the container image carries — **3.5.8**, which
offers X25519MLKEM768. Forcing TLS 1.2 does yield
`ECDHE-ECDSA-AES128-GCM-SHA256`, exactly as the config says, so the config
line is not wrong — it is just silent about the thing that turned out to
matter.

**Two consequences, in opposite directions:**

1. **Tier A now has E3 material.** OI-008 recorded that no Tier A target
   could negotiate a hybrid group, which is why E3 was never run. That is no
   longer true, and §9 VERIFY 1 (does sslyze report `X25519MLKEM768` as a
   negotiated group) now has a target to test against.
2. **The endpoint is NOT migrated.** A client offering only X25519 still
   completes a TLS 1.3 handshake — classical is still accepted. Under §5.7
   that is `classical_still_accepted = true`: the clock does **not** stop, the
   row keeps the **PARTIAL** qualifier, and it stays BLEEDING.

This is the design's own argument, measured on the first endpoint ever
probed. Reading the configuration gives "classical". Taking one handshake and
stopping gives "already migrated". Both are wrong, and the second is the
dangerous one — it would mark a bleeding surface as safe.

**Decision needed:** whether the harness *intends* Tier A to be classical. If
so, `haproxy.cfg` needs an explicit TLS 1.3 group restriction and this becomes
a harness fix. If the accidental hybrid is left in place, it should be
promoted to a deliberate, documented Tier A property — it is a better test
asset than the classical-only endpoint the harness thought it had.

**Update 2026-09-26 (DEV-013):** this entry's own decision is still open --
unchanged by this note, and out of this session's scope (the harness
compose/build files are owned elsewhere). What DEV-013 adds is a sharper
instrument for whichever way the decision goes: the adapter can now probe
`X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` individually
against Tier A and report ACCEPTANCE of each, not only which one is
preferred -- so if `haproxy.cfg` is later given an explicit TLS 1.3 group
list, the same probe path that measured the accidental hybrid here can also
confirm exactly which groups a deliberate configuration change actually
took effect for, group by group, rather than re-reading one preferred group
per test.

---

## OI-017 — sslyze 6.2.0 cannot see a hybrid PQ group. §9 VERIFY 1 answered: NO (2026-09-19)

**Status:** ANSWERED. The question is closed; the consequence is a design
change, filed as DEV-004.

§9 VERIFY item 1 asked whether "sslyze 6.2.0 reports `X25519MLKEM768` as a
negotiated/offered group (recorded probe used `CERTIFICATE_INFO` only —
FACT)". Tested against the live Tier A endpoint. **It does not, and it
cannot.**

**Measured, same endpoint, minutes apart:**

```
openssl s_client (OpenSSL 3.5.8)   Negotiated TLS1.3 group: X25519MLKEM768
sslyze 6.2.0 --elliptic_curves     supported_curves: X25519, X448,
                                   secp256r1, secp384r1, secp521r1
```

**Root cause, read off the library rather than inferred.** sslyze's TLS stack
is nassl 5.4.0, whose complete key-type vocabulary is:

```
DH, EC, X25519, X448, RSA, DSA, RSA_PSS
```

There is no ML-KEM member. sslyze has no name for a hybrid group, so there is
nothing for it to report even when the handshake uses one. This is a ceiling
in the tool, not a configuration or base-image problem: no flag and no newer
image changes it. Fixture:
`tests/fixtures/recorded/openssl/3.5.8/nassl_key_type_ceiling.txt`.

**Why it matters more than it looks.** The negotiated group is the single
input that can stop an exposure clock (§5.7). With sslyze as the only TLS
probe, no endpoint would ever be observed refusing classical, no clock would
ever stop, and every surface would sit at BLEEDING forever. That fails in the
*safe* direction — it under-claims — but it would make the tool structurally
incapable of recognising a migration that actually happened, which is the
thing the whole ledger exists to track.

**Resolution:** the TLS adapter runs two probes. See DEV-004.

**Update 2026-09-26 (DEV-013):** the two DEV-004 probes still only ever
report ONE negotiated group per handshake -- the endpoint's *preference*
when everything is offered. That leaves a related question this entry never
asked open: does the endpoint *accept* a hybrid group other than the one it
prefers (e.g. `SecP256r1MLKEM768`, RFC 10024's second standardised group),
which the full-offer probe would never reveal on an endpoint that always
prefers `X25519MLKEM768` when both are on the table. DEV-013 adds a third
probe shape -- one `openssl s_client -groups <GROUP> -brief` per named group,
offering ONLY that group -- so acceptance of each hybrid group (and a
classical control set) is answered individually, version-gated on
`openssl >= 3.5` (below that, or if the binary is missing, the new fields
report UNKNOWN with a visibility note, never a guess). Recordings:
`tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/`. This does not
reopen the ANSWERED status above -- sslyze's ceiling is unchanged and still
exactly as measured -- it only extends what the openssl-side probe answers.

**Not attempted:** whether a later sslyze/nassl adds ML-KEM. When one does,
the second probe can be dropped and `NASSL_KEY_TYPES` in
`adapters/tls/parser.py` re-recorded from the new library.

## OI-018 — `provider_pluggable`'s downgrade has no registered rule_id (2026-09-21)

Filed alongside DEV-012. `agility/evidence.py::provider_pluggable_for` caps `KNOWN`
(`provider_argument`, observed in source) down to `INFERRED` by construction, because a call site
that accepts a provider argument does not prove a second provider is actually registered at
runtime — but no Lock or harness §14–16 section names this rule, so it cannot be registered in
`rules/registry.py` per CLAUDE.md's anti-hallucination rule ("do not add a rule_id from memory").
**Not attempted:** searching for a future spec revision that might name it. When one does,
register the rule_id and route the field through `model.field_value.derive()`.

## OI-019 — harness PKI was regenerated with fresh random keys, staling recorded fixtures (2026-09-26) — RESOLVED

`ecdat-harness/harness/build/generate-pki.sh` minted new random keys on every run, so any
regeneration silently invalidated every fixture here that records those certificates' bytes
(`topo_x3_der_hash_equality/`, `e4_seclevel_tier_a_certs/`, `sslyze/6.2.0/tier_a_edge_lb.raw.json`);
`test_engine.py::test_the_wire_certificate_and_the_on_disk_certificate_are_the_same_object`
failed after one such regeneration. **Resolution:** the harness PKI is now deterministic (fixed
seed, serials, validity, RFC 6979 ECDSA nonces — see the harness README "Deterministic PKI"), and
the affected fixtures were re-recorded with real OpenSSL 3.5.4 / sslyze 6.2.0 against a local
`openssl s_server` mirroring `targets/payments/edge-lb/haproxy.cfg`. OI-014 (host OpenSSL
version drift) is unaffected.
