# Deviations

Places where the implementation departs from a plan or a canonical document, and
why. Recorded per CLAUDE.md: a departure is filed, never silently substituted.

## DEV-001 — P0's adapter-contract shape differs from `docs/build-plan.md` (2026-09-17)

**Issue.** `docs/build-plan.md` P0 specifies the adapter contract as
`supported_surface`, `support_level`, and `run()` → `(findings, visibility_entry)`.
The implemented contract in `src/ecdat/adapters/base.py` uses `dimensions`
(plural) and returns a single `AdapterRunResult`.

**Evidence.** Two facts drove the change, both discovered after the plan was
written:

1. A tuple return makes the TRAP-07 failure easy to write by accident:
   `return ([], [])` type-checks and reads as "nothing found", yet loses the
   distinction between *scanned and clean* and *never looked*. harness §7.3 is
   explicit that reporting zero assets without a coverage entry is a failure.
2. Recorded observation: a Semgrep run with Java rules over a Python target
   returns `results: []` **and** `paths.scanned: []`. Representing that honestly
   needs a `Coverage {scanned, skipped}` field, which a two-tuple has no place
   for. One adapter also legitimately covers more than one dimension, so the
   singular `visibility_entry` was wrong regardless.

**Options.** (a) Keep the tuple and bolt coverage on later — rejected, the
invariant would be unenforceable at the point it matters. (b) Return one
validated result object — chosen. (c) Return an iterable of results — rejected:
a generator that yields nothing is indistinguishable from a target never
scanned, which is the exact failure being guarded against.

**Impact.** `run()` is one target in, exactly one result out, so an orchestrator
can assert `len(results) == len(targets)` and diff the visibility matrix against
the target list mechanically. `supported_surface` → `dimensions` because the
values are `VisibilityDimension` members and an adapter may declare several.
No canonical document is contradicted; only the plan's own draft wording is.
`docs/build-plan.md` P0 should be read as superseded by this entry.

## DEV-002 — ledger phases 1–4 built before sensor phases P4/P5 (2026-09-19)

**Issue.** `docs/architecture/Pramana_Ledger_Spec.md` §7 fixes the order
`P0b -> P4 -> P5 -> 1 -> 2 -> 3 -> 4 -> 8`, and §11 puts a Linux build box
first. Phases 1–4 (evidence model, function resolution, scenario engine,
exposure ledger) were built first instead, on Windows, with no sensor work.

**Evidence.** §7's prerequisite is real: semgrep does not install on native
Windows (OI-009), and the Tier A images and Go binary cannot be built here. P4
(certs + TLS) needs sslyze and a live endpoint; P5 needs Trivy. None of that is
available on this machine today.

Phases 1–4, by contrast, have no external dependency at all. §5.4 requires
"pure date arithmetic; no hidden constants", and the ledger modules read no
clock, no network and no file at evaluation time (every input arrives in
`LedgerInputs`). The whole of §6's frozen test set is expressible against
constructed evidence objects. So the ordering constraint between P4 and
phase 1 is a *data* dependency -- phase 1 wants real observations to consume --
not a *build* dependency.

**Options.** (a) Wait for the build box and do nothing -- rejected, it stalls
the differentiator behind an environment problem. (b) Stub the sensors and
build phases 1–4 on fake adapters -- rejected: a stub adapter that emits
plausible evidence is exactly the "false certainty" failure, and it would need
deleting later. (c) Build phases 1–4 against explicitly-constructed evidence
objects and §6's frozen expectations, with no adapter involved -- chosen. The
ledger's input types are the contract P4 will fill; writing them first means
P4 has a typed target instead of a prose one.

**Impact.** `score_run.py` cannot yet score these phases on live output, so per
CLAUDE.md's workflow rule they are NOT closed -- they are implemented and
unit-green. Phase 1 and 2 close when P4's adapter produces
`NegotiatedHandshake` / `TemporalEvidence` from a real handshake. The §6 test
set does not depend on that and stays green either way.

## DEV-003 — lifetimes are stored in their policy's unit, not in days (2026-09-19)

**Issue.** `Pramana_Ledger_Spec.md` §5.3 names the fields
`secrecy_lifetime_X_days` and `authenticity_lifetime_A_days`.
`src/ecdat/context/binding.py` stores a `Lifetime` holding *either* years or
days, and `data/data_lifetime.yaml` rows are written in years.

**Evidence.** §6's own expected dates are calendar-year arithmetic and a fixed
day count cannot reproduce them across different leap-year spans. Row 2 of §6
is "RSA static key transport, X=7y ... aggressive: BLEEDING, unsavable
[2024-01-01, as_of]", i.e. `Z_aggr(2031-01-01) - 7y = 2024-01-01`. Seven
calendar years before 2031-01-01 spans two leap days (2024, 2028) and is 2557
days; seven before `Z_central(2036-01-01)` spans one (2032) and is 2556. Any
single day count is therefore wrong for one of the two scenarios:

    2036-01-01 - 2556d = 2029-01-01   (matches §6 "deadline 2029-01-01")
    2031-01-01 - 2556d = 2024-01-02   (§6 says 2024-01-01 -- off by one day)

Verified by running both subtractions before the model was written.

**Options.** (a) Keep days and accept the one-day error -- rejected; a deadline
that is wrong by a day is wrong, and the frozen test set is the acceptance
criterion. (b) Keep days and special-case leap years at subtraction time --
rejected: that is calendar-year arithmetic with the unit thrown away, which is
the bug. (c) Store the unit the policy was written in and subtract in that unit
-- chosen. A policy that says "seven years" means seven calendar years; storing
it as a day count silently re-dates every deadline crossing a different number
of leap days.

**Impact.** Field names change from `..._days` to `secrecy_lifetime_X` /
`authenticity_lifetime_A`, both `Lifetime`. `Lifetime` requires exactly one of
`years` / `days`, so a policy genuinely written in days still round-trips
exactly. The §5.4 requirement "pure date arithmetic; no hidden constants" is
strengthened, not weakened: there is no 365.2425 anywhere. Export (§5.11) must
serialise the unit alongside the number.

## DEV-004 — the TLS adapter runs two probes, not one (2026-09-19)

**Issue.** `Pramana_Ledger_Spec.md` §3 names sslyze as the TLS sensor, and
§7.1 P4 requires "negotiated suite and group recorded — the ledger's input".
`src/ecdat/adapters/tls/` runs sslyze **and** an `openssl s_client` probe.

**Evidence.** sslyze 6.2.0 cannot report a hybrid post-quantum group. Its TLS
stack is nassl 5.4.0, whose key-type enum is exactly `DH, EC, X25519, X448,
RSA, DSA, RSA_PSS` — no ML-KEM member exists, so nothing can be reported.
Measured against the live Tier A endpoint: OpenSSL 3.5.8 negotiated
`X25519MLKEM768` with it; sslyze scanning the same endpoint listed only
classical curves. Full working in OI-017.

So §3's tool choice and §7.1's requirement are in conflict, and the
requirement is the load-bearing one: without the negotiated group there is no
§5.7 evidence, no clock ever stops, and a completed migration is invisible.

**Options.** (a) Drop the group requirement and band every surface from
offered suites — rejected: it makes BLEEDING permanent and unfalsifiable.
(b) Wait for nassl to add ML-KEM — rejected: it makes the ledger's central
claim depend on someone else's roadmap. (c) Patch or fork nassl — rejected:
maintaining a TLS stack is not this project's business. (d) Add a second,
minimal probe that reads the negotiated group from a modern OpenSSL — chosen.

**Impact.** `TlsProbeBundle` carries three captures: sslyze JSON, a
full-offer `s_client` handshake, and a classical-only `s_client` handshake.
The third is what makes a migration falsifiable — an endpoint that negotiates
hybrid *and* still completes when offered only classical has stopped nothing,
and that is the Tier A endpoint's actual state today.

sslyze keeps the job it is good at (certificate chain, accepted suites, curve
enumeration) and keeps its separate-process boundary, so the AGPL-3.0
reasoning in §3 is untouched. The visibility entry names the ceiling in words
on every run, so a reader is never left thinking the curve list was exhaustive.

`tools/prober/Dockerfile` pins the prober's own TLS stack for the same reason
OI-014 gives: a scanner whose results depend on the host distribution's
OpenSSL is not reproducible.

## DEV-007 — within-surface merge key drops `algorithm_family` from strict equality (2026-09-20)

**Issue.** `docs/architecture/ECDAT_Final_Architecture.md` Part 5 states the canonical asset key
as `(algorithm_family, parameters, purpose, scope_anchor)`, which reads as: two Findings must
match on `algorithm_family` exactly before they are even candidates to merge. `src/ecdat/
correlation/merge.py` (P6, within-surface merge) is separately required to handle two Findings
that *disagree* on `public_key_algorithm` for the same `scope_anchor` by producing one merged
`CryptoAsset` with a CONFLICTING field on that key — not two separate, individually-certain
single-Finding assets that are never compared to each other.

**Evidence.** These two requirements are in direct tension. If `algorithm_family` gates grouping
by strict equality, two Findings that disagree on it can never land in the same group by
construction — `_merge_field` never runs on `public_key_algorithm` for them, so the required
CONFLICTING outcome is structurally unreachable. The disagreement would instead surface as "two
unrelated assets", which is a *worse* epistemic claim than "one asset, disputed field": it hides
that both observations were made at the same location, and CLAUDE.md's R-MONOTONE rule ("more
evidence never creates unsupported certainty") cuts both ways — silently splitting one location's
conflicting observations into two individually-confident assets manufactures unsupported
*distinctness* exactly as much as picking a winner would manufacture unsupported *certainty*.

**Options.** (a) Keep `algorithm_family` in the strict key and accept that a disagreement on it
never produces a CONFLICTING field, only two separate assets — rejected: it is the less honest
representation of what was actually observed, for the reason above, and it is incompatible with
the explicit within-surface-merge behaviour this phase is required to implement. (b) Drop
`scope_anchor` from the key too, and merge on `parameters` alone, even across surfaces — rejected
outright: it directly violates the hard "never merge across surfaces" rule (Lock; CLAUDE.md;
Part 5), which this module's own tests guard (`tests/unit/correlation/test_merge.py::
test_different_surfaces_with_matching_algorithm_and_parameters_never_merge`). (c) Key on
`(parameters, scope_anchor)` only, and let `algorithm_family` — like every other field
(`subject`, `key_usage`, etc.) — flow through the ordinary per-field agree/CONFLICT merge path —
chosen. `parameters` (key size and/or curve) remains a strong same-object signal on its own in
every surface this task covers: an RSA key and an EC key do not coincidentally share a
`(size, curve)` shape, so genuinely different key material at one location still lands in
different assets in practice. `algorithm_family` becomes data the merge can be honestly wrong
about, which is the more conservative claim.

**Impact.** `src/ecdat/correlation/merge.py`'s grouping key (`MergeKey`) is `(parameters,
scope_anchor)`, not the full Part 5 four-tuple — `purpose` was already excluded per this task's
own scope (a raw adapter Finding does not populate it; see the module docstring). `CryptoAsset.
algorithm_family` (the plain convenience field added alongside this module, `src/ecdat/model/
asset.py`) is populated from the merged `public_key_algorithm` field only when that field is
*not* itself CONFLICTING; under disagreement it is `None` and the authoritative record is
`asset.fields["public_key_algorithm"].state == CONFLICTING`. `CryptoAsset.purpose` is populated
the same convenience-readback way, from whatever `fields["purpose"]` ends up being after an
ordinary (non-key) merge, if a Finding happens to populate it. Cross-surface merging remains
structurally impossible regardless of any of this, because `scope_anchor` stays in the key
unconditionally.

## DEV-011 — P11's KMS half built and recorded against LocalStack, not a real AWS account (2026-09-20)

**Issue.** `docs/build-plan.md` and `docs/PRAMANA_FINAL_2_Implementation_Plan_and_Rating.md` §3
both call for a real AWS KMS reader (`adapters/kms/`). CLAUDE.md's anti-hallucination rule
("PARSERS are written only against tests/fixtures/recorded/") requires that fixture to be a real,
observed API response, not documentation transcribed from memory — and no AWS account or
credentials exist anywhere in this environment.

**Evidence.** Checked directly before deciding anything: `aws` is not installed, `~/.aws/` does
not exist, no `AWS_*` environment variable is set, on either the Windows host or the Linux build
box (WSL). This was not assumed; it was checked and the negative result recorded here rather than
silently working around it.

**Options.** (a) Write the adapter against AWS's published API documentation only, without a
recorded fixture — rejected outright: this is exactly the "documentation instead of a fixture"
shortcut CLAUDE.md's anti-hallucination rules exist to forbid, and it is indistinguishable from
guessing the moment AWS's own JSON shape differs from the docs in some undocumented way (as it
already does for at least one field here — see below). (b) Skip the KMS half of P11 entirely,
as it had been until this session — a defensible, already-filed position, but the user explicitly
asked for a real credential test rather than continuing to skip it. (c) Provision LocalStack (a
real, running open-source implementation of the AWS API surface) in the Linux build box, and hit
it with the real, unmodified `aws` CLI — chosen, with the user's explicit sign-off after being
asked directly (three options were put to them: provide real credentials, use LocalStack, or
leave it skipped).

**Impact.** Every fixture under `tests/fixtures/recorded/aws-kms/localstack-3.0.2/` is a real
HTTP response from a real running service, not invented — but it is not a genuine AWS account,
and that distinction is stated in that directory's own README, in
`adapters/kms/adapter.py`'s module docstring, and in `docs/build-plan.md`'s progress table, every
place the fact matters. `adapters/kms/adapter.py`'s live code path (`build_*_argv`,
`live_kms_runner`) is the real, unmodified `aws kms` CLI invocation shape; LocalStack is reached
only via the `--endpoint-url` option a real account run simply omits, so nothing about the
adapter's own code is LocalStack-specific. One genuine, measured finding came out of using a real
implementation rather than documentation: LocalStack's `latest` image tag now refuses to start at
all without a paid auth token (`License activation failed`, exit 55) — recorded in the fixture
README as a fact about the image at time of recording, and `:3.0` used instead as the last tag
confirmed to run the free/community KMS emulation.

## DEV-012 — P14's agility fields built without new rule_ids (2026-09-21)

**Issue.** `docs/build-plan.md` P14 adopts three agility fields (`algorithm_selection`,
`hybrid_capable`, `provider_pluggable`) narrowed from an outside review's proposal. None of the
three appears anywhere in the canonical architecture docs (`grep -rn "algorithm_selection\|
hybrid_capable\|provider_pluggable" docs/architecture/` returns nothing) — they are new,
build-plan-level work, not spec-named concepts. CLAUDE.md's anti-hallucination rule forbids
adding a `rule_id` to `src/ecdat/rules/registry.py` "from memory": every entry there must cite a
literal Lock or harness §14–16 section, and none names these three fields, so no citable
`rule_id` exists for them.

**Resolution.** `src/ecdat/agility/evidence.py` builds all three without `model.field_value
.derive()` and without setting `derived_from` on the resulting `FieldValue`, so `FieldValue`'s
own validator (`derived_from` set requires `rule_id`) is never in a position to need one:

- `algorithm_selection` and `hybrid_capable` are **relabellings**, not new inferences: each reads
  one existing source-adapter field (`algorithm_literal_at_call_site` / `algorithm_argument` from
  `source-semgrep`; `negotiated_group` from `tls-endpoint`) and names its already-observed state
  under a new enum value, copying that field's `state` and `evidence_refs` verbatim. No new
  epistemic content is introduced, so no rule governs the mapping — the same principle
  `model/temporal.py`'s `_earliest()` already applies to `possible_since` (a `min()` selection is
  not a derivation).
- `provider_pluggable` **is** a genuine epistemic downgrade: `source-semgrep`'s
  `provider_argument` is `KNOWN` (the source text literally names a provider argument at that
  call site), but the claim "this key's provider is pluggable" is weaker than what was observed
  — a call site that *can* take a provider argument is not proof that a second, actual provider is
  registered and reachable at runtime (the field's own module comment: "whether that is the
  provider that executes is a different question this surface cannot answer"). The result is
  capped to `INFERRED` directly (never `KNOWN`, matching build-plan.md P14's own text: "INFERRED
  ceiling"), with `evidence_refs` still copied from the source field so the claim remains
  traceable, but `derived_from` is left empty rather than cited against an invented `rule_id`.

**Impact.** All three agility fields are fully traceable to their source evidence
(`evidence_refs` never dropped) and replay identically (pure functions of `CryptoAsset.fields`,
no clock, no randomness), but they are not currently checkable by `model.field_value.derive()`'s
own R-DERIVE enforcement path the way a registered-rule_id derivation is. If build-plan.md P14's
work is later folded into a canonical architecture doc with a named rule for
`provider_pluggable`'s downgrade, register that rule_id in `rules/registry.py` and route
`provider_pluggable` through `derive()` at that point — filed as OI-018 alongside this entry.

## DEV-013 — the TLS adapter adds a third probe shape: one `openssl s_client` per named group (2026-09-26)

**Issue.** DEV-004 already runs two probes beyond sslyze -- a full-offer `s_client` handshake and
a classical-only one -- because §7.1 P4 needs the negotiated group and sslyze/nassl cannot report
one at all (OI-017). Both of those still answer only "what does this endpoint PREFER when
everything is offered at once": exactly one group per handshake. OI-016/OI-017 close on that
basis, but neither answers "does this endpoint also ACCEPT SecP256r1MLKEM768", a genuinely
different question a client offering only that one group is needed to answer, and a server that
always prefers X25519MLKEM768 when both are offered would never reveal it either way through the
existing two probes.

**Evidence.** RFC 10024 (`docs/sources/IETF_RFC_10024_2026.md`) names three standardised hybrid
groups, not one; `data/crypto_families.yaml`'s `hybrid_groups` table already cited all three
before this change. OpenSSL 3.5.4 (this machine's `openssl` CLI; Python's own linked OpenSSL is
3.0.18, confirmed via `ssl.OPENSSL_VERSION` -- a different, older library, which is why this
adapter shells out to a separately-resolved `openssl` binary rather than anything Python links)
negotiates each of the three when offered alone (`-groups <GROUP>`), and refuses a group it was
not configured with (`SSL alert number 40`, measured against a local `s_server`) -- see
`tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/README.md` for the exact commands and
the real recordings. OpenSSL added ML-KEM hybrid group support in the 3.5 series; below it,
`-groups X25519MLKEM768` fails to build a ClientHello at all (`Call to SSL_CONF_cmd(-groups,
X25519MLKEM768) failed`), so the group-probe path must know, at runtime, whether the `openssl`
binary it is about to shell out to is new enough -- never assume so.

**Resolution.** `TlsProbeBundle` gains `group_probe_texts` (one `-groups <G> -brief` recording per
group), `group_probe_openssl_version`, and `group_probe_unavailable_reason`.
`adapters/tls/parser.py::parse_group_probe` parses one recording and decides `accepted` by
comparing the reported group against the one offered, through a caller-supplied `canonicalize`
hook rather than exact string match -- OpenSSL reports a classical group back under its OWN
spelling (`prime256v1`) even when offered under the registry's alias spelling (`secp256r1`), and
without canonicalisation that looks like a refusal it is not (recorded:
`classical_server/probe_secp256r1.txt`). The adapter passes `data.crypto_families.canonical_family`
as that hook, so the resolution is the same naming-identity table the rest of the codebase already
cites, not a second one invented here. `adapters/tls/adapter.py::live_group_probe_runner` shells
out for real: it runs `openssl version` once, gates on `MIN_OPENSSL_VERSION = (3, 5, 0)` via
`parser.meets_min_openssl_version`, and only then runs one `s_client` invocation per group in
`default_group_probe_list()` (every cited hybrid group, standardised and deprecated alike, plus a
small classical control set -- all sourced from `data/crypto_families.yaml`, never hardcoded
literals). Below the minimum version, or if the binary cannot be started, no group is probed and
the bundle carries `group_probe_unavailable_reason` instead; the adapter reports
`hybrid_kex_supported` as UNKNOWN with a visibility note naming what was actually found, never a
silent skip and never an assumed capability. The binary is resolved from an explicit argument,
else `ECDAT_OPENSSL_BIN`, else bare `openssl` on PATH -- configurable, per the background this
change was scoped against.

No new `rule_id` was registered. Every new Finding field (`group_accepted_<GROUP>`,
`hybrid_kex_supported`, `hybrid_kex_accepted_groups`, `hybrid_kex_deprecated_groups_accepted`,
`group_codepoint_<GROUP>`) is emitted `KNOWN` directly from its own probe's evidence via
`_known()`/`_known_multi()`, exactly as the existing `der_sha256`/`negotiated_group` fields already
are -- none of them sets `derived_from`, so `FieldValue`'s R-DERIVE validator never requires a
`rule_id` for them (Lock §3: only a field with `derived_from` set needs one). Classifying an
accepted hybrid group as `HYBRID_KEX` still goes through the existing, already-registered
`FUNC-TLS-HYBRID-001` (`function/classifier.py::classify_handshake`, Pramana_Ledger_Spec.md §5.1,
"negotiated hybrid group observed -> HYBRID_KEX") -- that rule is general over ANY negotiated
hybrid group, not specific to the full-offer probe, so it needed no change and no sibling.

**The deprecated draft group.** `X25519Kyber768Draft00` (IANA codepoint `0x6399`, obsoleted by RFC
10024 per `docs/sources/IANA_TLS_SupportedGroups_2026.md`, retrieved 2026-09-26) is still included
in `data/crypto_families.yaml`'s `hybrid_groups` table and still classifies as `HYBRID_KEX` when
observed -- §5.1 names X25519MLKEM768 as an example of "negotiated hybrid group", not as an
exclusive list, and a legacy endpoint that still negotiates this draft group really is doing
hybrid PQ key exchange, just not on the standard track. It is flagged `deprecated: true` so the
adapter can say so, in words, in both a dedicated Finding field
(`hybrid_kex_deprecated_groups_accepted`) and the visibility entry, never silently folded into an
undifferentiated "hybrid supported" claim. No live OpenSSL on the recording machine implements
this pre-standardisation group as a named `-groups` value at all (`Call to SSL_CONF_cmd(-groups,
X25519Kyber768Draft00) failed`), so its test uses one hand-authored `Negotiated TLS1.3 group:`
line (the same shape the real recordings establish, group name substituted) rather than a
recording -- documented at the test site (`tests/unit/adapters/test_tls_group_probe.py`), never
presented as a live capture.

**Scope not attempted.** `cli.py::_build_tls` still refuses `--live` for the adapter as a whole
(it predates this change, pointing at `tools/prober/` instead) -- that gap is sslyze's own live
wiring, a separate, larger piece of work (the AGPL-3.0 separate-process boundary, spec §3), and
this change does not attempt it. `live_group_probe_runner` is a real, working live path for
exactly the group-probe piece and can be wired into the CLI once the sslyze half is; until then it
is reachable programmatically and is not yet a `BUILDERS` entry in `cli.py`.

**Impact.** `data/crypto_families.yaml`'s `hybrid_groups` rows gain `codepoint`/`deprecated`
fields, each independently cited (`docs/sources/IANA_TLS_SupportedGroups_2026.md`, added this
session) rather than reusing the existing `citation`/`quote` pair that classifies the group as
HYBRID_KEX -- two different claims, two different citations, per CLAUDE.md's per-field citation
discipline. `src/ecdat/data/crypto_families.py` gains `is_deprecated_hybrid_group`,
`hybrid_group_codepoint`, and `classical_control_groups`, all following `is_hybrid_group`'s
existing "no usable row -> False/None, never guessed" contract.

## DEV-013 follow-up — `tls-endpoint --live` wired into the CLI, openssl-only (2026-09-26)

**Issue.** DEV-013 itself left `cli.py::_build_tls` refusing `--live` outright ("Scope not
attempted"): `live_group_probe_runner` was a real, working live path for the per-group probes but
was not yet a `BUILDERS` entry, and DEV-004's full-offer/classical-only probes had no live argv
builders at all. CLAUDE.md's workflow rule ("a phase is done only when `ecdat scan` runs LIVE on
the Tier A target directory") and its adapter-contract rule ("every adapter MUST be able to invoke
its tool on a real target path") both name a gap this closes: `tls-endpoint` was the only one of
the nine adapters with no `--live` path reachable from the command line at all.

**Resolution.** `adapters/tls/adapter.py` gains `build_negotiated_argv` (DEV-004's full-offer
probe, no `-groups` restriction) and `build_classical_only_argv` (DEV-004's classical-only control
probe, offering exactly `classical_control_groups()`), and `live_tls_probe_runner`, a factory that
composes both with the existing per-group probe loop behind one `openssl version` gate: below
`MIN_OPENSSL_VERSION` (3.5.0), or if the binary cannot even be started, **no probe of any kind
runs** — the bundle carries only `group_probe_unavailable_reason` and the adapter reports
`hybrid_kex_supported` UNKNOWN with a visibility note naming what was actually found (the version
string, or "could not be started"). This is a deliberately more conservative gate than strictly
necessary — the full-offer and classical-only probes would produce a real, all-classical answer on
an older `openssl` too — chosen because a binary that already failed the one check this module can
perform on it (reporting its own version) is not one this module should trust for anything else
either, and it keeps exactly one code path to reason about instead of two.

`cli.py::_build_tls` now dispatches `--live` to `live_tls_probe_runner(openssl_bin=args.openssl_bin)`
instead of raising `CliUsageError`; a new `--openssl-bin` flag (default: `ECDAT_OPENSSL_BIN` env
var, else `PATH`) threads through exactly like `--rules-path`/`--pkcs11-module` do for their own
`--live` adapters. **sslyze is deliberately not wired live** — its own live invocation is the
AGPL-3.0 separate-process boundary DEV-004's own text already scoped as separate work (spec §3),
and that work remains untouched here. A live scan through this path therefore never populates
`sslyze_json`; every sslyze-sourced Finding field (`supported_curves`, `der_sha256`, `leaf_subject`,
the per-protocol `accepted_*` cipher-suite lists) stays absent rather than guessed, and
`coverage.skipped` states `"sslyze: not run for this target"` on every live run — the adapter
already handled a bundle with no `sslyze_json` correctly before this change (replay mode omits it
routinely), so no adapter-side change was needed for this half of the honesty requirement.

**Verification.** 6 new CLI-level tests in `tests/unit/test_cli.py` monkeypatch
`ecdat.adapters.tls.adapter.subprocess.run` to replay real recordings from
`tests/fixtures/recorded/openssl/3.5.4/hybrid_groups_probe/` (no network, no real subprocess) and
drive the whole path through `main()`: live wiring produces the expected hybrid findings and
`coverage.skipped` names sslyze as not run; an openssl reporting `3.0.13` (too old) and an openssl
that cannot be started at all both produce zero findings with `hybrid_kex_supported` UNKNOWN and a
visibility note naming the reason; `--openssl-bin` is asserted to be argv[0] of every subprocess
call made. `python -m pytest -q` is 0 failures (639 passed, 1 skipped, up from 636 passed before
this session — 6 new tests added, 1 stale test asserting `--live` was refused removed) and every
`tools/ci/check_*.py` passes.

Manually verified live against real processes (report only, not a test, per CLAUDE.md's
"replay of a recorded file ... is for tests and scoring only" rule): a throwaway self-signed
EC P-256 certificate (`openssl req -x509 ...`, discarded after use, never committed) plus a real
`openssl s_server` (OpenSSL 3.5.4, `-groups X25519MLKEM768:X25519`) on `127.0.0.1:15443`, scanned
with `ecdat scan --adapter tls-endpoint --live --host 127.0.0.1 --port 15443 --vantage
local:manual-check --consent`, produced `negotiated_group=X25519MLKEM768`,
`hybrid_kex_supported=True`, `classical_still_accepted=True`, all `KNOWN`, with `coverage.scanned`
listing all three real `openssl s_client` invocations. The same command against the real
`cloudflare.com:443` over the live network produced `negotiated_group=X25519MLKEM768` and accepted
`secp256r1` individually as well (3 of 6 probed groups accepted) — an independently-observed public
endpoint already negotiating ML-KEM hybrid key exchange, not a fixture.

**Scope still not attempted.** sslyze's own live wiring. A live `tls-endpoint` scan today is
openssl-only by design; a reader who wants the certificate chain, cipher-suite enumeration, or
`der_sha256` cross-surface correlation from a live TLS scan still needs either replay mode fed a
real recorded sslyze document, or `tools/prober/`'s coordinated vantage. Filed as the same
still-open item DEV-013 already named, not a new one.

## DEV-014 — new `k8s-secret` adapter: a Kubernetes Secret manifest surface (2026-09-27)

**Context.** No adapter read Kubernetes Secret manifests. A private key or certificate sitting
base64-encoded in a `kind: Secret` YAML document is a real, common deployment-surface risk
(plaintext-adjacent key material outside the artefact surface `certs-x509` already covers) and
CLAUDE.md is explicit that key material at rest anywhere is worth reporting — as a location and a
fingerprint, never as the bytes. build-plan.md does not enumerate this adapter by name; it is new
surface coverage, generic to any Kubernetes deployment, not specific to any one target.

**Resolution.** `adapters/k8s_secret/parser.py` and `adapters/k8s_secret/adapter.py` add
`K8sSecretAdapter` (`adapter_id = k8s-secret`, `support_level = PARTIAL`,
`dimensions = (DEPLOYMENT,)`) wired into `cli.py`'s `BUILDERS`/`ADAPTERS`/`_build_k8s_secret`
exactly like `certs-x509`: `--input` is a manifest file or directory, read directly (no
subprocess). It reads multi-document YAML, and for every `kind: Secret` document emits one
Finding per `data`/`stringData` entry, reporting `content_kind` (`certificate` / `private_key` /
`opaque` / `undecodable`), and:

- a certificate value is hashed and described by `adapters.certs.parser.load_pem_or_der`/`describe`
  directly (not re-implemented), so a certificate seen inside a Secret and the same certificate
  seen as a bare file correlate as the same object through `der_sha256` via
  `ecdat.correlation.engine`, with zero Secret-specific correlation code.
- a private-key value is loaded once with `cryptography`'s `load_pem_private_key`/
  `load_der_private_key` to read algorithm/size/curve, then the key object is discarded
  (`del key_obj`) — never returned, logged, or stored. `contains_private_key_material: KNOWN(True)`
  is the explicit risk-signal field.
- `kind: SealedSecret` / `kind: ExternalSecret` are recognised but never decrypted/resolved (the
  value at rest is never the plaintext for either), reported as their own manifest kind with every
  content field `UNKNOWN`.
- a file under a directory holding `Chart.yaml`, named `kustomization.yaml`, or containing Go
  template delimiters (`{{ ... }}`, not legal YAML) is detected and named in the visibility detail
  as "not rendered" rather than parsed or silently skipped — no helm/kustomize invocation is
  attempted (out of scope: a separate external-tool trust boundary, same reasoning DEV-004/DEV-013
  used for sslyze).

No new `rule_id` was registered: every field this adapter emits is a direct read off the manifest
(a `data`/`stringData` entry, decoded and described), the same "KNOWN from direct observation
needs no rule_id" reasoning `certs.adapter.CertificateAdapter._fields` already documents — nothing
here is `derived_from` another field.

Harness-side (out of ecdat's scope, recorded here only for cross-reference): `run_ecdat.py` gained
a `k8s-secret` run over `targets/infrastructure/k8s/secrets/`, and `score_run.py`'s `configuration`
surface join was generalised to accept a `k8ssecret:<path>:<key>` surface string (previously only
`config:<root>:<property key>`) so INF-017 can be matched by its ground-truth `key: data.tls.key`.

**Verification.** New tests in `tests/unit/adapters/test_k8s_secret.py` build small synthetic
manifests in `tmp_path` (a throwaway EC key + self-signed cert via `cryptography`, never a
recorded harness fixture) covering: a `kubernetes.io/tls` Secret's `tls.key`/`tls.crt`, an
`Opaque` Secret, a `stringData` entry, undecodable base64, a `SealedSecret` (detect-only, all
content UNKNOWN), and a Helm-chart-directory / `kustomization.yaml` file each reported as
not-rendered rather than parsed. Every assertion checks `SecretLeakError` is raised if a test
deliberately feeds the adapter a real PEM private key text and asserts the *serialised* result
never contains the PEM block, base64 key bytes, or `-----BEGIN`. `python -m pytest -q` and every
`tools/ci/check_*.py` are re-verified green in the same session this entry was added (see the
session's final numbers).
