# sslyze 6.2.0 (library) — recorded fixtures (2026-09-17, re-recorded 2026-09-26)

**Exact command to install (pinned):**
```bash
pip install --no-warn-script-location 'sslyze==6.2.0'
```
Run on native Windows Python (`C:\Python314`), no WSL needed — sslyze installs
fine there, unlike semgrep.

**Exact version:** `pip show sslyze` → `Version: 6.2.0`. Recorded dependency
conflict (does not block sslyze itself): `pyopenssl 25.3.0 requires
cryptography<47,>=45.0.7, but you have cryptography 44.0.3` — pip's resolver
downgraded `cryptography` to satisfy sslyze's own pin; both were already
present on this machine from an earlier task (OI-002's PRV-T1/T2/T3 work did
not use these). Not investigated further; recorded honestly per the
anti-hallucination rule against silently assuming environment purity.

**Date run:** 2026-09-17

**Target:** Tier A edge-lb TLS endpoint (harness §5.3 / §13). **Substitution
recorded:** the harness has no `haproxy` binary available on this machine
(`docs/open-issues.md` OI-007), so `openssl s_server -accept 8443 -cert
targets/payments/edge-lb/certs/pay-edge.pem -key
targets/payments/edge-lb/certs/pay-edge.pem -www` was used as a stand-in TLS
listener, presenting the exact same `pay-edge.pem` file
(`generate-pki.sh`-produced cert+key+chain bundle) that HAProxy's own config
(`haproxy.cfg`: `bind *:8443 ssl crt /etc/haproxy/certs/pay-edge.pem`) is
written to load. This proves the certificate/SNI-recording behaviour under
test but does **not** prove HAProxy's own TLS stack behaves identically
(cipher negotiation quirks, ALPN, etc. are HAProxy-specific and untested here)
— same class of honest substitution as OI-007's Maven-instead-of-Docker
workaround.

**Code:** `topo_x1_sni_probe.py` — uses the `sslyze` **library** API (not the
CLI), per this task's "sslyze (library)" instruction:
`sslyze.Scanner`, `ServerNetworkLocation`, `ServerScanRequest`,
`ScanCommand.CERTIFICATE_INFO`.

**Exact command:**
```bash
python topo_x1_sni_probe.py > topo_x1_sni_probe.raw.json 2> topo_x1_sni_probe.stderr.log
```

**Files:**
- `topo_x1_sni_probe.py` — the script (source, not output; kept alongside the
  recording per CLAUDE.md's "no parser without a recorded fixture" rule — this
  IS the fixture-producing code, analogous to `experiments/PRV-T*` layout).
- `topo_x1_sni_probe.raw.json` — raw JSON result.
- `topo_x1_sni_probe.stderr.log` — raw stderr (one `CryptographyDeprecationWarning`
  from sslyze's own trust-store loading code, unrelated to the SNI question).

See `docs/experiments.md` TOPO-X1 entry for the finding.

## `tier_a_edge_lb.raw.json` (re-recorded 2026-09-26; harness PKI staleness, not OI-014)

This file's original 2026-09-17 capture was never documented here (a gap
this re-recording also closes). It is consumed by
`ecdat/tests/unit/adapters/test_tls.py`,
`tests/unit/agility/test_evidence.py`, `tests/unit/assemble/test_bridge.py`,
`tests/unit/test_cli.py`, and (the case this re-recording exists for)
`tests/unit/correlation/test_engine.py::test_the_wire_certificate_and_the_on_disk_certificate_are_the_same_object`,
which cross-checks this fixture's leaf certificate against the real,
on-disk `ecdat-harness/harness/build/out/pay-edge/cert.pem` byte-for-byte —
so this fixture goes stale every time the harness PKI is regenerated with
new random keys (see the top-level "Deterministic PKI" section of
`ecdat-harness/README.md`: as of 2026-09-26 it no longer does, but this
particular file was still stale from the last non-deterministic
regeneration and needed one final re-recording).

**Target / substitution:** same `openssl s_server` standing in for HAProxy
as `topo_x1_sni_probe.py` above (see that entry), same `pay-edge.pem`. SNI
`pay-edge`, `127.0.0.1:8443` (the original capture recorded `172.18.0.3` — a
Docker-internal address this machine does not have; `127.0.0.1` is what
`openssl s_server` actually listened on here, both times).

**Code:** `tier_a_edge_lb_scan.py` — sslyze **library** API, scanning with
the **full** `ScanCommand` set (matches this file's own
`scan_result` key list: `certificate_info`, every `*_cipher_suites`,
`elliptic_curves`, etc. — a superset of `topo_x1_sni_probe.py`'s
certificate-only scan, needed because `test_tls.py` reads cipher-suite and
curve fields this file also carries). Builds sslyze's own
`SslyzeOutputAsJson` object the same way sslyze's CLI does internally
(`sslyze/__main__.py`), confirmed by reading that file before writing this
script, not guessed.

**Exact command (2026-09-26, second re-recording — see "Cipher/chain fidelity
fix" below for why this supersedes the first same-day capture):**
```bash
# split the combined leaf+intermediate bundle so s_server can serve the leaf
# as -cert and the intermediate as -cert_chain (s_server does NOT auto-chain
# extra certs found after the first one in a single -cert file the way
# HAProxy's `crt` directive does, so this split is required to reproduce
# HAProxy's send-the-whole-bundle behaviour):
awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} {print > ("cert" n ".pem")}' \
  ../../../../../../ecdat-harness/targets/payments/edge-lb/certs/pay-edge.pem

openssl s_server -accept 8443 \
  -cert cert1.pem \
  -key ../../../../../../ecdat-harness/targets/payments/edge-lb/certs/pay-edge.pem \
  -cert_chain cert2.pem \
  -cipher "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384" \
  -no_ssl3 -no_tls1 -no_tls1_1 \
  -www &
python tier_a_edge_lb_scan.py > tier_a_edge_lb.raw.json 2> tier_a_edge_lb.stderr.log
```
Run against `openssl version` → `OpenSSL 3.5.4 30 Sep 2025` (Git Bash
`/mingw64/bin/openssl`, same build the other `openssl/3.5.4` fixtures in
this repo were recorded against) and `pip show sslyze` → `Version: 6.2.0`.

**Cipher/chain fidelity fix (2026-09-26):** the first same-day re-recording
(see "Known follow-on" note it left, now resolved and removed) used plain
`-www` with no cipher or chain flags, so `s_server` negotiated whatever its
own OpenSSL build defaulted to and sent only the leaf certificate. That does
not mirror `targets/payments/edge-lb/haproxy.cfg` line 16
(`bind *:8443 ssl crt .../pay-edge.pem ssl-min-ver TLSv1.2 ciphers
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384`), and the mismatch
was silent — sslyze happily reported 7 accepted TLS 1.2 suites (every ECDSA
suite the ECDSA cert supports) instead of the 1 HAProxy's `ciphers` line
actually allows. Fixed by adding flags that mirror `haproxy.cfg`'s directives
one-for-one:
- `ssl-min-ver TLSv1.2` → `-no_ssl3 -no_tls1 -no_tls1_1` (s_server has no
  single "-min-ver" flag; disabling everything below 1.2 is the equivalent).
  TLS 1.3 is left enabled (HAProxy does not cap the max version here), which
  is why `tls_1_3_cipher_suites` still lists suites (e.g.
  `TLS_AES_256_GCM_SHA384`) — read on for why those weren't restricted too.
- `ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384` →
  `-cipher "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"`
  (OpenSSL's `ciphers`/`-cipher` controls TLS ≤1.2 suite selection only).
  Verified with `openssl s_client -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384`
  against the running `s_server`: handshake fails (alert 40, no suitable
  signature algorithm) because the loaded cert is ECDSA-only, so only the
  ECDHE-ECDSA suite is actually reachable — matching this file's recorded
  single TLS 1.2 accepted suite.
- `crt .../pay-edge.pem` (HAProxy's PEM-with-chain convention: HAProxy sends
  every cert in the file, not just the first) → `-cert cert1.pem -cert_chain
  cert2.pem` after splitting the same bundle, restoring the 2-certificate
  chain (leaf `CN=pay-edge` + `CN=Harness Intermediate CA ECC`) HAProxy would
  actually present.
- **haproxy.cfg has no other TLS-relevant directives** — no
  `ssl-max-ver`/`ssl-default-bind-options`, no `curves`, no `ciphersuites`
  (TLS 1.3 suite list), no ALPN, no client-cert (`ca-file`/`verify`) config
  (confirmed by reading the whole file: `global`/`defaults` blocks are TCP
  timeouts and logging only). Where HAProxy is left at its OpenSSL-linked
  build's default, this recording is left at `s_server`'s own OpenSSL
  3.5.4 defaults too (no `-curves`, no `-ciphersuites` override) rather than
  guessing a narrower HAProxy-specific default — documented here as the
  explicit choice per this task's "mirror defaults, document the choice"
  instruction.

**Verification (2026-09-26):** the recorded leaf certificate's
`fingerprint_sha256` (`iVkYElu2euguoesYl7BR7PFJkCRUGTzSdymO708xIPM=`, base64,
unchanged from the first same-day capture — same cert bytes, only the
negotiated suites/chain differ) decodes to the same SHA-256 as
`openssl x509 -in ecdat-harness/harness/build/out/pay-edge/cert.pem -outform DER | sha256sum`
→ `895918125bb67ae82ea1eb1897b051ecf149902454193cd277298eef4f3120f3` hex, and
the SPKI hash independently matches
`openssl x509 -in .../cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum`
→ `133afc2d59061ec4a826fbc664de07721bc086f5c05946dac254e70d3a935200` hex —
i.e. the exact real on-disk PKI file `test_engine.py`'s test reads,
confirmed identical before this file was committed. `tests/unit/adapters/test_tls.py`'s
`leaf_der_sha256`/`spki_sha256`/`der_sha256` constants were updated to these
same two values (with a comment pointing at the harness's "Deterministic
PKI"), and its `tls_1_2_cipher_suites` expectation
(`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` only) was left unchanged — it was
always correct; this recording was wrong. `python -m pytest -q` and every
`tools/ci/check_*.py` pass clean after this fix.

**Re-recorded 2026-09-27 (harness PKI date bump, not a fresh staleness bug):**
`ecdat-harness/harness/build/generate-pki.sh`'s fixed `NOT_BEFORE` moved from
`2026-09-01` to `2026-09-27` (pay-edge's leaf was about to run past its
documented 90-day window against real wall-clock; see
`ecdat-harness/README.md` "Deterministic PKI" and `docs/open-issues.md`
OI-019) and `harness/build/bump-pki.sh` was added as the one-command way to
do that going forward. Every cert byte pay-edge's leaf carries therefore
changed (new `notBefore`/`notAfter`, same key/subject/extensions), so this
fixture was re-recorded exactly as above: local
```
awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} {print > ("cert" n ".pem")}' \
  ../../../../../../ecdat-harness/targets/payments/edge-lb/certs/pay-edge.pem
openssl s_server -accept 8443 \
  -cert cert1.pem \
  -key ../../../../../../ecdat-harness/targets/payments/edge-lb/certs/pay-edge.pem \
  -cert_chain cert2.pem \
  -cipher "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384" \
  -no_ssl3 -no_tls1 -no_tls1_1 \
  -www &
python tier_a_edge_lb_scan.py > tier_a_edge_lb.raw.json 2> tier_a_edge_lb.stderr.log
```
(openssl 3.5.4, sslyze 6.2.0, s_server killed immediately after). The new
leaf `fingerprint_sha256` is `SCSAXNDkHMtxGw2mDrgz/wR2lcRStBYBPYoIU8DMe7A=`
(base64), which decodes to der_sha256
`4824805cd0e41ccb711b0da60eb833ff047695c452b416013d8a0853c0cc7bb0` hex —
independently confirmed against
`openssl x509 -in ecdat-harness/harness/build/out/pay-edge/cert.pem -outform DER | sha256sum`.
The SPKI hash is **unchanged**
(`133afc2d59061ec4a826fbc664de07721bc086f5c05946dac254e70d3a935200` hex — the
key itself is seed-derived, not date-derived). Accepted suites are unchanged
too: exactly one TLS 1.2 suite (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`)
and the same TLS 1.3 set, chain length 2. `tests/unit/adapters/test_tls.py`'s
`leaf_der_sha256`/`der_sha256` constants were updated to the new value;
`spki_sha256` was left as-is (genuinely unchanged). `python -m pytest -q` and
every `tools/ci/check_*.py` pass clean after this fix. See
`harness/build/bump-pki.sh`'s header comment for the full re-record
checklist to repeat next time this PKI is bumped.
