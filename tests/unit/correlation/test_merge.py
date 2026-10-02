"""Within-surface merge (Final Architecture Part 5; docs/deviations.md
DEV-007 for why `algorithm_family` disagreement still produces one merged
asset with a CONFLICTING field rather than two separate assets)."""
from __future__ import annotations

from ecdat.correlation.merge import merge_within_surface
from ecdat.model.epistemic import EpistemicState
from ecdat.model.field_value import FieldValue
from ecdat.model.finding import Finding

SURFACE_A = "certdir:/etc/pki/service-a"
SURFACE_B = "certdir:/etc/pki/service-b"


def _known(value):
    return FieldValue(value=value, state=EpistemicState.KNOWN, evidence_refs=("ev-1",))


def _cert_finding(
    finding_id: str,
    *,
    surface: str,
    algorithm: str,
    size: int | None = 2048,
    curve: str | None = None,
    extra_fields: dict | None = None,
) -> Finding:
    """A Finding shaped like CertificateAdapter._fields() actually emits
    (src/ecdat/adapters/certs/adapter.py): only the fields this merge task
    reads (public_key_algorithm/public_key_size/public_key_curve) plus one
    unrelated field (subject) to prove ordinary fields merge too."""
    fields = {
        "public_key_algorithm": _known(algorithm),
        "public_key_size": _known(size) if size is not None else FieldValue(
            value=None, state=EpistemicState.UNKNOWN
        ),
        "public_key_curve": _known(curve) if curve is not None else FieldValue(
            value=None, state=EpistemicState.UNKNOWN
        ),
        "subject": _known(f"CN={finding_id}"),
    }
    if extra_fields:
        fields.update(extra_fields)
    return Finding(
        finding_id=finding_id,
        surface=surface,
        evidence_refs=("ev-1",),
        fields=fields,
    )


def test_matching_algorithm_and_size_same_surface_merge_into_one_asset():
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="RSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    asset = assets[0]
    assert set(asset.finding_refs) == {"cert-a", "cert-b"}
    assert asset.scope_anchor == SURFACE_A
    assert asset.algorithm_family == "RSA"
    assert asset.fields["public_key_algorithm"].state == EpistemicState.KNOWN
    assert asset.fields["public_key_algorithm"].value == "RSA"
    # evidence_refs from both source Findings are unioned onto the field.
    assert asset.fields["public_key_algorithm"].evidence_refs == ("ev-1",)


def test_disagreeing_algorithm_same_scope_anchor_produces_conflicting_field_not_a_winner():
    # Same parameters (key size) and the same scope_anchor -- two tools
    # disagreeing about what the key material AT THAT LOCATION actually is.
    # Merging into one asset and flagging the field CONFLICTING is the
    # R-MONOTONE-honest outcome; silently splitting into two "certain"
    # single-source assets would hide that both observations point at the
    # same place. See DEV-007.
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="DSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    asset = assets[0]
    assert set(asset.finding_refs) == {"cert-a", "cert-b"}
    field = asset.fields["public_key_algorithm"]
    assert field.state == EpistemicState.CONFLICTING
    assert field.value is None  # never a silently-chosen winner
    assert field.resolution is not None
    assert field.resolution.reason
    # The plain convenience field must not paper over the conflict either.
    assert asset.algorithm_family is None
    # A field the two Findings actually agreed on still merges cleanly.
    assert asset.fields["public_key_size"].state == EpistemicState.KNOWN
    assert asset.fields["public_key_size"].value == 2048


def test_different_surfaces_with_matching_algorithm_and_parameters_never_merge():
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_B, algorithm="RSA", size=2048)

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 2
    scope_anchors = {asset.scope_anchor for asset in assets}
    assert scope_anchors == {SURFACE_A, SURFACE_B}
    for asset in assets:
        assert len(asset.finding_refs) == 1


def test_three_findings_two_matching_one_distinct_parameters_split_correctly():
    # Not one of the required cases, but guards the grouping key against a
    # regression where "aggressively merge within a surface" is read as
    # "merge everything on one surface into a single asset".
    finding_a = _cert_finding("cert-a", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_b = _cert_finding("cert-b", surface=SURFACE_A, algorithm="RSA", size=2048)
    finding_c = _cert_finding("cert-c", surface=SURFACE_A, algorithm="EC", size=None, curve="secp256r1")

    assets = merge_within_surface([finding_a, finding_b, finding_c])

    assert len(assets) == 2
    by_refs = {frozenset(asset.finding_refs): asset for asset in assets}
    assert frozenset({"cert-a", "cert-b"}) in by_refs
    assert frozenset({"cert-c"}) in by_refs
    ec_asset = by_refs[frozenset({"cert-c"})]
    assert ec_asset.algorithm_family == "EC"
    assert ec_asset.parameters == "secp256r1"


def test_empty_input_produces_no_assets():
    assert merge_within_surface([]) == ()


# --- conservative default for surfaces Part 5 was never written about --------


def _package_finding(finding_id: str, *, surface: str, name: str, version: str) -> Finding:
    """Shaped like PackagesAdapter._fields() (src/ecdat/adapters/packages/
    adapter.py): no public_key_algorithm/negotiated_group field anywhere, so
    it must never match a _KEY_SIGNATURES entry."""
    return Finding(
        finding_id=finding_id,
        surface=surface,
        evidence_refs=("ev-1",),
        fields={"name": _known(name), "version": _known(version)},
    )


def test_two_different_packages_same_surface_do_not_merge():
    # The bug this test guards against: before _KEY_SIGNATURES existed, any
    # Finding without public_key_size/public_key_curve fields got the SAME
    # key (None, None) within one surface, so two unrelated Trivy packages
    # found in the same rootfs silently collapsed into one CryptoAsset.
    finding_a = _package_finding("pkg-a", surface="rootfs:/app", name="bcprov-jdk18on", version="1.86")
    finding_b = _package_finding("pkg-b", surface="rootfs:/app", name="logback-core", version="1.5.38")

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 2
    for asset in assets:
        assert len(asset.finding_refs) == 1
        assert asset.algorithm_family is None
        assert asset.parameters is None


def test_two_packages_with_identical_fields_still_do_not_merge():
    # Even two Findings that happen to agree on every field value must not
    # merge for a surface with no recognised signature -- there is no
    # evidence they are "the same asset" observed twice, only that they
    # look alike; merging them would assert an identity nothing supports.
    finding_a = _package_finding("pkg-a", surface="rootfs:/app", name="commons-logging", version="1.3.6")
    finding_b = _package_finding("pkg-b", surface="rootfs:/app", name="commons-logging", version="1.3.6")

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 2


# --- tls-endpoint's own signature ---------------------------------------------


def _tls_finding(finding_id: str, *, surface: str, group: str, suite: str, protocol: str = "TLSv1.3") -> Finding:
    """Shaped like TlsEndpointAdapter._fields() (src/ecdat/adapters/tls/
    adapter.py): negotiated_group + negotiated_cipher_suite together are
    the recognised tls-endpoint signature."""
    return Finding(
        finding_id=finding_id,
        surface=surface,
        evidence_refs=("ev-1",),
        fields={
            "negotiated_group": _known(group),
            "negotiated_cipher_suite": _known(suite),
            "negotiated_protocol": _known(protocol),
        },
    )


def test_two_tls_probes_same_endpoint_same_negotiation_merge():
    finding_a = _tls_finding("tls-a", surface="tls:host:443", group="X25519", suite="TLS_AES_256_GCM_SHA384")
    finding_b = _tls_finding("tls-b", surface="tls:host:443", group="X25519", suite="TLS_AES_256_GCM_SHA384")

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    assert assets[0].algorithm_family == "X25519"


def test_two_tls_probes_disagreeing_group_same_endpoint_merge_and_conflict():
    # Same DEV-007 shape as certs: negotiated_group is excluded from the key
    # so a disagreement becomes a CONFLICTING field, never a silent split.
    finding_a = _tls_finding("tls-a", surface="tls:host:443", group="X25519", suite="TLS_AES_256_GCM_SHA384")
    finding_b = _tls_finding("tls-b", surface="tls:host:443", group="X25519MLKEM768", suite="TLS_AES_256_GCM_SHA384")

    assets = merge_within_surface([finding_a, finding_b])

    assert len(assets) == 1
    assert assets[0].fields["negotiated_group"].state == EpistemicState.CONFLICTING
    assert assets[0].algorithm_family is None


# --- source-semgrep's `algorithm` field -------------------------------------
#
# Regression (2026-09-28, quickscan demo root cause #1): source-semgrep
# matches neither `_KEY_SIGNATURES` signature (no `public_key_algorithm`, no
# `negotiated_group`/`negotiated_cipher_suite`), so it correctly gets no
# algorithm-based *merge* (module docstring) -- but before this fix, its
# `algorithm` field was also never read back onto `CryptoAsset.algorithm_family`
# at all, so a concrete literal algorithm found in Java source (e.g. a
# `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` call site)
# never contributed to any quantum-vulnerable count -- not even as
# "unclassified". `_ALGORITHM_FAMILY_READBACK_CANDIDATES` now includes
# "algorithm" as a third candidate.


def _semgrep_call_site_finding(finding_id: str, *, surface: str, algorithm: str) -> Finding:
    """Shaped like SemgrepSourceAdapter._fields_for_call_site() (src/ecdat/
    adapters/source/semgrep.py) for a literal-algorithm Cipher/Mac/
    MessageDigest call site: path/line/reachable/purpose plus the literal
    `algorithm` field this test cares about."""
    return Finding(
        finding_id=finding_id,
        surface=surface,
        evidence_refs=("ev-1",),
        fields={
            "path": _known("Foo.java"),
            "line": _known(42),
            "reachable": FieldValue(value=None, state=EpistemicState.UNKNOWN),
            "purpose": FieldValue(value=None, state=EpistemicState.UNKNOWN),
            "algorithm": _known(algorithm),
        },
    )


def test_semgrep_literal_transformation_string_becomes_the_assets_algorithm_family():
    finding = _semgrep_call_site_finding(
        "semgrep-1", surface="source", algorithm="RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    )

    (asset,) = merge_within_surface([finding])

    # The raw transformation string is what CryptoAsset carries (readback is
    # a plain, unmodified field readback) -- splitting it down to the bare
    # "RSA" family is `quickscan._classify_family`'s job
    # (ecdat.data.crypto_families.algorithm_component), not merge's.
    assert asset.algorithm_family == "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"


def test_semgrep_nonliteral_algorithm_never_becomes_a_guessed_family():
    finding = Finding(
        finding_id="semgrep-2",
        surface="source",
        evidence_refs=("ev-1",),
        fields={
            "path": _known("Foo.java"),
            "line": _known(10),
            "reachable": FieldValue(value=None, state=EpistemicState.UNKNOWN),
            "purpose": FieldValue(value=None, state=EpistemicState.UNKNOWN),
            "algorithm": FieldValue(value=None, state=EpistemicState.UNKNOWN),
            "algorithm_argument": _known("props.getTransformation()"),
        },
    )

    (asset,) = merge_within_surface([finding])

    assert asset.algorithm_family is None
