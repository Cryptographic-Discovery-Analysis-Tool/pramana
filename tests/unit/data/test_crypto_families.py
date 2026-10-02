"""data/crypto_families.yaml hybrid_groups (Pramana_Ledger_Spec.md §5.1).

RFC 10024 (docs/sources/IETF_RFC_10024_2026.md) resolved SecP256r1MLKEM768
and SecP384r1MLKEM1024 on 2026-09-26 -- previously recorded as "searched for
and NOT found in any in-repo document" (no guess by analogy with
X25519MLKEM768 was ever made, per data/base_confidence.yaml's own rule).
"""
from __future__ import annotations

from ecdat.data.crypto_families import (
    algorithm_component,
    canonical_family,
    hybrid_group_codepoint,
    hybrid_groups,
    is_deprecated_hybrid_group,
    is_hybrid_group,
    is_shor_broken,
)


def test_x25519mlkem768_is_still_a_hybrid_group():
    assert is_hybrid_group("X25519MLKEM768") is True


def test_rfc_10024_groups_are_now_cited_hybrid_groups():
    assert is_hybrid_group("SecP256r1MLKEM768") is True
    assert is_hybrid_group("SecP384r1MLKEM1024") is True
    assert {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"} <= hybrid_groups()


def test_an_uncited_group_spelling_is_not_a_hybrid_group():
    """No guessing by analogy: an unlisted spelling is not hybrid."""
    assert is_hybrid_group("SecP521r1MLKEM1024") is False
    assert is_hybrid_group(None) is False


# --- OI-016/OI-017 resolution: codepoints and the deprecated draft group ---


def test_the_iana_codepoints_are_cited():
    assert hybrid_group_codepoint("X25519MLKEM768") == "0x11EC"
    assert hybrid_group_codepoint("SecP256r1MLKEM768") == "0x11EB"
    assert hybrid_group_codepoint("SecP384r1MLKEM1024") == "0x11ED"
    assert hybrid_group_codepoint("X25519Kyber768Draft00") == "0x6399"


def test_an_unlisted_group_has_no_codepoint():
    assert hybrid_group_codepoint("SecP521r1MLKEM1024") is None
    assert hybrid_group_codepoint(None) is None


def test_the_legacy_draft_group_is_still_a_hybrid_group_but_flagged_deprecated():
    """X25519Kyber768Draft00 predates RFC 10024 and was obsoleted by it, but
    a server that still negotiates it really is doing hybrid PQ key
    exchange -- §5.1 classifies any negotiated hybrid group as HYBRID_KEX,
    it does not carve out an exception for a superseded one. `deprecated`
    is a visibility flag, not a withheld classification."""
    assert is_hybrid_group("X25519Kyber768Draft00") is True
    assert is_deprecated_hybrid_group("X25519Kyber768Draft00") is True


def test_the_standardised_rfc_10024_groups_are_not_deprecated():
    assert is_deprecated_hybrid_group("X25519MLKEM768") is False
    assert is_deprecated_hybrid_group("SecP256r1MLKEM768") is False
    assert is_deprecated_hybrid_group("SecP384r1MLKEM1024") is False


def test_an_unlisted_group_is_not_deprecated_by_default():
    """No guessing: an unlisted spelling is neither hybrid nor deprecated."""
    assert is_deprecated_hybrid_group("SecP521r1MLKEM1024") is False
    assert is_deprecated_hybrid_group(None) is False


# --- 2026-09-28 quickscan demo root cause: missing family_aliases rows -------
# (docs/sources/IETF_RFC_5480_2009.md, docs/sources/IETF_RFC_8017_2016.md)


def test_secp384r1_and_secp521r1_now_alias_to_their_nist_family():
    assert canonical_family("secp384r1") == "P-384"
    assert canonical_family("secp521r1") == "P-521"
    assert is_shor_broken(canonical_family("secp384r1")) is True
    assert is_shor_broken(canonical_family("secp521r1")) is True


def test_rsaencryption_oid_name_aliases_to_rsa():
    assert canonical_family("rsaEncryption") == "RSA"
    assert is_shor_broken(canonical_family("rsaEncryption")) is True


def test_an_unlisted_curve_spelling_is_still_unaliased():
    """No guessing by pattern: secp224r1 (P-224) has no alias row yet."""
    assert canonical_family("secp224r1") == "secp224r1"


# --- ECDH/AES/DSA families added directly to `families` (not aliases) -------


def test_generic_ecdh_is_shor_broken():
    assert is_shor_broken("ECDH") is True


def test_aes_is_not_shor_broken():
    assert is_shor_broken("AES") is False


def test_dsa_is_shor_broken():
    assert is_shor_broken("DSA") is True


# --- algorithm_component(): JCA transformation string -> algorithm ----------
# (docs/sources/Oracle_JavaSE17_Cipher_Transformation.md)


def test_algorithm_component_splits_cipher_transformation():
    assert algorithm_component("RSA/ECB/OAEPWithSHA-256AndMGF1Padding") == "RSA"
    assert algorithm_component("AES/GCM/NoPadding") == "AES"


def test_algorithm_component_passes_through_a_bare_algorithm_name():
    # Mac/MessageDigest algorithm names have no "/" at all.
    assert algorithm_component("HmacSHA256") == "HmacSHA256"
    assert algorithm_component("MD5") == "MD5"
    assert algorithm_component("ECDH") == "ECDH"


def test_algorithm_component_of_none_is_none():
    assert algorithm_component(None) is None
