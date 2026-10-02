"""Loader for `data/crypto_families.yaml` (Pramana_Ledger_Spec.md §5.5).

No family classification is hardcoded in `src/`, and there is no
name-pattern fallback: a family with no usable row is UNKNOWN to the ledger,
which produces an UNBOUNDED band and a closure task, not a guess. That is the
whole point -- guessing "anything with EC in the name is broken" is how a
scanner invents certainty it does not have.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_FILENAME = "crypto_families.yaml"


class NoCitedFamilyError(LookupError):
    """No usable row classifies this family."""


def _path() -> Path:
    # src/ecdat/data/crypto_families.py -> repository root -> data/
    return Path(__file__).resolve().parents[3] / "data" / _FILENAME


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    data = yaml.safe_load(_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "families" not in data:
        raise ValueError(f"malformed crypto-family registry at {_path()}")
    return data


def families() -> tuple[dict[str, Any], ...]:
    return tuple(load().get("families") or ())


def hybrid_groups() -> frozenset[str]:
    return frozenset(
        row["key"] for row in (load().get("hybrid_groups") or ()) if row.get("usable") is True
    )


def is_hybrid_group(group: str | None) -> bool:
    return group is not None and group in hybrid_groups()


def _hybrid_group_row(group: str) -> dict[str, Any] | None:
    for row in load().get("hybrid_groups") or ():
        if row.get("key") == group and row.get("usable") is True:
            return row
    return None


def is_deprecated_hybrid_group(group: str | None) -> bool:
    """True only for a hybrid group whose registry row is cited as
    deprecated (data/crypto_families.yaml, e.g. the pre-standardisation
    X25519Kyber768Draft00). False for an unlisted or non-deprecated group --
    never guessed from the name."""
    if group is None:
        return False
    row = _hybrid_group_row(group)
    return bool(row and row.get("deprecated") is True)


def hybrid_group_codepoint(group: str | None) -> str | None:
    """The IANA TLS Supported Groups codepoint cited for this group, or None
    when the group has no usable row (never inferred from the name)."""
    if group is None:
        return None
    row = _hybrid_group_row(group)
    return row.get("codepoint") if row else None


def classical_control_groups() -> tuple[str, ...]:
    """A small classical-group control set, spelled exactly as the wire
    reports them, read off rows this registry already cites -- so a caller
    that wants "a couple of classical groups to probe alongside the hybrid
    ones" (adapters/tls/adapter.py's group-probe path) never hardcodes a
    group name that isn't already a cited row here. Not exhaustive: just
    enough to show the same probe path also confirms an ordinary classical
    group when one is expected to work."""
    names: list[str] = []
    for row in families():
        if row.get("usable") is True and row.get("key") == "X25519":
            names.append(row["key"])
    for row in load().get("family_aliases") or ():
        if row.get("usable") is True and row.get("key") == "secp256r1":
            names.append(row["key"])
    return tuple(names)


def is_shor_broken(family: str) -> bool:
    """True/False only for a cited, usable row. Raises otherwise."""
    for row in families():
        if row.get("key") != family:
            continue
        if row.get("usable") is not True:
            raise NoCitedFamilyError(
                f"{family!r} is recorded but not usable: "
                f"{row.get('why_not_usable', 'no reason recorded')}"
            )
        return bool(row["shor_broken"])
    raise NoCitedFamilyError(f"{family!r} has no row in the crypto-family registry")


def algorithm_component(value: str | None) -> str | None:
    """The algorithm component of a JCA transformation string.

    `Cipher.getInstance(...)`'s argument is "algorithm/mode/padding" or bare
    "algorithm" (Java SE Cipher API doc; see
    docs/sources/Oracle_JavaSE17_Cipher_Transformation.md) -- e.g.
    `adapters/source/semgrep.py`'s `algorithm` field can be
    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" or "AES/GCM/NoPadding", not a
    bare family name. This is a pure string-format split (first `/`-segment),
    never a classification -- `Mac`/`MessageDigest` algorithm names
    (e.g. "HmacSHA256", "MD5") have no `/` at all and pass through
    unchanged. Classification still only ever comes from
    `data/crypto_families.yaml` via `canonical_family`/`is_shor_broken`.
    """
    if value is None:
        return None
    return value.split("/", 1)[0]


def canonical_family(name: str | None) -> str | None:
    """Resolve a wire/tool spelling to the family spelling the registry uses.

    Naming identity only (`basis: NAMING_IDENTITY` rows). An unlisted spelling
    is returned unchanged, so it misses `is_shor_broken` and becomes a closure
    task rather than a guess.
    """
    if name is None:
        return None
    for row in load().get("family_aliases") or ():
        if row.get("usable") is True and row.get("key") == name:
            return str(row["family"])
    return name
