"""Kubernetes Secret manifest parsing (generic -- not tied to any one
deployment; see the adapter module docstring for the observation-surface
rationale).

This module never returns key material, base64 values, or any decoded
secret bytes. It reduces a `data`/`stringData` entry to the same kind of
safe-to-emit description `adapters.certs.parser` already produces for a
certificate file: content KIND (certificate / private_key / opaque),
algorithm/size/curve where applicable, and certificate fingerprints where
the value decodes to one. Certificate values are handed to
`adapters.certs.parser.load_pem_or_der` / `describe` directly -- this module
does not re-implement certificate parsing, so a certificate found inside a
Secret and the same certificate found on disk correlate on the identical
`der_sha256`/`spki_sha256` hashes.

A decode or parse FAILURE is recorded as a note naming only the exception
TYPE, exactly like `certs.parser.CertificateParseError` -- never the bytes
that failed to decode or parse (CLAUDE.md: "No private key / secret bytes in
... logs ... test snapshots").
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

import yaml
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key

from ecdat.adapters.certs.parser import CertificateParseError, ParsedCertificate, load_pem_or_der

#: `kind:` values this module can decode content for.
SECRET_KIND = "Secret"

#: `kind:` values that are recognised but never decoded: the value at rest is
#: not the plaintext (SealedSecret is asymmetrically encrypted; ExternalSecret
#: is a reference to a value that lives in an external store this adapter has
#: no target for). Reporting these as ordinary Secrets that "have no data"
#: would be a false negative -- they are recorded as their own manifest kind
#: instead, with every content field left UNKNOWN.
DETECT_ONLY_KINDS = frozenset({"SealedSecret", "ExternalSecret"})

#: Keys a `kubernetes.io/tls` Secret conventionally carries a certificate
#: under. Used only as a hint when the content itself has no PEM marker (a
#: bare DER cert has none); the content sniff below is authoritative whenever
#: it succeeds.
_CONVENTIONAL_CERT_KEYS = frozenset({"tls.crt", "ca.crt"})
_CONVENTIONAL_KEY_KEYS = frozenset({"tls.key"})

_PEM_CERT_MARKER = b"-----BEGIN CERTIFICATE-----"
_PEM_PRIVATE_KEY_MARKER = b"PRIVATE KEY-----"


class K8sManifestParseError(ValueError):
    """The bytes are not YAML this module can read, or not YAML at all.

    Carries no manifest content and no exception text from the underlying
    parser, matching `certs.parser.CertificateParseError`'s contract: a
    manifest that fails to parse is not an invitation to echo what it held.
    """


def _yaml_documents(text: str, *, location: str) -> list[dict]:
    try:
        raw_docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise K8sManifestParseError(
            f"{location}: not readable YAML ({type(exc).__name__})"
        ) from None
    return [doc for doc in raw_docs if isinstance(doc, dict)]


def _decode_base64(value: str) -> tuple[bytes | None, str | None]:
    """(decoded bytes, error note). Never both non-None."""
    if not isinstance(value, str):
        return None, f"data value is not a string ({type(value).__name__})"
    try:
        return base64.b64decode(value, validate=True), None
    except Exception as exc:  # noqa: BLE001 -- type name only, never the value
        return None, f"not valid base64 ({type(exc).__name__})"


def _private_key_description(key) -> tuple[str, int | None, str | None]:
    """(algorithm, size in bits, curve name) for a private key object. Never
    the key itself -- mirrors `certs.parser._public_key_description`."""
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA", key.key_size, None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "EC", key.curve.key_size, key.curve.name
    if isinstance(key, dsa.DSAPrivateKey):
        return "DSA", key.key_size, None
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519", 255, None
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448", 448, None
    return type(key).__name__, None, None


@dataclass(frozen=True)
class SecretKeyObservation:
    """One `data`/`stringData` entry of one Secret, reduced to what may
    safely leave this process. There is no field here that can hold the
    decoded value itself."""

    key: str
    source_field: str  # "data" or "stringData"
    content_kind: str  # "certificate" | "private_key" | "opaque" | "undecodable"
    certificates: tuple[ParsedCertificate, ...] = ()
    key_algorithm: str | None = None
    key_size: int | None = None
    key_curve: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class ParsedSecretManifest:
    """One `kind: Secret` document, decoded. `location` is the file it came
    from; `doc_index` its position within that (possibly multi-document)
    file."""

    location: str
    doc_index: int
    name: str | None
    namespace: str | None
    secret_type: str | None
    keys: tuple[SecretKeyObservation, ...]


@dataclass(frozen=True)
class DetectedOnlyManifest:
    """One `kind: SealedSecret`/`ExternalSecret` document. Presence only --
    see `DETECT_ONLY_KINDS`'s docstring for why content is never decoded."""

    location: str
    doc_index: int
    kind: str
    name: str | None
    namespace: str | None


def _describe_value(key_name: str, data: bytes) -> SecretKeyObservation:
    if _PEM_CERT_MARKER in data or (key_name in _CONVENTIONAL_CERT_KEYS and b"-----BEGIN" in data):
        try:
            certificates = load_pem_or_der(data, location=key_name)
        except CertificateParseError as exc:
            return SecretKeyObservation(
                key=key_name, source_field="", content_kind="undecodable", note=str(exc)
            )
        return SecretKeyObservation(key=key_name, source_field="", content_kind="certificate", certificates=certificates)

    if _PEM_PRIVATE_KEY_MARKER in data or key_name in _CONVENTIONAL_KEY_KEYS:
        key_obj = None
        last_error: str | None = None
        for loader in (load_pem_private_key, load_der_private_key):
            try:
                key_obj = loader(data, password=None)
                break
            except Exception as exc:  # noqa: BLE001 -- type name only, never the bytes
                last_error = type(exc).__name__
                continue
        if key_obj is None:
            return SecretKeyObservation(
                key=key_name,
                source_field="",
                content_kind="undecodable",
                note=f"could not be parsed as a private key ({last_error})",
            )
        algorithm, size, curve = _private_key_description(key_obj)
        del key_obj  # read and discarded, unexamined -- see module docstring
        return SecretKeyObservation(
            key=key_name,
            source_field="",
            content_kind="private_key",
            key_algorithm=algorithm,
            key_size=size,
            key_curve=curve,
        )

    return SecretKeyObservation(key=key_name, source_field="", content_kind="opaque")


def _with_source_field(observation: SecretKeyObservation, source_field: str) -> SecretKeyObservation:
    return SecretKeyObservation(
        key=observation.key,
        source_field=source_field,
        content_kind=observation.content_kind,
        certificates=observation.certificates,
        key_algorithm=observation.key_algorithm,
        key_size=observation.key_size,
        key_curve=observation.key_curve,
        note=observation.note,
    )


def _secret_keys(doc: dict) -> tuple[SecretKeyObservation, ...]:
    observations: list[SecretKeyObservation] = []

    data = doc.get("data") or {}
    if isinstance(data, dict):
        for key_name, raw_value in sorted(data.items()):
            decoded, error = _decode_base64(raw_value)
            if decoded is None:
                observations.append(
                    SecretKeyObservation(key=str(key_name), source_field="data", content_kind="undecodable", note=error)
                )
                continue
            observations.append(_with_source_field(_describe_value(str(key_name), decoded), "data"))

    string_data = doc.get("stringData") or {}
    if isinstance(string_data, dict):
        for key_name, raw_value in sorted(string_data.items()):
            text_value = raw_value if isinstance(raw_value, str) else str(raw_value)
            observations.append(
                _with_source_field(_describe_value(str(key_name), text_value.encode("utf-8")), "stringData")
            )

    return tuple(observations)


def parse_manifest_text(
    text: str, *, location: str
) -> tuple[list[ParsedSecretManifest], list[DetectedOnlyManifest], list[str]]:
    """Parse one file's YAML documents.

    Returns (secrets, detect_only, notes). `notes` records documents this
    module recognised but did not act on (not a Secret/SealedSecret/
    ExternalSecret `kind`, or a `kind: Secret` doc with no usable name) --
    never raised as an error, because "this document is not a k8s Secret" is
    an ordinary, expected outcome for a manifest directory, not a parse
    failure.
    """
    documents = _yaml_documents(text, location=location)
    secrets: list[ParsedSecretManifest] = []
    detect_only: list[DetectedOnlyManifest] = []
    notes: list[str] = []

    for index, doc in enumerate(documents):
        kind = doc.get("kind")
        if kind == SECRET_KIND:
            metadata = doc.get("metadata") or {}
            secrets.append(
                ParsedSecretManifest(
                    location=location,
                    doc_index=index,
                    name=metadata.get("name") if isinstance(metadata, dict) else None,
                    namespace=metadata.get("namespace") if isinstance(metadata, dict) else None,
                    secret_type=doc.get("type"),
                    keys=_secret_keys(doc),
                )
            )
        elif kind in DETECT_ONLY_KINDS:
            metadata = doc.get("metadata") or {}
            detect_only.append(
                DetectedOnlyManifest(
                    location=location,
                    doc_index=index,
                    kind=str(kind),
                    name=metadata.get("name") if isinstance(metadata, dict) else None,
                    namespace=metadata.get("namespace") if isinstance(metadata, dict) else None,
                )
            )
        else:
            notes.append(f"{location}#{index}: kind={kind!r}, not a Secret/SealedSecret/ExternalSecret")

    return secrets, detect_only, notes
