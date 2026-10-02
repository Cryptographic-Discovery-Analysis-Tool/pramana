# Java SE 17 API — javax.crypto.Cipher (transformation string format)

- **Publisher:** Oracle
- **Date:** Java SE 17 API documentation (current as retrieved)
- **URL:** https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html
- **Retrieved:** 2026-09-28, HTML javadoc (via web fetch)
- **Why vendored:** `adapters/source/semgrep.py`'s `algorithm` field, for a
  `Cipher.getInstance(...)` call site, carries the raw JCA transformation
  string exactly as matched (e.g. `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"`,
  `"AES/GCM/NoPadding"`), not a bare algorithm-family name. Classifying it
  against `data/crypto_families.yaml` requires knowing that the string's
  first `/`-separated component is the algorithm, per this specification --
  not a guess about JCA's string format.

## Cipher class documentation — "Cipher Algorithm Names" / transformation format

Exact text:

- "A transformation is of the form:
  - 'algorithm/mode/padding' or
  - 'algorithm'

  (in the latter case, provider-specific default values for the mode and
  padding scheme are used). For example, the following is a valid
  transformation:

  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");"

This is a format/parsing statement, not a security classification -- used
only to justify splitting a semgrep-observed transformation string on `/`
and taking the first component as the algorithm family lookup key
(`ecdat.data.crypto_families`). It does not by itself supply any
`shor_broken` value; that still comes only from the matching
`data/crypto_families.yaml` family row (or its absence, which is reported
honestly as unclassified, never guessed).

See also the companion **JDK Providers Documentation — Java Security
Standard Algorithm Names** (`Cipher` Algorithm Names section,
https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html),
which recommends fully specifying algorithm/mode/padding rather than relying
on a provider default.
