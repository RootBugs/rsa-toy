"""PEM-ish key export/import — rsa-toy's own documented text format.

Layout (hex integers, one field per line)::

    -----BEGIN OSS-RSA PUBLIC KEY-----
    n=<hex modulus>
    e=<hex exponent>
    -----END OSS-RSA PUBLIC KEY-----

Private keys use ``-----BEGIN OSS-RSA PRIVATE KEY-----`` markers and add
``d=``, ``p=`` and ``q=`` lines. The format is deliberately simple: it
round-trips exactly and every parse failure raises :class:`KeyFormatError`
with a reason. Values must be lowercase hex without ``0x`` prefixes.
"""

from __future__ import annotations

from rsa import PrivateKey, PublicKey, RSAError

__all__ = [
    "KeyFormatError",
    "export_public",
    "import_public",
    "export_private",
    "import_private",
]

PUBLIC_BEGIN = "-----BEGIN OSS-RSA PUBLIC KEY-----"
PUBLIC_END = "-----END OSS-RSA PUBLIC KEY-----"
PRIVATE_BEGIN = "-----BEGIN OSS-RSA PRIVATE KEY-----"
PRIVATE_END = "-----END OSS-RSA PRIVATE KEY-----"


class KeyFormatError(RSAError):
    """Raised when a serialized key cannot be parsed or is inconsistent."""


def _encode(fields: dict[str, int], begin: str, end: str) -> str:
    lines = [begin]
    for name, value in fields.items():
        lines.append(f"{name}={value:x}")
    lines.append(end)
    return "\n".join(lines) + "\n"


def _decode(text: str, begin: str, end: str) -> dict[str, int]:
    if not isinstance(text, str):
        raise KeyFormatError("key must be text")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != begin:
        raise KeyFormatError(f"missing header line {begin!r}")
    if lines[-1] != end:
        raise KeyFormatError(f"missing footer line {end!r}")
    fields: dict[str, int] = {}
    for line in lines[1:-1]:
        if "=" not in line:
            raise KeyFormatError(f"malformed field line: {line!r}")
        name, _, raw = line.partition("=")
        name = name.strip()
        raw = raw.strip()
        if name in fields:
            raise KeyFormatError(f"duplicate field {name!r}")
        if not raw or not all(c in "0123456789abcdef" for c in raw):
            raise KeyFormatError(f"field {name!r} must be lowercase hex")
        fields[name] = int(raw, 16)
    return fields


def _require(fields: dict[str, int], names: tuple[str, ...]) -> None:
    for name in names:
        if name not in fields:
            raise KeyFormatError(f"missing field {name!r}")
    extra = set(fields) - set(names)
    if extra:
        raise KeyFormatError(f"unexpected field(s): {', '.join(sorted(extra))}")


def export_public(pub: PublicKey) -> str:
    """Serialize a public key to the PEM-ish text format."""
    return _encode({"n": pub.n, "e": pub.e}, PUBLIC_BEGIN, PUBLIC_END)


def import_public(text: str) -> PublicKey:
    """Parse a public key; raises :class:`KeyFormatError` on any problem."""
    fields = _decode(text, PUBLIC_BEGIN, PUBLIC_END)
    _require(fields, ("n", "e"))
    n, e = fields["n"], fields["e"]
    if n < 3 or n % 2 == 0:
        raise KeyFormatError("modulus must be an odd integer >= 3")
    if e < 3 or e % 2 == 0:
        raise KeyFormatError("exponent must be odd and >= 3")
    if e >= n:
        raise KeyFormatError("exponent must be smaller than modulus")
    return PublicKey(n, e)


def export_private(priv: PrivateKey) -> str:
    """Serialize a private key (including CRT factors when present)."""
    fields: dict[str, int] = {"n": priv.n, "e": priv.e, "d": priv.d}
    if priv.p is not None:
        fields["p"] = priv.p
    if priv.q is not None:
        fields["q"] = priv.q
    return _encode(fields, PRIVATE_BEGIN, PRIVATE_END)


def import_private(text: str) -> PrivateKey:
    """Parse a private key; validates internal consistency of the values."""
    fields = _decode(text, PRIVATE_BEGIN, PRIVATE_END)
    _require(fields, ("n", "e", "d", "p", "q"))
    n, e, d = fields["n"], fields["e"], fields["d"]
    p, q = fields["p"], fields["q"]
    if n < 3 or n % 2 == 0:
        raise KeyFormatError("modulus must be an odd integer >= 3")
    if p * q != n:
        raise KeyFormatError("p * q does not equal n")
    if p < 3 or q < 3 or p % 2 == 0 or q % 2 == 0:
        raise KeyFormatError("factors must be odd integers >= 3")
    phi = (p - 1) * (q - 1)
    if (e * d) % phi != 1:
        raise KeyFormatError("d is not the inverse of e modulo phi(n)")
    return PrivateKey(n, e, d, p, q)
