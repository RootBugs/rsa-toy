"""Textbook RSA made inspectable: keygen, PKCS#1 v1.5-style padding,
encrypt/decrypt and sign/verify.

Padding styles (both "PKCS#1 v1.5-style", documented, not byte-for-byte
compatible with OpenSSL):

* **Encryption**: ``0x00 || 0x02 || PS || 0x00 || M`` where ``PS`` is at
  least 8 non-zero random bytes. ``decrypt`` *strictly* validates every
  field and raises :class:`PaddingError` on any malformation.
* **Signature**: ``0x00 || 0x01 || PS(0xFF) || 0x00 || M`` where ``PS`` is at
  least 8 ``0xFF`` bytes. ``verify`` validates the same way and returns
  ``False`` (never raises) on mismatch or bad padding.

All randomness comes from an explicit :class:`random.Random`; when omitted a
fresh seeded generator is used so behaviour is reproducible.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from primality import generate_prime

__all__ = [
    "PublicKey",
    "PrivateKey",
    "RSAError",
    "PaddingError",
    "generate_keypair",
    "rsa_int",
    "pad_encrypt",
    "unpad_encrypt",
    "pad_sign",
    "unpad_sign",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
]

DEFAULT_EXPONENT = 65537
_PAD_SEED = 0xA5A5
_MIN_PS = 8  # PKCS#1 v1.5 requires at least 8 bytes of padding string


class RSAError(ValueError):
    """Base class for rsa-toy errors."""


class PaddingError(RSAError):
    """Raised when decrypted padding fails strict validation."""


@dataclass(frozen=True)
class PublicKey:
    """RSA public key: modulus ``n`` and exponent ``e``."""

    n: int
    e: int

    @property
    def byte_size(self) -> int:
        """Length in bytes of one encoded block (``k`` in PKCS terms)."""
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    """RSA private key with CRT-safe extra factors ``p`` and ``q``."""

    n: int
    e: int
    d: int
    p: int | None = None
    q: int | None = None

    @property
    def byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)


def generate_keypair(
    bits: int = 512, seed: int | None = None, exponent: int = DEFAULT_EXPONENT
) -> tuple[PublicKey, PrivateKey]:
    """Generate an ``(e, d, n)`` keypair.

    *bits* is the modulus size; primes of ``bits // 2`` are drawn with
    :func:`primality.generate_prime`. ``gcd(e, phi) == 1`` is enforced by
    regenerating a prime when it fails, and ``d`` is the modular inverse of
    ``e`` modulo ``phi = (p-1)(q-1)``.
    """
    if bits < 16:
        raise ValueError("modulus must be at least 16 bits")
    if exponent % 2 == 0 or exponent < 3:
        raise ValueError("public exponent must be odd and >= 3")
    rng = random.Random(seed)
    half = bits // 2
    while True:
        p = generate_prime(half, rng)
        q = generate_prime(half, rng)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if math.gcd(exponent, phi) != 1:
            continue
        d = pow(exponent, -1, phi)
        n = p * q
        return (
            PublicKey(n, exponent),
            PrivateKey(n, exponent, d, p, q),
        )


def rsa_int(value: int, exp: int, n: int) -> int:
    """Raw modular exponentiation — the ``m^e mod n`` primitive itself."""
    if not 0 <= value < n:
        raise RSAError("value must satisfy 0 <= value < n")
    return pow(value, exp, n)


def _int_to_block(x: int, k: int) -> bytes:
    if x.bit_length() > k * 8:
        raise RSAError("integer does not fit in modulus-sized block")
    return x.to_bytes(k, "big")


def _check_block_size(k: int) -> None:
    if k < _MIN_PS + 3:
        raise ValueError("modulus too small for PKCS#1 v1.5-style padding")


def pad_encrypt(msg: bytes, k: int, rng: random.Random) -> bytes:
    """Encode *msg* as ``00 02 PS 00 M`` in exactly *k* bytes."""
    _check_block_size(k)
    if len(msg) > k - 11:
        raise PaddingError(
            f"message of {len(msg)} bytes too long for {k}-byte modulus "
            f"(max {k - 11})"
        )
    ps_len = k - len(msg) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = rng.randrange(256)
        if b != 0:
            ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + msg


def unpad_encrypt(em: bytes) -> bytes:
    """Strictly validate ``00 02 PS 00 M`` and return ``M``.

    Raises :class:`PaddingError` for every malformation: wrong header,
    missing separator, or a padding string shorter than 8 bytes.
    """
    if len(em) < 11:
        raise PaddingError("encoded message too short")
    if em[0] != 0x00:
        raise PaddingError("encoded message must start with 0x00")
    if em[1] != 0x02:
        raise PaddingError("encryption block type 0x02 expected")
    sep = em.find(b"\x00", 2)
    if sep < 0:
        raise PaddingError("no 0x00 separator after padding string")
    if sep - 2 < _MIN_PS:
        raise PaddingError(
            f"padding string must be at least {_MIN_PS} bytes, got {sep - 2}"
        )
    return em[sep + 1:]


def pad_sign(msg: bytes, k: int) -> bytes:
    """Encode *msg* as ``00 01 FF..FF 00 M`` in exactly *k* bytes."""
    _check_block_size(k)
    if len(msg) > k - 11:
        raise PaddingError(
            f"message of {len(msg)} bytes too long for {k}-byte modulus "
            f"(max {k - 11})"
        )
    return b"\x00\x01" + b"\xff" * (k - len(msg) - 3) + b"\x00" + msg


def unpad_sign(em: bytes) -> bytes:
    """Strictly validate the signature encoding and return ``M``."""
    if len(em) < 11:
        raise PaddingError("encoded message too short")
    if em[0] != 0x00 or em[1] != 0x01:
        raise PaddingError("signature block type 0x01 expected")
    sep = em.find(b"\x00", 2)
    if sep < 0:
        raise PaddingError("no 0x00 separator after padding string")
    if sep - 2 < _MIN_PS:
        raise PaddingError("padding string must be at least 8 bytes")
    if any(b != 0xFF for b in em[2:sep]):
        raise PaddingError("signature padding must be all 0xFF")
    return em[sep + 1:]


def _rng_or_default(rng: random.Random | None) -> random.Random:
    return rng if rng is not None else random.Random(_PAD_SEED)


def encrypt(
    pub: PublicKey, msg: bytes, rng: random.Random | None = None
) -> bytes:
    """Encrypt *msg* for *pub* with randomized PKCS-style padding."""
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    k = pub.byte_size
    em = pad_encrypt(bytes(msg), k, _rng_or_default(rng))
    m = int.from_bytes(em, "big")
    if m >= pub.n:
        raise PaddingError("message representative out of range")
    return _int_to_block(rsa_int(m, pub.e, pub.n), k)


def decrypt(priv: PrivateKey, ct: bytes) -> bytes:
    """Decrypt *ct* and strictly validate the recovered padding."""
    if not isinstance(ct, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    k = priv.byte_size
    ct = bytes(ct)
    if len(ct) != k:
        raise RSAError(
            f"ciphertext must be exactly {k} bytes, got {len(ct)}"
        )
    c = int.from_bytes(ct, "big")
    if c >= priv.n:
        raise RSAError("ciphertext representative out of range")
    m = rsa_int(c, priv.d, priv.n)
    return unpad_encrypt(_int_to_block(m, k))


def sign(priv: PrivateKey, msg: bytes) -> bytes:
    """Produce a PKCS-style signature over *msg*."""
    if not isinstance(msg, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    k = priv.byte_size
    em = pad_sign(bytes(msg), k)
    m = int.from_bytes(em, "big")
    if m >= priv.n:
        raise PaddingError("message representative out of range")
    return _int_to_block(rsa_int(m, priv.d, priv.n), k)


def verify(pub: PublicKey, msg: bytes, sig: bytes) -> bool:
    """Return ``True`` iff *sig* is a valid signature on *msg* under *pub*.

    Any structural problem (bad length, out-of-range block, malformed
    padding, wrong message) yields ``False`` — never an exception.
    """
    if not isinstance(msg, (bytes, bytearray)) or not isinstance(
        sig, (bytes, bytearray)
    ):
        return False
    k = pub.byte_size
    sig = bytes(sig)
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= pub.n:
        return False
    try:
        em = _int_to_block(rsa_int(s, pub.e, pub.n), k)
        recovered = unpad_sign(em)
    except (RSAError, PaddingError, ValueError):
        return False
    return recovered == bytes(msg)
