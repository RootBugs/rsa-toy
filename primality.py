"""Miller-Rabin primality testing and seeded prime generation.

The Miller-Rabin test writes ``n - 1 = d * 2^s`` with ``d`` odd, then checks
for a witness ``a`` such that ``a^d != 1 (mod n)`` and
``a^(d*2^r) != -1 (mod n)`` for all ``0 <= r < s``. Such an ``a`` proves ``n``
composite; passing for many independent bases makes it a strong pseudoprime.

Determinism: below ``DETERMINISTIC_LIMIT`` the first 13 primes are used as
bases, which is *proven* deterministic (no randomness involved). Above the
limit, ``rounds`` pseudorandom bases are drawn from the supplied
:class:`random.Random` — always seeded by the caller in this project.
"""

from __future__ import annotations

import random

__all__ = [
    "DETERMINISTIC_LIMIT",
    "is_probable_prime",
    "miller_rabin",
    "generate_prime",
    "small_primes",
]

# Product of the first 13 primes' witness sufficiency: every composite below
# this bound is detected by bases {2,3,...,41} (standard result).
DETERMINISTIC_LIMIT = 3_317_044_064_679_887_385_961_981

_DETERMINISTIC_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)

_DEFAULT_SEED = 0xC0FFEE

_SMALL_LIMIT = 1_000_000


def small_primes(limit: int = _SMALL_LIMIT) -> tuple[int, ...]:
    """Return all primes below *limit* via the sieve of Eratosthenes."""
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return tuple(i for i in range(limit) if sieve[i])


_PRIMES = small_primes(65536)
_PRIME_SET = frozenset(_PRIMES)


def miller_rabin(n: int, bases) -> bool:
    """Return ``False`` if some base in *bases* proves *n* composite.

    Does not handle ``n < 2``; callers filter first. A base divisible by *n*
    is skipped (it is not a witness).
    """
    if n < 2:
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in bases:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False  # a is a witness: n is composite
    return True


def _bases_for(n: int, rounds: int, rng: random.Random) -> tuple[int, ...]:
    if n < DETERMINISTIC_LIMIT:
        return _DETERMINISTIC_BASES
    return tuple(rng.randrange(2, n - 2) for _ in range(rounds))


def is_probable_prime(
    n: int, rounds: int = 40, rng: random.Random | None = None
) -> bool:
    """Decide whether *n* is prime.

    Below ``DETERMINISTIC_LIMIT`` the answer is mathematically certain.
    Above it, *rounds* random bases are used (error probability < 4^-rounds).
    When *rng* is omitted a fresh ``random.Random(_DEFAULT_SEED)`` is used, so
    the result is deterministic for a given *n*.
    """
    if n < 2:
        return False
    if n in _PRIME_SET:
        return True
    for p in _PRIMES:
        if n % p == 0:
            return False
    if rng is None:
        rng = random.Random(_DEFAULT_SEED)
    return miller_rabin(n, _bases_for(n, rounds, rng))


def generate_prime(bits: int, rng: random.Random) -> int:
    """Generate a prime with exactly *bits* bits using seeded *rng*.

    Candidates are odd, have their top bit set (so the size is exact) and are
    tested with :func:`is_probable_prime`. Raises ``ValueError`` for
    nonsensical sizes.
    """
    if bits < 3:
        raise ValueError("prime size must be at least 3 bits")
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rng=rng):
            return candidate
