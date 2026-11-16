"""Primality tests: known primes/composites, determinism, seeded generation."""

from __future__ import annotations

import random
import unittest

from primality import (
    DETERMINISTIC_LIMIT,
    generate_prime,
    is_probable_prime,
    miller_rabin,
    small_primes,
)


class MillerRabinClassificationTests(unittest.TestCase):

    def test_known_primes_are_prime(self):
        primes = [
            2, 3, 5, 7, 65537,
            2_147_483_647,          # 2^31 - 1, Mersenne prime
            2_305_843_009_213_693_951,  # 2^61 - 1, Mersenne prime
        ]
        for n in primes:
            self.assertTrue(is_probable_prime(n), n)

    def test_known_composites_are_composite(self):
        composites = [0, 1, -5, 4, 9, 15, 341, 561, 1105, 1729, 3277]
        for n in composites:
            self.assertFalse(is_probable_prime(n), n)

    def test_carmichael_numbers_rejected(self):
        # Carmichael numbers pass Fermat tests for every coprime base but
        # Miller-Rabin with multiple bases must still catch them.
        carmichael = [561, 1105, 1729, 2465, 2821, 6601, 8911, 15841]
        for n in carmichael:
            self.assertFalse(is_probable_prime(n), n)

    def test_even_numbers_and_small_factors(self):
        self.assertFalse(is_probable_prime(2 * (10**9 + 7)))
        self.assertFalse(is_probable_prime(1_000_003 * 2))

    def test_miller_rabin_direct_witness(self):
        # Base 2 proves 9 = 3^2 composite.
        self.assertFalse(miller_rabin(9, [2]))
        # A prime survives any single base.
        self.assertTrue(miller_rabin(1_000_003, [2]))
        self.assertTrue(miller_rabin(1_000_003, [2, 3, 5, 7]))

    def test_miller_rabin_rejects_n_below_two(self):
        self.assertFalse(miller_rabin(1, [2]))
        self.assertFalse(miller_rabin(-3, [2]))

    def test_deterministic_limit_value(self):
        self.assertEqual(DETERMINISTIC_LIMIT, 3_317_044_064_679_887_385_961_981)

    def test_large_composite_detected_with_seeded_rng(self):
        rng = random.Random(11)
        p = generate_prime(45, random.Random(1))
        q = generate_prime(45, random.Random(2))
        n = p * q  # > DETERMINISTIC_LIMIT, so random bases are drawn
        self.assertGreater(n, DETERMINISTIC_LIMIT)
        self.assertFalse(is_probable_prime(n, rng=random.Random(7)))
        self.assertFalse(is_probable_prime(n, rng=random.Random(7)))


class PrimeGenerationTests(unittest.TestCase):

    def test_generated_prime_has_exact_bit_length(self):
        p = generate_prime(64, random.Random(3))
        self.assertEqual(p.bit_length(), 64)
        self.assertTrue(is_probable_prime(p))

    def test_generation_is_deterministic_for_seed(self):
        a = generate_prime(48, random.Random(123))
        b = generate_prime(48, random.Random(123))
        self.assertEqual(a, b)

    def test_different_seeds_usually_differ(self):
        a = generate_prime(64, random.Random(1))
        b = generate_prime(64, random.Random(2))
        self.assertNotEqual(a, b)

    def test_tiny_prime_size_rejected(self):
        with self.assertRaises(ValueError):
            generate_prime(2, random.Random(0))


class SmallPrimesTests(unittest.TestCase):

    def test_sieve_prefix(self):
        self.assertEqual(
            small_primes(50),
            (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47),
        )

    def test_sieve_count_under_100(self):
        self.assertEqual(len(small_primes(100)), 25)


if __name__ == "__main__":
    unittest.main()
