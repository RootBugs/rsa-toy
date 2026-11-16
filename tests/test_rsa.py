"""RSA core tests: known vector, roundtrips, padding rejection, verification."""

from __future__ import annotations

import math
import random
import unittest

from rsa import (
    DEFAULT_EXPONENT,
    PaddingError,
    PrivateKey,
    PublicKey,
    RSAError,
    decrypt,
    encrypt,
    generate_keypair,
    pad_encrypt,
    pad_sign,
    rsa_int,
    sign,
    unpad_encrypt,
    unpad_sign,
    verify,
)

# Classic textbook example: p=61, q=53, n=3233, phi=3120, e=17, d=2753.
SMALL_N, SMALL_E, SMALL_D = 3233, 17, 2753

# One shared 512-bit key for roundtrip tests (generated once, seeded).
PUB, PRIV = generate_keypair(512, seed=20260214)
K = PUB.byte_size  # 64


class KnownVectorTests(unittest.TestCase):

    def test_textbook_small_key_encrypt(self):
        # Hand-computed: 65^17 mod 3233 = 2790.
        self.assertEqual(rsa_int(65, SMALL_E, SMALL_N), 2790)

    def test_textbook_small_key_decrypt(self):
        self.assertEqual(rsa_int(2790, SMALL_D, SMALL_N), 65)

    def test_rsa_int_rejects_out_of_range(self):
        with self.assertRaises(RSAError):
            rsa_int(SMALL_N, SMALL_E, SMALL_N)
        with self.assertRaises(RSAError):
            rsa_int(-1, SMALL_E, SMALL_N)


class KeygenTests(unittest.TestCase):

    def test_keypair_consistency(self):
        self.assertEqual(PRIV.n, PUB.n)
        self.assertEqual(PRIV.e, PUB.e)
        self.assertEqual(PRIV.p * PRIV.q, PUB.n)
        phi = (PRIV.p - 1) * (PRIV.q - 1)
        self.assertEqual(math.gcd(PUB.e, phi), 1)
        self.assertEqual((PUB.e * PRIV.d) % phi, 1)
        self.assertEqual(PUB.e, DEFAULT_EXPONENT)

    def test_seeded_keygen_is_deterministic(self):
        a = generate_keypair(256, seed=77)
        b = generate_keypair(256, seed=77)
        self.assertEqual(a, b)

    def test_byte_size_matches_modulus(self):
        self.assertEqual(K, (PUB.n.bit_length() + 7) // 8)
        self.assertEqual(K, 64)

    def test_tiny_modulus_rejected(self):
        with self.assertRaises(ValueError):
            generate_keypair(8, seed=1)

    def test_even_exponent_rejected(self):
        with self.assertRaises(ValueError):
            generate_keypair(256, seed=1, exponent=65536)


class PaddingTests(unittest.TestCase):

    def test_pad_encrypt_shape(self):
        em = pad_encrypt(b"hi", 64, random.Random(5))
        self.assertEqual(len(em), 64)
        self.assertEqual(em[:2], b"\x00\x02")
        sep = em.find(b"\x00", 2)
        self.assertGreaterEqual(sep - 2, 8)
        self.assertNotIn(b"\x00", em[2:sep])
        self.assertEqual(em[sep + 1:], b"hi")

    def test_pad_encrypt_is_seed_deterministic(self):
        a = pad_encrypt(b"data", 64, random.Random(9))
        b = pad_encrypt(b"data", 64, random.Random(9))
        c = pad_encrypt(b"data", 64, random.Random(10))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_pad_sign_shape(self):
        em = pad_sign(b"msg", 64)
        self.assertEqual(len(em), 64)
        self.assertEqual(em[:2], b"\x00\x01")
        sep = em.find(b"\x00", 2)
        self.assertGreaterEqual(sep - 2, 8)
        self.assertTrue(all(b == 0xFF for b in em[2:sep]))
        self.assertEqual(em[sep + 1:], b"msg")

    def test_unpad_encrypt_rejects_bad_header(self):
        with self.assertRaises(PaddingError):
            unpad_encrypt(b"\x00\x01" + b"\xff" * 60 + b"\x00m")
        with self.assertRaises(PaddingError):
            unpad_encrypt(b"\x01\x02" + b"\xff" * 60 + b"\x00m")

    def test_unpad_encrypt_rejects_missing_separator(self):
        with self.assertRaises(PaddingError):
            unpad_encrypt(b"\x00\x02" + b"\x01" * 62)

    def test_unpad_encrypt_rejects_short_padding_string(self):
        # Separator after only 4 PS bytes (< 8 required).
        em = b"\x00\x02" + b"\x01" * 4 + b"\x00" + b"abcdef" + b"\x11" * 50
        with self.assertRaises(PaddingError):
            unpad_encrypt(em[:64])

    def test_unpad_encrypt_rejects_truncated_input(self):
        with self.assertRaises(PaddingError):
            unpad_encrypt(b"\x00\x02\x01")

    def test_unpad_sign_rejects_ff_violation(self):
        em = b"\x00\x01" + b"\xff" * 8 + b"\x01" + b"\xff" * 40 + b"\x00m"
        with self.assertRaises(PaddingError):
            unpad_sign(em[:64])


class EncryptDecryptTests(unittest.TestCase):

    def test_roundtrip_various_messages(self):
        messages = [
            b"",
            b"x",
            b"hello world",
            b"A" * (K - 11),  # maximum legal size
            bytes(range(50)),
        ]
        for i, msg in enumerate(messages):
            ct = encrypt(PUB, msg, rng=random.Random(100 + i))
            self.assertEqual(len(ct), K)
            self.assertEqual(decrypt(PRIV, ct), msg, msg)

    def test_padding_is_randomized(self):
        a = encrypt(PUB, b"same", rng=random.Random(1))
        b = encrypt(PUB, b"same", rng=random.Random(2))
        self.assertNotEqual(a, b)
        self.assertEqual(decrypt(PRIV, a), b"same")
        self.assertEqual(decrypt(PRIV, b), b"same")

    def test_message_too_long_rejected(self):
        with self.assertRaises(PaddingError):
            encrypt(PUB, b"A" * (K - 10), rng=random.Random(1))

    def test_decrypt_rejects_wrong_length(self):
        ct = encrypt(PUB, b"abc", rng=random.Random(1))
        with self.assertRaises(RSAError):
            decrypt(PRIV, ct[:-1])
        with self.assertRaises(RSAError):
            decrypt(PRIV, ct + b"\x00")

    def test_decrypt_rejects_representative_ge_n(self):
        with self.assertRaises(RSAError):
            decrypt(PRIV, b"\xff" * K)

    def test_decrypt_rejects_malformed_padding(self):
        """Crafted ciphertexts whose plaintext fails strict PKCS validation."""
        cases = [
            b"\x00\x01" + b"\xff" * 62,          # wrong block type
            b"\x00\x02" + b"\x01" * 62,          # no 0x00 separator
            b"\x02\x02" + b"\x01" * 62,          # missing leading 0x00
            b"\x00\x03" + b"\x01" * 62,          # bad block type byte
        ]
        for em in cases:
            m = int.from_bytes(em, "big")
            if m >= PUB.n:
                continue
            ct = rsa_int(m, PUB.e, PUB.n).to_bytes(K, "big")
            with self.assertRaises(PaddingError, msg=em[:4]):
                decrypt(PRIV, ct)

    def test_decrypt_rejects_short_ps_via_crafted_block(self):
        em = b"\x00\x02" + b"\x01" * 7 + b"\x00" + b"m" + b"\x11" * (K - 11)
        m = int.from_bytes(em[:K], "big")
        ct = rsa_int(m, PUB.e, PUB.n).to_bytes(K, "big")
        with self.assertRaises(PaddingError):
            decrypt(PRIV, ct)

    def test_encrypt_type_check(self):
        with self.assertRaises(TypeError):
            encrypt(PUB, "not bytes", rng=random.Random(1))
        with self.assertRaises(TypeError):
            decrypt(PRIV, "not bytes")


class SignVerifyTests(unittest.TestCase):

    def test_sign_verify_roundtrip(self):
        msg = b"the quick brown fox"
        sig = sign(PRIV, msg)
        self.assertEqual(len(sig), K)
        self.assertTrue(verify(PUB, msg, sig))

    def test_verify_wrong_message_fails(self):
        sig = sign(PRIV, b"original")
        self.assertFalse(verify(PUB, b"originaL", sig))

    def test_verify_wrong_key_fails(self):
        other_pub, _ = generate_keypair(512, seed=999)
        sig = sign(PRIV, b"payload")
        self.assertFalse(verify(other_pub, b"payload", sig))

    def test_verify_tampered_signature_fails(self):
        sig = bytearray(sign(PRIV, b"payload"))
        sig[10] ^= 0x01
        self.assertFalse(verify(PUB, b"payload", bytes(sig)))

    def test_verify_bad_signature_length_fails(self):
        sig = sign(PRIV, b"payload")
        self.assertFalse(verify(PUB, b"payload", sig[:-1]))

    def test_verify_signature_ge_n_fails(self):
        self.assertFalse(verify(PUB, b"payload", b"\xff" * K))

    def test_verify_rejects_encryption_padded_block(self):
        """A 00 02-style block must never verify as a signature."""
        em = pad_encrypt(b"payload", K, random.Random(3))
        m = int.from_bytes(em, "big")
        if m < PRIV.n:
            sig = rsa_int(m, PRIV.d, PRIV.n).to_bytes(K, "big")
            self.assertFalse(verify(PUB, b"payload", sig))

    def test_verify_type_errors_return_false(self):
        self.assertFalse(verify(PUB, "str", b"\x00" * K))
        self.assertFalse(verify(PUB, b"m", "str"))


if __name__ == "__main__":
    unittest.main()
