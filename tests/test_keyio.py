"""Key serialization tests: exact roundtrips and strict parse failures."""

from __future__ import annotations

import unittest

from keyio import (
    PRIVATE_BEGIN,
    PRIVATE_END,
    PUBLIC_BEGIN,
    PUBLIC_END,
    KeyFormatError,
    export_private,
    export_public,
    import_private,
    import_public,
)
from rsa import generate_keypair

PUB, PRIV = generate_keypair(512, seed=20260214)


class RoundtripTests(unittest.TestCase):

    def test_public_roundtrip_exact(self):
        text = export_public(PUB)
        self.assertTrue(text.startswith(PUBLIC_BEGIN + "\n"))
        self.assertTrue(text.rstrip().endswith(PUBLIC_END))
        self.assertEqual(import_public(text), PUB)

    def test_private_roundtrip_exact(self):
        text = export_private(PRIV)
        self.assertTrue(text.startswith(PRIVATE_BEGIN + "\n"))
        self.assertTrue(text.rstrip().endswith(PRIVATE_END))
        self.assertEqual(import_private(text), PRIV)

    def test_public_text_is_lowercase_hex_lines(self):
        lines = export_public(PUB).splitlines()
        self.assertEqual(lines[1], f"n={PUB.n:x}")
        self.assertEqual(lines[2], f"e={PUB.e:x}")


class ParseFailureTests(unittest.TestCase):

    def test_missing_header_rejected(self):
        text = export_public(PUB).replace(PUBLIC_BEGIN, "-----BEGIN X-----")
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_missing_footer_rejected(self):
        text = "\n".join(
            export_public(PUB).splitlines()[:-1]
        ) + "\n"
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_missing_field_rejected(self):
        text = "\n".join(
            line for line in export_public(PUB).splitlines()
            if not line.startswith("e=")
        ) + "\n"
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_extra_field_rejected(self):
        text = export_public(PUB).replace(
            PUBLIC_END, "x=ab\n" + PUBLIC_END
        )
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_duplicate_field_rejected(self):
        text = export_public(PUB).replace(
            f"e={PUB.e:x}", f"e={PUB.e:x}\ne={PUB.e:x}"
        )
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_non_hex_value_rejected(self):
        text = export_public(PUB).replace(f"n={PUB.n:x}", "n=zz12")
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_uppercase_hex_rejected(self):
        text = export_public(PUB).replace(f"e={PUB.e:x}", "e=A5")
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_malformed_line_rejected(self):
        text = export_public(PUB).replace(
            f"n={PUB.n:x}", f"n{PUB.n:x}"
        )
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_non_string_input_rejected(self):
        with self.assertRaises(KeyFormatError):
            import_public(b"binary")


class ConsistencyTests(unittest.TestCase):

    def test_even_modulus_rejected(self):
        text = export_public(PUB).replace(f"n={PUB.n:x}", f"n={PUB.n + 1:x}")
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_exponent_ge_modulus_rejected(self):
        # e >= n is rejected by import_public's validation.
        text = export_public(PUB).replace(f"e={PUB.e:x}", f"e={PUB.n:x}")
        with self.assertRaises(KeyFormatError):
            import_public(text)

    def test_inconsistent_factors_rejected(self):
        text = export_private(PRIV).replace(
            f"q={PRIV.q:x}", f"q={PRIV.q + 2:x}"
        )
        with self.assertRaises(KeyFormatError):
            import_private(text)

    def test_wrong_d_rejected(self):
        text = export_private(PRIV).replace(
            f"d={PRIV.d:x}", f"d={PRIV.d + 1:x}"
        )
        with self.assertRaises(KeyFormatError):
            import_private(text)

    def test_private_key_dataclass_roundtrip_keeps_public(self):
        priv = import_private(export_private(PRIV))
        self.assertEqual(priv.public, PUB)
        self.assertEqual(export_private(priv), export_private(PRIV))

    def test_imported_key_still_works(self):
        pub = import_public(export_public(PUB))
        priv = import_private(export_private(PRIV))
        from rsa import decrypt, encrypt
        import random

        msg = b"still works"
        ct = encrypt(pub, msg, rng=random.Random(1))
        self.assertEqual(decrypt(priv, ct), msg)


if __name__ == "__main__":
    unittest.main()
