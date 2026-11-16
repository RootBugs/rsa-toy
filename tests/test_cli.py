"""CLI tests: keygen/encrypt/decrypt/sign/verify over real temp files."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import cli


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.prefix = str(self.dir / "kp")
        code, out, _ = _run(
            ["keygen", "--bits", "512", "--seed", "42", "--out", self.prefix]
        )
        self.assertEqual(code, 0, out)
        self.pub = self.prefix + ".pub"
        self.key = self.prefix + ".key"

    def test_keygen_writes_key_files(self):
        pub_text = Path(self.pub).read_text(encoding="ascii")
        key_text = Path(self.key).read_text(encoding="ascii")
        self.assertIn("-----BEGIN OSS-RSA PUBLIC KEY-----", pub_text)
        self.assertIn("-----BEGIN OSS-RSA PRIVATE KEY-----", key_text)
        self.assertIn("d=", key_text)

    def test_keygen_is_deterministic_with_seed(self):
        other = str(self.dir / "kp2")
        _run(["keygen", "--bits", "512", "--seed", "42", "--out", other])
        self.assertEqual(
            Path(self.pub).read_text(encoding="ascii"),
            Path(other + ".pub").read_text(encoding="ascii"),
        )

    def test_encrypt_decrypt_file_roundtrip(self):
        plain = self.dir / "note.txt"
        plain.write_bytes(b"attack at dawn, not at dusk")
        enc = self.dir / "note.enc"
        dec = self.dir / "note.out"

        code, out, _ = _run(
            ["encrypt", "--pub", self.pub, "--in", str(plain), "--out", str(enc)]
        )
        self.assertEqual(code, 0, out)
        self.assertNotEqual(enc.read_bytes(), plain.read_bytes())

        code, out, _ = _run(
            ["decrypt", "--key", self.key, "--in", str(enc), "--out", str(dec)]
        )
        self.assertEqual(code, 0, out)
        self.assertEqual(dec.read_bytes(), plain.read_bytes())

    def test_sign_verify_valid(self):
        msg = self.dir / "msg.bin"
        msg.write_bytes(b"release v1.0")
        sig = self.dir / "msg.sig"
        code, out, _ = _run(
            ["sign", "--key", self.key, "--in", str(msg), "--out", str(sig)]
        )
        self.assertEqual(code, 0, out)
        code, out, _ = _run(
            ["verify", "--pub", self.pub, "--in", str(msg), "--sig", str(sig)]
        )
        self.assertEqual(code, 0)
        self.assertIn("VALID", out)

    def test_verify_rejects_tampered_message(self):
        msg = self.dir / "msg.bin"
        msg.write_bytes(b"release v1.0")
        sig = self.dir / "msg.sig"
        _run(["sign", "--key", self.key, "--in", str(msg), "--out", str(sig)])
        msg.write_bytes(b"release v9.9")
        code, out, _ = _run(
            ["verify", "--pub", self.pub, "--in", str(msg), "--sig", str(sig)]
        )
        self.assertEqual(code, 1)
        self.assertIn("INVALID", out)

    def test_decrypt_garbage_reports_error(self):
        bad = self.dir / "garbage.bin"
        bad.write_bytes(b"not an rsa block at all")
        outp = self.dir / "out.bin"
        code, _, err = _run(
            ["decrypt", "--key", self.key, "--in", str(bad), "--out", str(outp)]
        )
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_missing_input_file_reports_error(self):
        outp = self.dir / "out.bin"
        code, _, err = _run(
            [
                "encrypt",
                "--pub", self.pub,
                "--in", str(self.dir / "absent.txt"),
                "--out", str(outp),
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_verify_missing_signature_reports_error(self):
        msg = self.dir / "msg.bin"
        msg.write_bytes(b"data")
        code, _, err = _run(
            [
                "verify",
                "--pub", self.pub,
                "--in", str(msg),
                "--sig", str(self.dir / "absent.sig"),
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
