"""CLI for rsa-toy: keygen, encrypt, decrypt, sign, verify.

Key files use the PEM-ish text format from :mod:`keyio`. Example session::

    python cli.py keygen --bits 512 --seed 42 --out kp
    python cli.py encrypt --pub kp.pub --in note.txt --out note.enc
    python cli.py decrypt --key kp.key --in note.enc --out note.out
    python cli.py sign --key kp.key --in note.txt --out note.sig
    python cli.py verify --pub kp.pub --in note.txt --sig note.sig
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from keyio import export_private, export_public, import_private, import_public
from rsa import RSAError, decrypt, encrypt, generate_keypair, sign, verify

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rsa-toy",
        description="Textbook RSA with PKCS#1 v1.5-style padding.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_kg = sub.add_parser("keygen", help="generate a keypair")
    p_kg.add_argument("--bits", type=int, default=512)
    p_kg.add_argument("--seed", type=int, default=None)
    p_kg.add_argument("--out", required=True, metavar="PREFIX",
                      help="write PREFIX.pub and PREFIX.key")

    for name, help_ in (
        ("encrypt", "encrypt a file under the public key"),
        ("decrypt", "decrypt a file with the private key"),
        ("sign", "sign a file with the private key"),
    ):
        p = sub.add_parser(name, help=help_)
        key_flag = "--pub" if name == "encrypt" else "--key"
        p.add_argument(key_flag, required=True, metavar="FILE")
        p.add_argument("--in", dest="inp", required=True, metavar="FILE")
        p.add_argument("--out", dest="outp", required=True, metavar="FILE")

    p_v = sub.add_parser("verify", help="verify a signature")
    p_v.add_argument("--pub", required=True, metavar="FILE")
    p_v.add_argument("--in", dest="inp", required=True, metavar="FILE")
    p_v.add_argument("--sig", required=True, metavar="FILE")

    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            pub, priv = generate_keypair(bits=args.bits, seed=args.seed)
            Path(f"{args.out}.pub").write_text(export_public(pub), encoding="ascii")
            Path(f"{args.out}.key").write_text(
                export_private(priv), encoding="ascii"
            )
            print(f"keygen: {args.bits}-bit modulus, n={pub.n:x}")
            return 0

        if args.command == "encrypt":
            pub = import_public(Path(args.pub).read_text(encoding="ascii"))
            data = Path(args.inp).read_bytes()
            Path(args.outp).write_bytes(encrypt(pub, data))
            print(f"encrypted {len(data)} bytes -> {args.outp}")
            return 0

        if args.command == "decrypt":
            priv = import_private(Path(args.key).read_text(encoding="ascii"))
            data = Path(args.inp).read_bytes()
            Path(args.outp).write_bytes(decrypt(priv, data))
            print(f"decrypted {len(data)} bytes -> {args.outp}")
            return 0

        if args.command == "sign":
            priv = import_private(Path(args.key).read_text(encoding="ascii"))
            data = Path(args.inp).read_bytes()
            Path(args.outp).write_bytes(sign(priv, data))
            print(f"signed {len(data)} bytes -> {args.outp}")
            return 0

        # verify
        pub = import_public(Path(args.pub).read_text(encoding="ascii"))
        data = Path(args.inp).read_bytes()
        sig = Path(args.sig).read_bytes()
        if verify(pub, data, sig):
            print("VALID")
            return 0
        print("INVALID")
        return 1
    except (RSAError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
