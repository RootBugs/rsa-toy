# rsa-toy — RSA from Scratch

Textbook RSA made inspectable: **Miller-Rabin prime generation**, keypair
generation with an explicit `gcd` check, **PKCS#1 v1.5-style padding** for
both encryption and signatures, strict padding validation on decrypt, and a
PEM-ish key format of our own. Every number is visible; nothing is hidden
behind a library.

## Why it's special

- **Hand-computable vectors are asserted exactly.** The classic
  `p=61, q=53, n=3233, e=17, d=2753` example is asserted to produce
  `65^17 mod 3233 = 2790`.
- **Strict padding, no oracle games.** `decrypt` validates *every* field of
  `00 02 PS 00 M` — leading `0x00`, block type `0x02`, separator, and a
  padding string of at least 8 non-zero bytes — and raises `PaddingError`
  with a precise reason for each failure mode.
- **Deterministic everywhere.** Keygen, prime generation and padding all take
  seeded `random.Random` instances (or fixed default seeds), so the whole
  suite runs identically on every machine.
- **Miller-Rabin done honestly**: proven-deterministic bases below
  `3.317e24`, seeded random bases above it; Carmichael numbers
  (561, 1105, 1729, …) are asserted to be *rejected*.

## Architecture

| Module | Responsibility |
|---|---|
| `primality.py` | Sieve, Miller-Rabin witnesses, seeded `generate_prime(bits, rng)` |
| `rsa.py` | `PublicKey`/`PrivateKey`, keygen, pad/unpad, encrypt/decrypt/sign/verify |
| `keyio.py` | PEM-ish export/import with strict field validation (`KeyFormatError`) |
| `cli.py` | `keygen`, `encrypt`, `decrypt`, `sign`, `verify` over files |

Key file format (own documented format, not OpenSSL-compatible):

```
-----BEGIN OSS-RSA PUBLIC KEY-----
n=<hex modulus>
e=<hex exponent>
-----END OSS-RSA PUBLIC KEY-----
```

## Runnable example

```console
$ python -c "
from rsa import generate_keypair, encrypt, decrypt, sign, verify
from keyio import export_private, import_private
import random
pub, priv = generate_keypair(512, seed=42)
msg = b'Meet me at dawn'
ct = encrypt(pub, msg, rng=random.Random(1))
print('n    =', hex(pub.n)[:34] + '...')
print('ct   =', ct.hex()[:48] + '...')
print('pt   =', decrypt(priv, ct))
sig = sign(priv, msg)
print('verify:', verify(pub, msg, sig))
print('tamper:', verify(pub, b'Meet me at dusk', sig))
key2 = import_private(export_private(priv))
print('reimport works:', decrypt(key2, ct))
"
n    = 0x7ba9bbc9fe9339ce7bbf817b5b3e68aa...
ct   = 0893ae88e8759b7735fbf86cf02ea2d75d89e89007995a94...
pt   = b'Meet me at dawn'
verify: True
tamper: False
reimport works: b'Meet me at dawn'
```

CLI session:

```console
$ python cli.py keygen --bits 512 --seed 42 --out kp
keygen: 512-bit modulus, n=7ba9bbc9fe9339ce...
$ python cli.py encrypt --pub kp.pub --in note.txt --out note.enc
encrypted 15 bytes -> note.enc
$ python cli.py verify --pub kp.pub --in note.txt --sig note.sig
VALID
```

## Tests

```console
python -m unittest discover -s tests -v
```

72 tests: the hand-computed small-key vector, keygen consistency
(`gcd(e, phi) == 1`, `e*d ≡ 1 mod phi`), encrypt/decrypt and sign/verify
roundtrips, rejection of malformed padding (four crafted ciphertext
classes), wrong-key and tampered-signature verification failures,
Miller-Rabin classification of known primes/composites/Carmichael numbers,
key serialization roundtrip plus 10 strict parse-failure cases, and CLI
end-to-end flows over real temp files.
