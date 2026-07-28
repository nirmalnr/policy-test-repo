# sign_manifest.py

Signs and verifies embedded JSON `signature` blocks, e.g. the `catalog.signature` /
`schema.signature` blocks in [`catalog-testing/node-manifest.json`](../catalog-testing/node-manifest.json).

The signed bytes are the target object, JCS-canonicalized (RFC 8785) with its own
`signature` field removed — canonicalization means re-serializing the file (pretty-printing,
key reordering) never breaks a signature. Signing uses Ed25519 directly over those canonical
bytes (no extra digest step). Keys are base64-encoded raw Ed25519 bytes (32-byte seed for the
private key, 32-byte point for the public key) — the same format beckn-onix's Signer plugin
uses for transaction signing, so a transaction key pair can be reused here.

## Setup

```
pip3 install -r tools/requirements.txt
cp tools/.env.example .env
```

Generate an Ed25519 key pair and fill in `.env` (`KEY_ID`, `PRIVATE_KEY`, `PUBLIC_KEY`):

```
python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64
priv = Ed25519PrivateKey.generate()
seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print('PRIVATE_KEY=' + base64.b64encode(seed).decode())
print('PUBLIC_KEY=' + base64.b64encode(pub).decode())
"
```

`.env` is gitignored (it holds `PRIVATE_KEY`); `tools/.env.example` is checked in as a template.

## Sign

```
python3 tools/sign_manifest.py sign --file catalog-testing/node-manifest.json --path catalog
python3 tools/sign_manifest.py sign --file catalog-testing/node-manifest.json --path schema
```

`--path` addresses the object to sign with dot- or slash-separated keys (`catalog`, `a.b.c`,
`/a/b/c`). `KEY_ID` and `PRIVATE_KEY` come from `.env` (override with `--env-file`).

`validUntil` defaults to 365 days from now (`--valid-days N` to change); or set it explicitly
with `--valid-until 2027-01-01T00:00:00Z`. Use `--dry-run` to print the computed signature block
without writing the file, and `--output PATH` to write elsewhere instead of overwriting `--file`.

## Verify

```
python3 tools/sign_manifest.py verify --file catalog-testing/node-manifest.json
```

With no `--path`, verify walks the whole document and checks every object that has a
`signature` block, printing OK/FAIL per path and exiting non-zero if any fail. Pass `--path`
to check a single object. `--json` prints machine-readable results.

Public keys for `keyId`s other than the one in `.env` are resolved from `--key-dir`
(default `keys/`) as `<keyId>.public.b64`.

Exit codes: `0` all checked signatures valid, `1` at least one invalid/expired, `2` usage error
(bad path, missing key material, etc).
