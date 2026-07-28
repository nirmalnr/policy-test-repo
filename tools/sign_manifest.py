#!/usr/bin/env python3
"""Sign/verify embedded JSON signature blocks using Ed25519 over JCS-canonicalized (RFC 8785) content.

Signature blocks look like: {"keyId": "...", "value": "<base64 sig>", "validUntil": "<ISO8601>"}
and sit as a sibling "signature" key inside the object they cover. The signed bytes are the
JCS canonicalization of that object with its own "signature" key removed.

Keys are Ed25519, base64-encoded raw bytes (32-byte seed for private, 32-byte point for public) --
the same format beckn-onix's Signer plugin uses for transaction signing, so the same key pair can
be reused here.
"""
import argparse
import base64
import json
import sys
from datetime import datetime, timedelta, timezone

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ToolError(Exception):
    """Raised for user-facing errors (bad path, missing key, etc)."""


def load_env(path):
    env = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return env


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def resolve_pointer(root, pointer):
    if pointer in ("", ".", "/"):
        return root
    segments = [s for s in pointer.replace("/", ".").split(".") if s]
    node = root
    walked = []
    for segment in segments:
        if not isinstance(node, dict) or segment not in node:
            available = list(node.keys()) if isinstance(node, dict) else []
            raise ToolError(
                f"path segment '{segment}' not found under '{'.'.join(walked) or '<root>'}' "
                f"(available keys: {available})"
            )
        node = node[segment]
        walked.append(segment)
    if not isinstance(node, dict):
        raise ToolError(f"path '{pointer}' does not resolve to an object")
    return node


def find_all_signed_objects(root, prefix=""):
    results = []
    if isinstance(root, dict):
        if "signature" in root:
            results.append((prefix or ".", root))
        for key, value in root.items():
            if key == "signature":
                continue
            child_prefix = f"{prefix}.{key}" if prefix else key
            results.extend(find_all_signed_objects(value, child_prefix))
    elif isinstance(root, list):
        for index, item in enumerate(root):
            results.extend(find_all_signed_objects(item, f"{prefix}[{index}]"))
    return results


def strip_signature(obj):
    return {k: v for k, v in obj.items() if k != "signature"}


def canonicalize(obj):
    return jcs.canonicalize(obj)


def private_key_from_b64(seed_b64):
    try:
        seed = base64.b64decode(seed_b64, validate=True)
    except Exception as e:
        raise ToolError(f"PRIVATE_KEY is not valid base64: {e}")
    if len(seed) != 32:
        raise ToolError(f"PRIVATE_KEY must decode to 32 bytes (got {len(seed)})")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_from_b64(pub_b64):
    try:
        pub = base64.b64decode(pub_b64, validate=True)
    except Exception as e:
        raise ToolError(f"public key is not valid base64: {e}")
    if len(pub) != 32:
        raise ToolError(f"public key must decode to 32 bytes (got {len(pub)})")
    return Ed25519PublicKey.from_public_bytes(pub)


def compute_valid_until(args):
    if args.valid_until:
        return args.valid_until
    days = args.valid_days if args.valid_days is not None else 365
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime(DATE_FMT)


def resolve_public_key(key_id, env, key_dir):
    if key_id == env.get("KEY_ID"):
        if env.get("PUBLIC_KEY"):
            return public_key_from_b64(env["PUBLIC_KEY"])
        if env.get("PRIVATE_KEY"):
            return private_key_from_b64(env["PRIVATE_KEY"]).public_key()
    key_path = f"{key_dir.rstrip('/')}/{key_id}.public.b64"
    try:
        with open(key_path, "r") as f:
            return public_key_from_b64(f.read().strip())
    except FileNotFoundError:
        raise ToolError(
            f"no public key available for keyId '{key_id}' "
            f"(checked .env and '{key_path}')"
        )


def cmd_sign(args):
    env = load_env(args.env_file)
    key_id = env.get("KEY_ID")
    private_key_b64 = env.get("PRIVATE_KEY")
    if not key_id or not private_key_b64:
        raise ToolError(f"KEY_ID and PRIVATE_KEY must be set in '{args.env_file}'")

    data = load_json(args.file)
    target = resolve_pointer(data, args.path)

    canonical = canonicalize(strip_signature(target))
    private_key = private_key_from_b64(private_key_b64)
    signature = private_key.sign(canonical)

    target["signature"] = {
        "keyId": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
        "validUntil": compute_valid_until(args),
    }

    if args.dry_run:
        print(json.dumps(target["signature"], indent=2))
        return 0

    save_json(args.output or args.file, data)
    print(f"signed '{args.path}' with keyId '{key_id}'")
    return 0


def verify_one(pointer, obj, env, key_dir, now):
    signature_block = obj.get("signature")
    if not signature_block:
        return pointer, False, "missing signature block"

    key_id = signature_block.get("keyId")
    value = signature_block.get("value")
    valid_until = signature_block.get("validUntil")
    if not key_id or not value:
        return pointer, False, "signature block missing keyId/value"

    try:
        public_key = resolve_public_key(key_id, env, key_dir)
        signature = base64.b64decode(value, validate=True)
        canonical = canonicalize(strip_signature(obj))
        public_key.verify(signature, canonical)
    except InvalidSignature:
        return pointer, False, "signature invalid"
    except ToolError as e:
        return pointer, False, str(e)

    if valid_until:
        try:
            expiry = datetime.strptime(valid_until, DATE_FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            return pointer, False, f"unparseable validUntil '{valid_until}'"
        if now > expiry:
            return pointer, False, f"expired (validUntil {valid_until})"

    return pointer, True, "OK"


def cmd_verify(args):
    env = load_env(args.env_file)
    data = load_json(args.file)
    now = (
        datetime.strptime(args.now, DATE_FMT).replace(tzinfo=timezone.utc)
        if args.now
        else datetime.now(timezone.utc)
    )

    if args.path:
        targets = [(args.path, resolve_pointer(data, args.path))]
    else:
        targets = find_all_signed_objects(data)
        if not targets:
            raise ToolError("no signature blocks found in document")

    results = [verify_one(pointer, obj, env, args.key_dir, now) for pointer, obj in targets]

    if args.json:
        print(json.dumps(
            [{"path": p, "valid": ok, "reason": reason} for p, ok, reason in results],
            indent=2,
        ))
    else:
        for pointer, ok, reason in results:
            print(f"{'OK  ' if ok else 'FAIL'} {pointer}: {reason}")

    return 0 if all(ok for _, ok, _ in results) else 1


def build_arg_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sign_parser = sub.add_parser("sign", help="sign an object with a signature block")
    sign_parser.add_argument("--file", required=True)
    sign_parser.add_argument("--path", required=True)
    sign_parser.add_argument("--env-file", default=".env")
    validity = sign_parser.add_mutually_exclusive_group()
    validity.add_argument("--valid-days", type=int)
    validity.add_argument("--valid-until")
    sign_parser.add_argument("--output")
    sign_parser.add_argument("--dry-run", action="store_true")
    sign_parser.set_defaults(func=cmd_sign)

    verify_parser = sub.add_parser("verify", help="verify signature block(s)")
    verify_parser.add_argument("--file", required=True)
    verify_parser.add_argument("--path")
    verify_parser.add_argument("--env-file", default=".env")
    verify_parser.add_argument("--key-dir", default="keys")
    verify_parser.add_argument("--now")
    verify_parser.add_argument("--json", action="store_true")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
