"""
algovoi-rfc9421-keyid -- resolve an RFC 9421 signature `keyid` to a raw 32-byte
Ed25519 public key, and the inverse key-publication helpers.

Three key sources:
- inline   : `did:key:z...` (no network; SSRF-safe by construction, preferred)
- cache    : a caller-supplied cache is consulted before any fetch
- resolver : an HTTPS GET of a `did:web:` DID or a plain https URL, accepting
             both a W3C did.json and the `{ "address", "public_key" }` shape

The resolver path is SSRF-guarded: https only, resolved addresses checked
against a non-public blocklist, the connected peer IP re-checked after connect
(DNS-rebind defence), redirects re-validated and capped, and size/time caps.

Only the standard library is required. PEM `public_key` values additionally need
the optional `cryptography` extra (`pip install algovoi-rfc9421-keyid[pem]`).

Apache-2.0. Companion to algovoi-rfc9421-verifier and algovoi-rfc9421-signer.
"""

from algovoi_rfc9421_keyid.resolver import (
    KeyResolutionError,
    SSRFError,
    ResolvedKey,
    resolve_keyid,
    encode_did_key,
    ed25519_multibase,
    build_did_document,
    build_key_source,
    check_ip_allowed,
)

__version__ = "0.1.0"

__all__ = [
    "KeyResolutionError",
    "SSRFError",
    "ResolvedKey",
    "resolve_keyid",
    "encode_did_key",
    "ed25519_multibase",
    "build_did_document",
    "build_key_source",
    "check_ip_allowed",
]
