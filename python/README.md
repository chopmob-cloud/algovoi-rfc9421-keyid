# algovoi-rfc9421-keyid

SSRF-guarded resolution of an RFC 9421 signature `keyid` to a raw 32-byte
Ed25519 public key, plus the inverse key-publication helpers. Companion to
[`algovoi-rfc9421-verifier`](https://pypi.org/project/algovoi-rfc9421-verifier/)
and [`algovoi-rfc9421-signer`](https://pypi.org/project/algovoi-rfc9421-signer/).

The verifier is a pure, offline function. Key resolution is a separate concern
because it does outbound network I/O, so it lives in its own package with its own
version and its own security surface.

## Key sources

- **inline** (`did:key:z...`): the key is encoded in the identifier itself, so no
  network call is made. This is the preferred, SSRF-safe path.
- **cache**: a caller-supplied cache is consulted before any fetch.
- **resolver**: an HTTPS GET of a `did:web:` DID or a plain `https` URL,
  accepting both a W3C `did.json` (Ed25519VerificationKey2020 / publicKeyMultibase
  / JWK) and the `{ "address", "public_key" }` shape.

## SSRF guard (resolver path)

- `https` only.
- Resolved addresses are checked against a non-public blocklist
  (private, loopback, link-local including cloud metadata, multicast, reserved).
- The actual connected peer IP is re-checked after connect, which defeats a DNS
  rebind between the check and the connection.
- Redirects are re-validated on every hop and capped.
- Response size and total time are capped.

## Install

```
pip install algovoi-rfc9421-keyid
```

`did:key`, `did:web`, hex, multibase, base64 and JWK key shapes are stdlib-only.
PEM public keys additionally need the optional extra:

```
pip install algovoi-rfc9421-keyid[pem]
```

## Usage

```python
from algovoi_rfc9421_keyid import resolve_keyid, encode_did_key

# inline, no network
r = resolve_keyid(encode_did_key(pub_bytes))
assert r.key_source == "inline"

# did:web, SSRF-guarded HTTPS resolution
r = resolve_keyid("did:web:api.example.com")
verify_key = r.public_key  # raw 32-byte Ed25519 key

# publish your own key (the inverse)
from algovoi_rfc9421_keyid import build_did_document, build_key_source
did_json = build_did_document("did:web:api.example.com", pub_bytes)
```

Apache-2.0.
