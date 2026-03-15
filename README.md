# HMAC Signing Library

[![CI](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/ci.yml)
[![Tests](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/tests.yml/badge.svg)](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/CompliantInnovation/docspera-hmac-signing-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/CompliantInnovation/docspera-hmac-signing-lib)
[![Release](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/release.yml/badge.svg)](https://github.com/CompliantInnovation/docspera-hmac-signing-lib/actions/workflows/release.yml)
[![PyPI version](https://badge.fury.io/py/docspera-hmac-signing-lib.svg)](https://badge.fury.io/py/docspera-hmac-signing-lib)
[![Python versions](https://img.shields.io/pypi/pyversions/docspera-hmac-signing-lib.svg)](https://pypi.org/project/docspera-hmac-signing-lib/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python library for signing and verifying HTTP webhook requests between systems. Supports HMAC (symmetric) and asymmetric (Ed25519/RSA) signing with built-in key rotation support.

## Installation

```bash
pip install -e .
```

Or add to your `requirements.txt`:
```
git+https://github.com/your-org/docspera-hmac-signing-lib.git
```

## Features

- **HMAC Signing** - Sign requests with a shared secret key
- **Asymmetric Signing** - Sign with private key, verify with public key (Ed25519 or RSA)
- **Key Rotation** - Support multiple valid keys simultaneously for zero-downtime rotation
- **Timestamp Validation** - Prevent replay attacks with configurable time windows
- **Thread-Safe** - Key manager is safe for concurrent use

## Quick Start

### HMAC Signing (Shared Secret)

**Client - Sign a request:**
```python
from hmac_lib import create_signed_request
import requests

body = '{"event": "order.created", "data": {"id": 123}}'

headers = create_signed_request(
    body=body,
    secret_key="your-shared-secret",
    credential="your-api-key",
    method="POST",
    path="/webhook",
)

response = requests.post(
    "https://api.example.com/webhook",
    data=body,
    headers=headers,
)
```

**Server - Verify a request (AWS Lambda / API Gateway):**
```python
from hmac_lib import validate_hmac_signature

def lambda_handler(event, context):
    result = validate_hmac_signature(event, secret_key="your-shared-secret")

    if result is not True:
        return result  # Returns {"statusCode": 401, "body": "..."}

    # Process the valid request
    return {"statusCode": 200, "body": "OK"}
```

**Server - Verify a request (generic):**
```python
from hmac_lib import verify_hmac_signature

is_valid, error = verify_hmac_signature(
    body=request.body,
    secret_key="your-shared-secret",
    auth_header=request.headers["Authorization"],
    headers=dict(request.headers),
    method="POST",
    path="/webhook",
)

if not is_valid:
    return Response(status=401, body=f"Unauthorized: {error}")
```

### Asymmetric Signing (Public/Private Keys)

Use asymmetric signing when you want to:
- Share only the public key with the verifying party
- Prove the sender's identity (non-repudiation)
- Avoid sharing secrets between systems

**Generate keys (do once, store securely):**
```python
from hmac_lib import generate_key_pair, KeyType

# Ed25519 (recommended - fast, small keys)
private_key, public_key = generate_key_pair(KeyType.ED25519)

# Or RSA (for legacy compatibility)
private_key, public_key = generate_key_pair(KeyType.RSA, key_size=2048)

# Save keys to files
with open("private_key.pem", "wb") as f:
    f.write(private_key)
with open("public_key.pem", "wb") as f:
    f.write(public_key)
```

**Client - Sign with private key:**
```python
from hmac_lib import create_signed_request_asymmetric, KeyType

with open("private_key.pem", "rb") as f:
    private_key = f.read()

body = '{"event": "order.created"}'

headers = create_signed_request_asymmetric(
    body=body,
    private_key_pem=private_key,
    key_id="client-key-v1",  # Required - identifies which key was used
    key_type=KeyType.ED25519,
    method="POST",
    path="/webhook",
)
```

**Server - Verify with public key:**
```python
from hmac_lib import verify_asymmetric_signature, parse_asymmetric_header

with open("client_public_key.pem", "rb") as f:
    public_key = f.read()

# Parse the Authorization header
auth_type, params = parse_asymmetric_header(request.headers["Authorization"])

# Extract signed headers
signed_headers = {}
for name in params["signed_headers"].split(";"):
    signed_headers[name] = request.headers.get(name)

# Verify
is_valid, error = verify_asymmetric_signature(
    body=request.body,
    public_key_pem=public_key,
    signature=params["signature"],
    key_type=params["key_type"],
    headers_to_sign=signed_headers,
    method="POST",
    path="/webhook",
)
```

### Key Rotation with KeyManager

The `KeyManager` class handles multiple keys for seamless rotation:

```python
from hmac_lib import KeyManager, SigningMethod

km = KeyManager()

# Phase 1: Add initial key
km.add_hmac_key("v1", "secret-key-v1")

# Phase 2: Add new key (both valid for verification)
km.add_hmac_key("v2", "secret-key-v2")

# Phase 3: Switch to new key for signing
km.set_active_key("v2")

# Sign requests (uses active key v2)
headers = km.sign_request(
    body='{"data": "value"}',
    method="POST",
    path="/webhook",
)
# Authorization header includes KeyId=v2

# Verify requests (works with both v1 and v2)
is_valid, error = km.verify_request(
    body=request_body,
    auth_header=request.headers["Authorization"],
    headers=dict(request.headers),
    method="POST",
    path="/webhook",
)

# Phase 4: Remove old key after transition
km.remove_key("v1")
```

**Mixed key types:**
```python
from hmac_lib import KeyManager, SigningMethod, generate_key_pair, KeyType

km = KeyManager()

# Add HMAC key
km.add_hmac_key("hmac-1", "shared-secret")

# Add asymmetric key
private_key, public_key = generate_key_pair(KeyType.ED25519)
km.add_asymmetric_key(
    "ed25519-1",
    SigningMethod.ED25519,
    private_key_pem=private_key,
    public_key_pem=public_key,
    set_active=True,
)

# Sign with asymmetric key (active)
headers = km.sign_request(body='{"data": "value"}')
```

**Verification-only keys (server side):**
```python
# Server only needs public keys to verify
km = KeyManager()
km.add_asymmetric_key(
    "client-key-1",
    SigningMethod.ED25519,
    public_key_pem=client_public_key,  # No private key needed
)
```

## Authorization Header Format

### HMAC
```
Authorization: HMAC-SHA256 KeyId=key-v1&Credential=api-key&SignedHeaders=date;host&Signature=base64sig
```

### Asymmetric
```
Authorization: ASYMMETRIC-Ed25519 KeyId=key-v1&SignedHeaders=date;host&Signature=base64sig
```

**Required fields:**
- `KeyId` - Identifies which key was used (required for all requests)
- `SignedHeaders` - Semicolon-separated list of headers included in signature
- `Signature` - Base64-encoded signature

## Canonical String Format

The signature is computed over a canonical string:

```
METHOD
PATH
header1:value1
header2:value2
BODY
```

Headers are sorted alphabetically by name (case-insensitive).

## API Reference

### HMAC Functions

| Function | Description |
|----------|-------------|
| `create_signed_request()` | Create signed request headers |
| `validate_hmac_signature()` | Validate API Gateway event (returns True or error dict) |
| `verify_hmac_signature()` | Verify signature (returns tuple of is_valid, error) |
| `compute_hmac_signature()` | Compute raw signature |
| `parse_hmac_header()` | Parse Authorization header |
| `verify_timestamp()` | Validate Date header timestamp |

### Asymmetric Functions

| Function | Description |
|----------|-------------|
| `generate_key_pair()` | Generate Ed25519 or RSA key pair |
| `create_signed_request_asymmetric()` | Create signed request headers |
| `verify_asymmetric_signature()` | Verify signature with public key |
| `compute_asymmetric_signature()` | Compute raw signature with private key |
| `parse_asymmetric_header()` | Parse Authorization header |

### Key Manager

| Method | Description |
|--------|-------------|
| `add_hmac_key()` | Add HMAC key |
| `add_asymmetric_key()` | Add asymmetric key pair |
| `set_active_key()` | Set key for signing new requests |
| `remove_key()` | Remove a key (cannot remove active key) |
| `mark_key_invalid()` | Mark key as invalid for verification |
| `sign_request()` | Sign request with active key |
| `verify_request()` | Verify request (finds key by KeyId) |
| `list_keys()` | List all keys with status |

## Manual Implementation (Without Library)

If you need to implement signing in another language or without this library, here's how to create a compatible signature:

### Python Example (Manual HMAC Signing)

```python
import base64
import hashlib
import hmac
from email.utils import formatdate
import requests

# Configuration
secret_key = "your-shared-secret"
key_id = "your-key-id"
credential = "your-api-key"
method = "POST"
path = "/webhook"
url = f"https://api.example.com{path}"
body = '{"event":"order.created","data":{"id":123}}'

# Step 1: Create headers to sign
date_header = formatdate(usegmt=True)  # e.g., "Wed, 05 Feb 2026 12:00:00 GMT"
headers_to_sign = {
    "date": date_header,
    "host": "api.example.com",
    "content-type": "application/json",
}

# Step 2: Build canonical string
# Format: METHOD\nPATH\nheader1:value1\nheader2:value2\n...\nBODY
# Headers must be sorted alphabetically (case-insensitive)
canonical_parts = [method, path]
for header_name in sorted(headers_to_sign.keys(), key=str.lower):
    canonical_parts.append(f"{header_name.lower()}:{headers_to_sign[header_name]}")
canonical_parts.append(body)
canonical_string = "\n".join(canonical_parts)

# Step 3: Compute HMAC-SHA256 signature
signature_bytes = hmac.new(
    secret_key.encode("utf-8"),
    canonical_string.encode("utf-8"),
    hashlib.sha256,
).digest()
signature = base64.b64encode(signature_bytes).decode("ascii")

# Step 4: Build Authorization header
signed_headers_list = ";".join(sorted(headers_to_sign.keys(), key=str.lower))
auth_header = f"HMAC-SHA256 KeyId={key_id}&Credential={credential}&SignedHeaders={signed_headers_list}&Signature={signature}"

# Step 5: Make the request
response = requests.post(
    url,
    data=body,
    headers={
        "Authorization": auth_header,
        "Date": date_header,
        "Host": "api.example.com",
        "Content-Type": "application/json",
    },
)
print(f"Response: {response.status_code}")
```

### Canonical String Example

For a POST request to `/webhook` with body `{"event":"test"}`:

```
POST
/webhook
content-type:application/json
date:Wed, 05 Feb 2026 12:00:00 GMT
host:api.example.com
{"event":"test"}
```

### Other Languages

The algorithm is straightforward to implement in any language:

1. **Build canonical string**: `METHOD + \n + PATH + \n + sorted_headers + \n + BODY`
2. **Compute signature**: `base64(HMAC-SHA256(secret_key, canonical_string))`
3. **Format header**: `HMAC-SHA256 KeyId=...&Credential=...&SignedHeaders=...&Signature=...`

**Key points:**
- Headers are sorted alphabetically by lowercase name
- Header format in canonical string: `lowercase_name:value` (no space after colon)
- SignedHeaders is semicolon-separated, lowercase, alphabetically sorted
- Signature is base64-encoded

## FastAPI JWKS Endpoint (Public Key Distribution)

If you're using asymmetric signing with key rotation, you can expose your public keys via a standard JWKS endpoint so that clients can automatically fetch and cache verification keys.

```bash
pip install docspera-hmac-signing-lib fastapi uvicorn
```

```python
import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from hmac_lib import KeyManager, KeyType, SigningMethod, generate_key_pair

app = FastAPI()

# --- Key rotation config ---
KEY_TYPE = KeyType.ED25519
ROTATION_INTERVAL_HOURS = 24
GRACE_PERIOD_HOURS = 48

# --- State ---
km = KeyManager()
key_metadata: dict[str, dict] = {}  # key_id -> {public_key_pem, created_at, expires_at}


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pem_to_jwk(key_id: str, public_key_pem: bytes) -> dict:
    """Convert an Ed25519 or RSA PEM public key to JWK format."""
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    pub = load_pem_public_key(public_key_pem)

    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": _base64url(raw),
                "kid": key_id, "use": "sig", "alg": "EdDSA"}

    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
        e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
        return {"kty": "RSA", "n": _base64url(n_bytes), "e": _base64url(e_bytes),
                "kid": key_id, "use": "sig", "alg": "RS256"}

    raise ValueError(f"Unsupported key type: {type(pub)}")


def rotate_key():
    """Generate a new key pair, register it in KeyManager, and track metadata."""
    key_id = f"key-{uuid.uuid4().hex[:8]}"
    private_pem, public_pem = generate_key_pair(KEY_TYPE)
    method = SigningMethod.ED25519 if KEY_TYPE == KeyType.ED25519 else SigningMethod.RSA

    km.add_asymmetric_key(key_id, method,
                          private_key_pem=private_pem,
                          public_key_pem=public_pem,
                          set_active=True)

    now = datetime.now(timezone.utc)
    key_metadata[key_id] = {
        "public_key_pem": public_pem,
        "created_at": now,
        "expires_at": now + timedelta(hours=ROTATION_INTERVAL_HOURS),
    }


def cleanup_expired_keys():
    """Remove keys that are past the grace period."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=GRACE_PERIOD_HOURS)
    active_key = km.get_active_key()
    for kid in list(key_metadata):
        meta = key_metadata[kid]
        if meta["expires_at"] < cutoff and (active_key is None or kid != active_key.key_id):
            km.remove_key(kid)
            del key_metadata[kid]


# Create initial key on startup
rotate_key()


@app.get("/.well-known/jwks.json")
def jwks():
    """Public JWKS endpoint — returns all valid public keys."""
    cleanup_expired_keys()
    keys = [_pem_to_jwk(kid, meta["public_key_pem"])
            for kid, meta in key_metadata.items()]
    return JSONResponse(
        content={"keys": keys},
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.post("/rotate")
def trigger_rotation():
    """Trigger a manual key rotation (protect this in production)."""
    rotate_key()
    return {"status": "rotated", "active_key": km.get_active_key().key_id}
```

Run locally:
```bash
uvicorn app:app --reload
# GET http://localhost:8000/.well-known/jwks.json
```

**Clients** verify signatures by fetching the JWKS endpoint, finding the key matching the `KeyId` from the `Authorization` header, and using it to verify:

```python
import requests
from hmac_lib import verify_asymmetric_signature, parse_asymmetric_header
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def verify_with_jwks(jwks_url, auth_header, body, headers, method="POST", path="/"):
    """Fetch public keys from JWKS endpoint and verify the request signature."""
    _, params = parse_asymmetric_header(auth_header)
    kid = params["key_id"]

    # Fetch JWKS (cache this in production)
    jwks = requests.get(jwks_url).json()
    jwk = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if not jwk:
        return False, f"Key {kid} not found in JWKS"

    # Reconstruct PEM from JWK
    if jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
        import base64
        raw = base64.urlsafe_b64decode(jwk["x"] + "==")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        public_key_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    else:
        raise ValueError(f"Unsupported JWK type: {jwk['kty']}")

    # Extract signed headers
    signed_headers = {}
    for name in params["signed_headers"].split(";"):
        if name:
            signed_headers[name] = headers.get(name, "")

    return verify_asymmetric_signature(
        body=body,
        public_key_pem=public_key_pem,
        signature=params["signature"],
        key_type=params["key_type"],
        headers_to_sign=signed_headers,
        method=method,
        path=path,
    )
```

## Configuration Options

### Timestamp Validation

```python
# Default: 5 minutes (300 seconds)
validate_hmac_signature(event, secret_key, max_age_seconds=300)

# Custom time window
validate_hmac_signature(event, secret_key, max_age_seconds=600)  # 10 minutes

# Disable timestamp validation entirely
validate_hmac_signature(event, secret_key, require_date=False)
verify_hmac_signature(..., require_date=False)
```

### Algorithms

**HMAC:**
- SHA256 (default)
- SHA384
- SHA512
- SHA224
- SHA1 (not recommended)

**Asymmetric:**
- Ed25519 (default, recommended)
- RSA with PSS padding and SHA256

## Security Considerations

1. **Timestamp validation** prevents replay attacks - requests older than 5 minutes are rejected by default
2. **Constant-time comparison** prevents timing attacks on signature verification
3. **KeyId required** - all requests must identify which key was used
4. **Date header must be signed** - prevents timestamp tampering

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=hmac_lib --cov-report=term-missing
```

## License

MIT
