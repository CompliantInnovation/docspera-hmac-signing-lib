"""
HMAC Signing Library for HTTP Webhook Requests.

Provides HMAC and asymmetric signature generation and verification
with support for key rotation between systems.

Basic Usage (HMAC):
    from hmac_lib import create_signed_request, validate_hmac_signature

    # Client: Sign a request
    headers = create_signed_request(
        body='{"data": "value"}',
        secret_key="shared-secret",
        credential="my-api-key",
    )

    # Server: Verify a request (API Gateway event)
    result = validate_hmac_signature(event, secret_key="shared-secret")

Asymmetric Usage:
    from hmac_lib import generate_key_pair, create_signed_request_asymmetric, KeyType

    # Generate keys (do once)
    private_key, public_key = generate_key_pair(KeyType.ED25519)

    # Client: Sign with private key
    headers = create_signed_request_asymmetric(
        body='{"data": "value"}',
        private_key_pem=private_key,
        key_id="my-key-1",
    )

Key Rotation Usage:
    from hmac_lib import KeyManager, SigningMethod

    km = KeyManager()
    km.add_hmac_key("v1", "secret-v1")
    km.add_hmac_key("v2", "secret-v2", set_active=True)

    # Sign with active key
    headers = km.sign_request(body='{"data": "value"}')

    # Verify (finds key by KeyId in header)
    is_valid, error = km.verify_request(body, auth_header, headers)
"""

from hmac_lib.hmac_lib import (
    compute_hmac_signature,
    create_signed_request,
    parse_hmac_header,
    validate_hmac_signature,
    verify_hmac_signature,
    verify_timestamp,
)

from hmac_lib.asymmetric import (
    KeyType,
    compute_asymmetric_signature,
    create_signed_request_asymmetric,
    generate_key_pair,
    parse_asymmetric_header,
    verify_asymmetric_signature,
)

from hmac_lib.key_manager import (
    KeyManager,
    SigningKey,
    SigningMethod,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # HMAC functions
    "compute_hmac_signature",
    "create_signed_request",
    "parse_hmac_header",
    "validate_hmac_signature",
    "verify_hmac_signature",
    "verify_timestamp",
    # Asymmetric functions
    "KeyType",
    "compute_asymmetric_signature",
    "create_signed_request_asymmetric",
    "generate_key_pair",
    "parse_asymmetric_header",
    "verify_asymmetric_signature",
    # Key manager
    "KeyManager",
    "SigningKey",
    "SigningMethod",
]
