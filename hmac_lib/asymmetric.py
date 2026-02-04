"""
Asymmetric key signing for HTTP webhook requests.

Provides Ed25519 and RSA signature generation and verification using
public/private key pairs.
"""

import base64
import re
from email.utils import formatdate
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes


class KeyType:
    """Supported asymmetric key types."""

    ED25519 = "Ed25519"  # Default - modern, fast, smaller keys
    RSA = "RSA"


def generate_key_pair(
    key_type: str = KeyType.ED25519,
    key_size: int = 2048,
) -> tuple[bytes, bytes]:
    """
    Generate a public/private key pair.

    Args:
        key_type: "Ed25519" (default) or "RSA"
        key_size: Key size for RSA (2048, 3072, 4096). Ignored for Ed25519.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as bytes

    Raises:
        ValueError: If unsupported key type is specified
    """
    private_key: PrivateKeyTypes
    if key_type == KeyType.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == KeyType.RSA:
        if key_size not in (2048, 3072, 4096):
            raise ValueError(f"Invalid RSA key size: {key_size}. Use 2048, 3072, or 4096.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key_pem, public_key_pem


def _build_canonical_string(
    body: str,
    headers_to_sign: Optional[dict[str, str]],
    method: str,
    path: str,
) -> str:
    """Build the canonical string for signing."""
    canonical_parts = []

    # Add method and path
    canonical_parts.append(method.upper())
    canonical_parts.append(path)

    # Add headers if provided (in sorted order for consistency)
    if headers_to_sign:
        for header_name in sorted(headers_to_sign.keys(), key=str.lower):
            canonical_parts.append(f"{header_name.lower()}:{headers_to_sign[header_name]}")

    # Add body
    canonical_parts.append(body)

    return "\n".join(canonical_parts)


def _load_private_key(private_key_pem: bytes) -> PrivateKeyTypes:
    """Load a private key from PEM bytes."""
    return serialization.load_pem_private_key(private_key_pem, password=None)


def _load_public_key(public_key_pem: bytes) -> PublicKeyTypes:
    """Load a public key from PEM bytes."""
    return serialization.load_pem_public_key(public_key_pem)


def compute_asymmetric_signature(
    body: str,
    private_key_pem: bytes,
    key_type: str = KeyType.ED25519,
    encoding: str = "utf-8",
    headers_to_sign: Optional[dict[str, str]] = None,
    method: str = "POST",
    path: str = "/",
) -> tuple[str, str]:
    """
    Compute signature using private key.

    Args:
        body: The request body to sign (as string)
        private_key_pem: PEM-encoded private key
        key_type: "Ed25519" (default) or "RSA"
        encoding: Text encoding (default: utf-8)
        headers_to_sign: Dictionary of headers to include in signature
        method: HTTP method (default: POST)
        path: Request path (default: /)

    Returns:
        Tuple of (base64_signature, canonical_string)

    Raises:
        ValueError: If unsupported key type or invalid key
    """
    canonical_string = _build_canonical_string(body, headers_to_sign, method, path)
    data = canonical_string.encode(encoding)

    private_key = _load_private_key(private_key_pem)

    if key_type == KeyType.ED25519:
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Key type mismatch: expected Ed25519 private key")
        signature = private_key.sign(data)
    elif key_type == KeyType.RSA:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Key type mismatch: expected RSA private key")
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    return base64.b64encode(signature).decode("ascii"), canonical_string


def verify_asymmetric_signature(
    body: str,
    public_key_pem: bytes,
    signature: str,
    key_type: str = KeyType.ED25519,
    encoding: str = "utf-8",
    headers_to_sign: Optional[dict[str, str]] = None,
    method: str = "POST",
    path: str = "/",
) -> tuple[bool, Optional[str]]:
    """
    Verify signature using public key.

    Args:
        body: The request body
        public_key_pem: PEM-encoded public key
        signature: Base64-encoded signature to verify
        key_type: "Ed25519" (default) or "RSA"
        encoding: Text encoding (default: utf-8)
        headers_to_sign: Dictionary of headers that were signed
        method: HTTP method (default: POST)
        path: Request path (default: /)

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        canonical_string = _build_canonical_string(body, headers_to_sign, method, path)
        data = canonical_string.encode(encoding)
        signature_bytes = base64.b64decode(signature)

        public_key = _load_public_key(public_key_pem)

        if key_type == KeyType.ED25519:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False, "Key type mismatch: expected Ed25519 public key"
            public_key.verify(signature_bytes, data)
        elif key_type == KeyType.RSA:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "Key type mismatch: expected RSA public key"
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.AUTO,
                ),
                hashes.SHA256(),
            )
        else:
            return False, f"Unsupported key type: {key_type}"

        return True, None

    except Exception as e:
        return False, f"Signature verification failed: {str(e)}"


def parse_asymmetric_header(auth_header: str) -> tuple[str, dict[str, str]]:
    """
    Parse asymmetric authorization header.

    Expected format:
    Authorization: ASYMMETRIC-ED25519 KeyId=<key_id>&SignedHeaders=<headers>&Signature=<sig>

    Args:
        auth_header: The Authorization header value

    Returns:
        Tuple of (auth_type, params_dict) where params_dict contains:
        - key_type: "Ed25519" or "RSA"
        - key_id: The key identifier (required)
        - signed_headers: Semicolon-separated list of signed headers
        - signature: The signature value

    Raises:
        ValueError: If header format is invalid or KeyId is missing
    """
    if not auth_header:
        raise ValueError("Empty authorization header")

    # Match ASYMMETRIC-ALGORITHM followed by parameters
    parts = auth_header.split(" ")
    if not parts[0].upper().startswith("ASYMMETRIC-") or len(parts) != 2:
        raise ValueError("Invalid asymmetric header format")

    key_type = parts[0].split("-", 1)[1]
    params_str = parts[1]

    # Normalize key type
    if key_type.upper() == "ED25519":
        key_type = KeyType.ED25519
    elif key_type.upper() == "RSA":
        key_type = KeyType.RSA
    else:
        raise ValueError(f"Unsupported key type in header: {key_type}")

    # Parse parameters
    params = {}
    param_pattern = r"(\w+)=([^&]+)"
    for param_match in re.finditer(param_pattern, params_str):
        key = param_match.group(1).lower()
        value = param_match.group(2)
        params[key] = value

    if "keyid" not in params:
        raise ValueError("Missing KeyId in asymmetric header")
    if "signature" not in params:
        raise ValueError("Missing Signature in asymmetric header")

    return parts[0], {
        "key_type": key_type,
        "key_id": params["keyid"],
        "signed_headers": params.get("signedheaders", ""),
        "signature": params["signature"],
    }


def create_signed_request_asymmetric(
    body: str,
    private_key_pem: bytes,
    key_id: str,
    key_type: str = KeyType.ED25519,
    include_date: bool = True,
    additional_headers: Optional[dict[str, str]] = None,
    method: str = "POST",
    path: str = "/",
) -> dict[str, str]:
    """
    Create signed request headers using asymmetric key.

    Args:
        body: The request body to sign
        private_key_pem: PEM-encoded private key
        key_id: Identifier for this key (required in Authorization header)
        key_type: "Ed25519" (default) or "RSA"
        include_date: Whether to include Date header (default: True)
        additional_headers: Additional headers to sign
        method: HTTP method
        path: Request path

    Returns:
        Dictionary of headers to add to the request, including Authorization
    """
    headers_to_sign = {}

    # Add Date header if requested
    if include_date:
        headers_to_sign["Date"] = formatdate(usegmt=True)

    # Add additional headers
    if additional_headers:
        headers_to_sign.update(additional_headers)

    # Compute signature
    signature, _ = compute_asymmetric_signature(
        body=body,
        private_key_pem=private_key_pem,
        key_type=key_type,
        headers_to_sign=headers_to_sign,
        method=method,
        path=path,
    )

    # Build signed headers list
    signed_headers_list = ";".join(sorted(headers_to_sign.keys(), key=str.lower))

    # Create authorization header
    auth_header = f"ASYMMETRIC-{key_type} KeyId={key_id}&SignedHeaders={signed_headers_list}&Signature={signature}"

    # Return all headers
    result_headers = {"Authorization": auth_header}
    result_headers.update(headers_to_sign)

    return result_headers
