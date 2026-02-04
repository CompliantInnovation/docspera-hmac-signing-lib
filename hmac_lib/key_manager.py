"""
Key manager for signing key rotation support.

Provides a thread-safe key manager that supports multiple active keys
for graceful key rotation between systems.
"""

import re
import threading
from dataclasses import dataclass
from email.utils import formatdate
from enum import Enum
from typing import Any, Optional

from hmac_lib.asymmetric import (
    KeyType,
    compute_asymmetric_signature,
    verify_asymmetric_signature,
)
from hmac_lib.hmac_lib import (
    compute_hmac_signature,
    verify_timestamp,
)


class SigningMethod(Enum):
    """Supported signing methods."""

    HMAC = "hmac"
    RSA = "rsa"
    ED25519 = "ed25519"


@dataclass
class SigningKey:
    """Represents a signing key (symmetric or asymmetric)."""

    key_id: str
    method: SigningMethod
    algorithm: str = "SHA256"  # For HMAC
    secret_key: Optional[str] = None  # For HMAC
    private_key_pem: Optional[bytes] = None  # For asymmetric (signing)
    public_key_pem: Optional[bytes] = None  # For asymmetric (verification)
    is_active: bool = True  # Can be used for signing new requests
    is_valid: bool = True  # Can be used for verification (during rotation)


class KeyManager:
    """
    Manages multiple signing keys for rotation support.

    Thread-safe key manager that allows:
    - Multiple keys to be valid simultaneously
    - One active key for signing new requests
    - Graceful key rotation without downtime

    Usage:
        km = KeyManager()

        # Add keys
        km.add_hmac_key("key-v1", "secret123")
        km.add_hmac_key("key-v2", "newsecret456", set_active=True)

        # Sign requests (uses active key)
        headers = km.sign_request(body="/webhook", method="POST", path="/webhook")

        # Verify requests (finds key by KeyId in header)
        is_valid, error = km.verify_request(body, auth_header, headers)

        # After rotation complete, remove old key
        km.remove_key("key-v1")
    """

    def __init__(self):
        self._keys: dict[str, SigningKey] = {}
        self._active_key_id: Optional[str] = None
        self._lock = threading.RLock()

    def add_hmac_key(
        self,
        key_id: str,
        secret_key: str,
        algorithm: str = "SHA256",
        set_active: bool = False,
    ) -> None:
        """
        Add an HMAC (symmetric) key.

        Args:
            key_id: Unique identifier for this key
            secret_key: The secret key for HMAC
            algorithm: Hash algorithm (default: SHA256)
            set_active: Whether to make this the active key for signing
        """
        with self._lock:
            self._keys[key_id] = SigningKey(
                key_id=key_id,
                method=SigningMethod.HMAC,
                algorithm=algorithm,
                secret_key=secret_key,
            )
            if set_active or self._active_key_id is None:
                self._active_key_id = key_id

    def add_asymmetric_key(
        self,
        key_id: str,
        method: SigningMethod,
        private_key_pem: Optional[bytes] = None,
        public_key_pem: Optional[bytes] = None,
        set_active: bool = False,
    ) -> None:
        """
        Add an asymmetric key pair (or just public key for verification).

        Args:
            key_id: Unique identifier for this key
            method: SigningMethod.RSA or SigningMethod.ED25519
            private_key_pem: PEM-encoded private key (for signing)
            public_key_pem: PEM-encoded public key (for verification)
            set_active: Whether to make this the active key for signing
        """
        if method not in (SigningMethod.RSA, SigningMethod.ED25519):
            raise ValueError(f"Invalid asymmetric method: {method}")

        if private_key_pem is None and public_key_pem is None:
            raise ValueError("At least one of private_key_pem or public_key_pem is required")

        with self._lock:
            self._keys[key_id] = SigningKey(
                key_id=key_id,
                method=method,
                private_key_pem=private_key_pem,
                public_key_pem=public_key_pem,
            )
            if (
                set_active
                and private_key_pem is not None
                or self._active_key_id is None
                and private_key_pem is not None
            ):
                self._active_key_id = key_id

    def set_active_key(self, key_id: str) -> None:
        """
        Set which key to use for signing new requests.

        Args:
            key_id: The key identifier to make active

        Raises:
            ValueError: If key doesn't exist or can't sign (no private key)
        """
        with self._lock:
            if key_id not in self._keys:
                raise ValueError(f"Key '{key_id}' not found")

            key = self._keys[key_id]
            if key.method == SigningMethod.HMAC and not key.secret_key:
                raise ValueError(f"Key '{key_id}' has no secret key for signing")
            if key.method in (SigningMethod.RSA, SigningMethod.ED25519) and not key.private_key_pem:
                raise ValueError(f"Key '{key_id}' has no private key for signing")

            self._active_key_id = key_id

    def get_key(self, key_id: str) -> Optional[SigningKey]:
        """Get a key by ID."""
        with self._lock:
            return self._keys.get(key_id)

    def get_active_key(self) -> Optional[SigningKey]:
        """Get the currently active key for signing."""
        with self._lock:
            if self._active_key_id is None:
                return None
            return self._keys.get(self._active_key_id)

    def list_keys(self) -> dict[str, dict[str, Any]]:
        """
        List all keys with their status.

        Returns:
            Dictionary of key_id -> {method, is_active, is_valid, can_sign, can_verify}
        """
        with self._lock:
            result = {}
            for key_id, key in self._keys.items():
                can_sign = (key.method == SigningMethod.HMAC and key.secret_key is not None) or (
                    key.method in (SigningMethod.RSA, SigningMethod.ED25519) and key.private_key_pem is not None
                )
                can_verify = (key.method == SigningMethod.HMAC and key.secret_key is not None) or (
                    key.method in (SigningMethod.RSA, SigningMethod.ED25519) and key.public_key_pem is not None
                )
                result[key_id] = {
                    "method": key.method.value,
                    "is_active": key_id == self._active_key_id,
                    "is_valid": key.is_valid,
                    "can_sign": can_sign,
                    "can_verify": can_verify,
                }
            return result

    def remove_key(self, key_id: str) -> None:
        """
        Remove a key (after rotation is complete).

        Args:
            key_id: The key identifier to remove

        Raises:
            ValueError: If trying to remove the active key
        """
        with self._lock:
            if key_id == self._active_key_id:
                raise ValueError("Cannot remove the active key. Set a different active key first.")
            self._keys.pop(key_id, None)

    def mark_key_invalid(self, key_id: str) -> None:
        """
        Mark a key as invalid (won't be used for verification).

        Args:
            key_id: The key identifier to invalidate
        """
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].is_valid = False

    def sign_request(
        self,
        body: str,
        credential: str = "",
        method: str = "POST",
        path: str = "/",
        include_date: bool = True,
        additional_headers: Optional[dict[str, str]] = None,
    ) -> dict[str, str]:
        """
        Sign a request using the active key.

        Includes KeyId in the Authorization header.

        Args:
            body: The request body to sign
            credential: The credential/API key identifier (for HMAC)
            method: HTTP method
            path: Request path
            include_date: Whether to include Date header
            additional_headers: Additional headers to sign

        Returns:
            Dictionary of headers to add to the request

        Raises:
            ValueError: If no active key is set
        """
        with self._lock:
            key = self.get_active_key()
            if key is None:
                raise ValueError("No active key set for signing")

            headers_to_sign = {}
            if include_date:
                headers_to_sign["Date"] = formatdate(usegmt=True)
            if additional_headers:
                headers_to_sign.update(additional_headers)

            if key.method == SigningMethod.HMAC:
                signature, _ = compute_hmac_signature(
                    body=body,
                    secret_key=key.secret_key,
                    algorithm=key.algorithm,
                    headers_to_sign=headers_to_sign,
                    method=method,
                    path=path,
                )
                signed_headers_list = ";".join(sorted(headers_to_sign.keys(), key=str.lower))
                auth_header = f"HMAC-{key.algorithm} KeyId={key.key_id}&Credential={credential}&SignedHeaders={signed_headers_list}&Signature={signature}"
            else:
                # Asymmetric
                key_type = KeyType.ED25519 if key.method == SigningMethod.ED25519 else KeyType.RSA
                signature, _ = compute_asymmetric_signature(
                    body=body,
                    private_key_pem=key.private_key_pem,
                    key_type=key_type,
                    headers_to_sign=headers_to_sign,
                    method=method,
                    path=path,
                )
                signed_headers_list = ";".join(sorted(headers_to_sign.keys(), key=str.lower))
                auth_header = f"ASYMMETRIC-{key_type} KeyId={key.key_id}&SignedHeaders={signed_headers_list}&Signature={signature}"

            result_headers = {"Authorization": auth_header}
            result_headers.update(headers_to_sign)
            return result_headers

    def _parse_auth_header(self, auth_header: str) -> tuple[str, dict[str, str]]:
        """
        Parse authorization header to extract KeyId and other params.

        Handles both HMAC and ASYMMETRIC header formats.
        """
        if not auth_header:
            raise ValueError("Empty authorization header")

        parts = auth_header.split(" ")
        if len(parts) != 2:
            raise ValueError("Invalid authorization header format")

        auth_type = parts[0].upper()
        params_str = parts[1]

        # Parse parameters
        params = {}
        param_pattern = r"(\w+)=([^&]+)"
        for param_match in re.finditer(param_pattern, params_str):
            key = param_match.group(1).lower()
            value = param_match.group(2)
            params[key] = value

        if "keyid" not in params:
            raise ValueError("Missing KeyId in authorization header")
        if "signature" not in params:
            raise ValueError("Missing Signature in authorization header")

        # Determine method from auth type
        if auth_type.startswith("HMAC-"):
            algorithm = auth_type.split("-", 1)[1]
            params["method"] = "hmac"
            params["algorithm"] = algorithm
        elif auth_type.startswith("ASYMMETRIC-"):
            key_type = auth_type.split("-", 1)[1]
            if key_type.upper() == "ED25519":
                params["method"] = "ed25519"
            elif key_type.upper() == "RSA":
                params["method"] = "rsa"
            else:
                raise ValueError(f"Unknown asymmetric key type: {key_type}")
        else:
            raise ValueError(f"Unknown authorization type: {auth_type}")

        return auth_type, params

    def verify_request(
        self,
        body: str,
        auth_header: str,
        headers: dict[str, str],
        method: str = "POST",
        path: str = "/",
        max_age_seconds: int = 300,
        require_date: bool = True,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify a request, extracting KeyId from auth header to find correct key.

        Args:
            body: The request body
            auth_header: The Authorization header value
            headers: Dictionary of all request headers
            method: HTTP method
            path: Request path
            max_age_seconds: Maximum age for Date header
            require_date: Whether to require and validate Date header

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            auth_type, params = self._parse_auth_header(auth_header)

            key_id = params["keyid"]
            signature = params["signature"]
            signed_header_names = params.get("signedheaders", "").split(";") if params.get("signedheaders") else []

            with self._lock:
                key = self._keys.get(key_id)
                if key is None:
                    return False, f"Unknown key: {key_id}"
                if not key.is_valid:
                    return False, f"Key '{key_id}' is no longer valid"

            # Validate Date header if required
            if require_date:
                date_header = None
                for h_name, h_value in headers.items():
                    if h_name.lower() == "date":
                        date_header = h_value
                        break

                if not date_header:
                    return False, "Missing required Date header"

                is_valid_time, time_error = verify_timestamp(date_header, max_age_seconds)
                if not is_valid_time:
                    return False, f"Timestamp validation failed: {time_error}"

                if "date" not in [h.lower() for h in signed_header_names]:
                    return False, "Date header must be included in signed headers"

            # Extract headers that were signed
            headers_to_verify = {}
            for header_name in signed_header_names:
                if not header_name:
                    continue
                header_found = False
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        headers_to_verify[header_name.lower()] = h_value
                        header_found = True
                        break
                if not header_found:
                    return False, f"Signed header '{header_name}' not found in request"

            # Verify signature based on key type
            if key.method == SigningMethod.HMAC:
                expected_signature, _ = compute_hmac_signature(
                    body=body,
                    secret_key=key.secret_key,
                    algorithm=params.get("algorithm", "SHA256"),
                    headers_to_sign=headers_to_verify,
                    method=method,
                    path=path,
                )
                import hmac as hmac_module

                if hmac_module.compare_digest(expected_signature, signature):
                    return True, None
                else:
                    return False, "Signature mismatch"
            else:
                # Asymmetric verification
                key_type = KeyType.ED25519 if key.method == SigningMethod.ED25519 else KeyType.RSA
                return verify_asymmetric_signature(
                    body=body,
                    public_key_pem=key.public_key_pem,
                    signature=signature,
                    key_type=key_type,
                    headers_to_sign=headers_to_verify,
                    method=method,
                    path=path,
                )

        except Exception as e:
            return False, str(e)
