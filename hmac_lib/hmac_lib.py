import hashlib
import hmac
import base64
import re
from datetime import timezone, datetime
from email.utils import parsedate_to_datetime, formatdate
from typing import Any, Dict, Optional, Tuple, Union


def compute_hmac_signature(
    body: str,
    secret_key: str,
    algorithm: str = "SHA256",
    encoding: str = "utf-8",
    headers_to_sign: Optional[Dict[str, str]] = None,
    method: str = "POST",
    path: str = "/",
) -> Tuple[str, str]:
    """
    Compute HMAC signature for a given body and secret key with optional header signing.

    Args:
        body: The request body to sign (as string)
        secret_key: The secret key for HMAC
        algorithm: Hash algorithm (SHA256, SHA384, SHA512, etc.)
        encoding: Text encoding (default: utf-8)
        headers_to_sign: Dictionary of headers to include in signature (e.g., {'date': 'Thu, 05 Jan 2024 12:00:00 GMT'})
        method: HTTP method (default: POST)
        path: Request path (default: /)

    Returns:
        Tuple of (signature, canonical_string) where:
        - signature: Base64-encoded signature string
        - canonical_string: The canonical string that was signed (for debugging)

    Raises:
        ValueError: If unsupported algorithm is specified
    """
    # Map algorithm names to hashlib functions
    algorithm_map = {
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "SHA224": hashlib.sha224,
        "SHA1": hashlib.sha1,
    }

    algo_upper = algorithm.upper()
    if algo_upper not in algorithm_map:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Build canonical string
    canonical_parts = []

    # Add method and path
    canonical_parts.append(method.upper())
    canonical_parts.append(path)

    # Add headers if provided (in sorted order for consistency)
    signed_headers = []
    if headers_to_sign:
        for header_name in sorted(headers_to_sign.keys(), key=str.lower):
            signed_headers.append(header_name.lower())
            canonical_parts.append(
                f"{header_name.lower()}:{headers_to_sign[header_name]}"
            )

    # Add body
    canonical_parts.append(body)

    # Join with newlines
    canonical_string = "\n".join(canonical_parts)

    # Create HMAC
    h = hmac.new(
        secret_key.encode(encoding),
        canonical_string.encode(encoding),
        algorithm_map[algo_upper],
    )

    # Return base64-encoded signature and the canonical string
    return base64.b64encode(h.digest()).decode("ascii"), canonical_string


def parse_hmac_header(auth_header: str) -> Tuple[str, Dict[str, str]]:
    """
    Parse HMAC authorization header.

    Expected format:
    Authorization: HMAC-SHA256 Credential=<key>&SignedHeaders=<headers>&Signature=<sig>

    Args:
        auth_header: The Authorization header value

    Returns:
        Dictionary with 'algorithm', 'credential', 'signed_headers', and 'signature'

    Raises:
        ValueError: If header format is invalid
    """
    if not auth_header:
        raise ValueError("Empty authorization header")

    # Match HMAC-ALGORITHM followed by parameters
    parts = auth_header.split(" ")
    if not parts[0].upper().startswith("HMAC-") or len(parts) != 2:
        raise ValueError("Invalid HMAC header format")

    algorithm = parts[0].split("-")[1].upper()
    params_str = parts[1]

    # Parse parameters
    params = {}
    param_pattern = r"(\w+)=([^&]+)"
    for param_match in re.finditer(param_pattern, params_str):
        key = param_match.group(1).lower()
        value = param_match.group(2)
        params[key] = value

    if "signature" not in params:
        raise ValueError("Missing signature in HMAC header")

    return parts[0], {
        "algorithm": algorithm,
        "credential": params.get("credential", ""),
        "signed_headers": params.get("signedheaders", ""),
        "signature": params["signature"],
    }


def verify_timestamp(
    date_header: str, max_age_seconds: int = 300
) -> Tuple[bool, Optional[str]]:
    """
    Verify that a Date header timestamp is within acceptable age.

    Args:
        date_header: The Date header value (RFC 2822 format)
        max_age_seconds: Maximum acceptable age in seconds (default: 5 minutes)

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Parse the date header
        request_time = parsedate_to_datetime(date_header)

        # Ensure timezone awareness
        if request_time.tzinfo is None:
            request_time = request_time.replace(tzinfo=timezone.utc)

        # Get current time
        current_time = datetime.now(timezone.utc)

        # Calculate time difference
        time_diff = abs((current_time - request_time).total_seconds())

        if time_diff > max_age_seconds:
            return (
                False,
                f"Request timestamp too old: {time_diff:.0f} seconds (max: {max_age_seconds})",
            )

        # Also check if timestamp is in the future (with small tolerance)
        future_tolerance = 60  # 1 minute tolerance for clock skew
        if (request_time - current_time).total_seconds() > future_tolerance:
            return False, "Request timestamp is in the future"

        return True, None

    except Exception as e:
        return False, f"Invalid date header: {str(e)}"


def verify_hmac_signature(
    body: str,
    secret_key: str,
    auth_header: str,
    headers: Dict[str, str],
    method: str = "POST",
    path: str = "/",
    max_age_seconds: int = 300,
    require_date: bool = True,
) -> Tuple[bool, Optional[str]]:
    """
    Verify HMAC signature from authorization header with timestamp validation.

    Args:
        body: The request body
        secret_key: The secret key for HMAC
        auth_header: The Authorization header value
        headers: Dictionary of all request headers
        method: HTTP method (default: POST)
        path: Request path (default: /)
        max_age_seconds: Maximum age for Date header (default: 5 minutes)
        require_date: Whether to require and validate Date header (default: True)

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Parse the authorization header
        auth_type, header_data = parse_hmac_header(auth_header)

        # Get signed headers list
        signed_header_names = []
        if header_data["signed_headers"]:
            signed_header_names = [
                h.strip().lower() for h in header_data["signed_headers"].split(";")
            ]

        # Check if date is required and present
        if require_date:
            date_header = None
            for h_name, h_value in headers.items():
                if h_name.lower() == "date":
                    date_header = h_value
                    break

            if not date_header:
                return False, "Missing required Date header"

            # Verify timestamp to prevent replay attacks
            is_valid_time, time_error = verify_timestamp(date_header, max_age_seconds)
            if not is_valid_time:
                return False, f"Timestamp validation failed: {time_error}"

            # Ensure date is in signed headers
            if "date" not in signed_header_names and require_date:
                return False, "Date header must be included in signed headers"

        # Extract headers to sign
        headers_to_sign = {}
        for header_name in signed_header_names:
            header_found = False
            for h_name, h_value in headers.items():
                if h_name.lower() == header_name:
                    headers_to_sign[header_name] = h_value
                    header_found = True
                    break

            if not header_found:
                return False, f"Signed header '{header_name}' not found in request"

        # Compute expected signature
        expected_signature, _ = compute_hmac_signature(
            body=body,
            secret_key=secret_key,
            algorithm=header_data["algorithm"],
            headers_to_sign=headers_to_sign,
            method=method,
            path=path,
        )

        # Compare signatures (using constant-time comparison)
        received_signature = header_data["signature"]
        if hmac.compare_digest(expected_signature, received_signature):
            return True, None
        else:
            return False, "Signature mismatch"

    except Exception as e:
        return False, str(e)


def create_signed_request(
    body: str,
    secret_key: str,
    credential: str,
    algorithm: str = "SHA256",
    include_date: bool = True,
    additional_headers: Optional[Dict[str, str]] = None,
    method: str = "POST",
    path: str = "/",
) -> Dict[str, str]:
    """
    Create a signed request with proper headers.

    Args:
        body: The request body to sign
        secret_key: The secret key for HMAC
        credential: The credential/API key identifier
        algorithm: Hash algorithm (default: SHA256)
        include_date: Whether to include Date header (default: True)
        additional_headers: Additional headers to sign
        method: HTTP method
        path: Request path

    Returns:
        Dictionary of headers to add to the request
    """
    headers_to_sign = {}

    # Add Date header if requested
    if include_date:
        headers_to_sign["Date"] = formatdate(usegmt=True)

    # Add additional headers
    if additional_headers:
        headers_to_sign.update(additional_headers)

    # Compute signature
    signature, _ = compute_hmac_signature(
        body=body,
        secret_key=secret_key,
        algorithm=algorithm,
        headers_to_sign=headers_to_sign,
        method=method,
        path=path,
    )

    # Build signed headers list
    signed_headers_list = ";".join(sorted(headers_to_sign.keys(), key=str.lower))

    # Create authorization header
    auth_header = f"HMAC-{algorithm} Credential={credential}&SignedHeaders={signed_headers_list}&Signature={signature}"

    # Return all headers
    result_headers = {"Authorization": auth_header}
    result_headers.update(headers_to_sign)

    return result_headers


def validate_hmac_signature(
    event: Dict[str, Any],
    secret_key: str,
    max_age_seconds: int = 300,
) -> Union[bool, Dict[str, Any]]:
    """
    Validate HMAC signature from an AWS API Gateway event.

    This is a convenience wrapper around verify_hmac_signature() that handles
    the API Gateway event structure and returns appropriate HTTP responses.

    Args:
        event: API Gateway event with httpMethod, path, headers, body
        secret_key: The secret key for HMAC validation
        max_age_seconds: Maximum age for timestamp validation (default: 5 minutes)

    Returns:
        True if signature is valid
        Dict with statusCode and body if validation fails (e.g., {"statusCode": 401, "body": "..."})
    """
    headers = event.get("headers", {}) or {}

    # Find Authorization header (case-insensitive)
    auth_header = None
    for key, value in headers.items():
        if key.lower() == "authorization":
            auth_header = value
            break

    if not auth_header:
        return {
            "statusCode": 401,
            "body": "Missing Authorization header",
        }

    # Get body
    body = event.get("body", "") or ""

    # Call verify_hmac_signature
    is_valid, error_msg = verify_hmac_signature(
        body=body,
        secret_key=secret_key,
        auth_header=auth_header,
        headers=headers,
        method=event.get("httpMethod", "POST"),
        path=event.get("path", "/"),
        max_age_seconds=max_age_seconds,
        require_date=True,
    )

    if is_valid:
        return True
    else:
        return {
            "statusCode": 401,
            "body": f"Invalid signature: {error_msg}",
        }
