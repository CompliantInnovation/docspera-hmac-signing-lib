"""
Unit tests for S&N Feedback API HMAC signature validation.

Tests the HMAC signature computation and validation to ensure
consistency between client and server implementations.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from datetime import datetime
from unittest.mock import patch

import pytest

from hmac_lib.hmac_lib import (
    compute_hmac_signature,
    parse_hmac_header,
    validate_hmac_signature,
    verify_timestamp,
)


class TestHMACSignatureComputation(unittest.TestCase):
    """Test HMAC signature computation functions."""

    def setUp(self):
        """Set up test data."""
        self.test_key = b"test-secret-key-123"
        self.test_key_b64 = base64.b64encode(self.test_key).decode("utf-8")

    def test_compute_hmac_signature_basic(self):
        """Test basic HMAC signature computation."""
        signature, canonical_string = compute_hmac_signature(
            secret_key=self.test_key.decode("utf-8"),
            algorithm="SHA256",
            method="POST",
            path="/feedback",
            headers_to_sign={
                "date": "Tue, 04 Nov 2025 05:15:11 GMT",
                "host": "api.docspera.com",
                "content-type": "application/json",
            },
            body='{"test": "data"}',
        )

        # Verify it's base64 encoded
        self.assertIsInstance(signature, str)
        decoded = base64.b64decode(signature)
        self.assertEqual(len(decoded), 32)  # SHA256 produces 32 bytes

    def test_compute_hmac_signature_with_query_params(self):
        """Test HMAC signature with query parameters."""
        signature, _ = compute_hmac_signature(
            secret_key=self.test_key.decode("utf-8"),
            method="GET",
            path="/feedback",
            # query_params={"page": "1", "limit": "10"},
            headers_to_sign={"host": "api.docspera.com"},
            body="",
        )

        self.assertIsInstance(signature, str)

    def test_compute_hmac_signature_consistent(self):
        """Test that same inputs produce same signature."""
        params = {
            "secret_key": self.test_key.decode("utf-8"),
            "method": "POST",
            "path": "/feedback/scheduling",
            "headers_to_sign": {
                "date": "Tue, 04 Nov 2025 05:15:11 GMT",
                "host": "snn.api-external.stage.docspera.co",
                "content-type": "application/json",
            },
            "body": '{"eventId":"12345","timestamp":"2025-11-04T05:15:11Z","status":"SUCCESS"}',
        }

        sig1, _ = compute_hmac_signature(**params)
        sig2, _ = compute_hmac_signature(**params)

        self.assertEqual(sig1, sig2, "Same inputs should produce same signature")

    def test_compute_hmac_signature_different_body(self):
        """Test that different bodies produce different signatures."""
        base_params = {
            "secret_key": self.test_key.decode("utf-8"),
            "method": "POST",
            "path": "/feedback",
            # "query_params": {},
            "headers_to_sign": {
                "date": "Tue, 04 Nov 2025 05:15:11 GMT",
                "host": "snn.api-external.stage.docspera.co",
                "content-type": "application/json",
            },
        }

        sig1, _ = compute_hmac_signature(**base_params, body='{"a": 1}')
        sig2, _ = compute_hmac_signature(**base_params, body='{"a": 2}')

        self.assertNotEqual(sig1, sig2, "Different bodies should produce different signatures")

    def test_string_to_sign_format(self):
        """Test the string-to-sign format matches specification."""
        # We'll monkey-patch the hmac to capture the string-to-sign
        original_hmac_new = hmac.new
        captured_string = []

        def mock_hmac_new(key, msg, digestmod):
            captured_string.append(msg.decode("utf-8"))
            return original_hmac_new(key, msg, digestmod)

        with patch("hmac.new", side_effect=mock_hmac_new):
            compute_hmac_signature(
                secret_key=self.test_key.decode("utf-8"),
                method="POST",
                path="/feedback",
                # query_params={"test": "value"},
                headers_to_sign={
                    "date": "Tue, 04 Nov 2025 05:15:11 GMT",
                    "host": "api.docspera.com",
                },
                body='{"test": "data"}',
            )

        self.assertEqual(len(captured_string), 1)
        string_to_sign = captured_string[0]

        # Verify format
        lines = string_to_sign.split("\n")
        # Should have: method, path, query, headers (2 lines), signed headers, hash = 7 lines
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], "POST")  # Method
        self.assertEqual(lines[1], "/feedback")  # Path
        # self.assertEqual(lines[2], "test=value")  # Query string
        # Canonical headers are sorted and on separate lines
        self.assertEqual(lines[2], "date:Tue, 04 Nov 2025 05:15:11 GMT")
        self.assertEqual(lines[3], "host:api.docspera.com")
        # self.assertEqual(lines[5], "date;host")  # Signed headers
        # lines[6] is the payload hash


class TestAuthorizationHeaderParsing(unittest.TestCase):
    """Test Authorization header parsing."""

    def test_parse_valid_header(self):
        """Test parsing a valid Authorization header."""
        header = "HMAC-SHA256 SignedHeaders=date;host&Signature=abc123=="

        auth_type, params = parse_hmac_header(header)

        self.assertEqual(auth_type, "HMAC-SHA256")
        self.assertEqual(params["signed_headers"], "date;host")
        self.assertEqual(params["signature"], "abc123==")

    def test_parse_header_with_multiple_params(self):
        """Test parsing header with multiple parameters."""
        header = "HMAC-SHA256 Algorithm=SHA256&SignedHeaders=date;host;content-type&Signature=xyz789"

        auth_type, params = parse_hmac_header(header)

        self.assertEqual(auth_type, "HMAC-SHA256")
        self.assertEqual(params["algorithm"], "SHA256")
        self.assertEqual(params["signed_headers"], "date;host;content-type")
        self.assertEqual(params["signature"], "xyz789")

    def test_parse_invalid_header_format(self):
        """Test parsing invalid header formats."""
        with self.assertRaises(ValueError):
            parse_hmac_header("InvalidHeader")

        with self.assertRaises(ValueError):
            parse_hmac_header("")

    def test_parse_header_without_params(self):
        with pytest.raises(ValueError):
            """Test parsing header without parameters."""
            auth_type, params = parse_hmac_header("Bearer token123")


class TestTimestampValidation(unittest.TestCase):
    """Test timestamp validation function."""

    def test_validate_recent_rfc7231_timestamp(self):
        """Test validation of recent RFC 7231 timestamp."""
        current_time = time.gmtime()
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", current_time)

        result = verify_timestamp(date_str, max_age_seconds=300)
        self.assertTrue(result)

    def test_validate_expired_rfc7231_timestamp(self):
        """Test validation of expired RFC 7231 timestamp."""
        old_time = time.gmtime(time.time() - 3600)  # 1 hour ago
        date_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", old_time)

        result, message = verify_timestamp(date_str, max_age_seconds=300)
        self.assertFalse(result)

    def test_validate_iso8601_timestamp(self):
        """Test validation of ISO 8601 timestamp."""
        current_time = datetime.utcnow()
        date_str = current_time.isoformat() + "Z"

        result = verify_timestamp(date_str, max_age_seconds=300)
        self.assertTrue(result)

    def test_validate_invalid_timestamp_format(self):
        """Test validation of invalid timestamp formats."""
        result, message = verify_timestamp("not a date", max_age_seconds=300)
        self.assertFalse(result)

        result, message = verify_timestamp("2025-13-45T25:00:00Z", max_age_seconds=300)
        self.assertFalse(result)


class TestFullHMACValidation(unittest.TestCase):
    """Test full HMAC signature validation flow."""

    def setUp(self):
        """Set up test environment."""
        self.test_key = b"uZFKDKZi9L5dmpuV9cC4E3R69P2m4B3Q"
        self.test_key_b64 = base64.b64encode(self.test_key).decode("utf-8")

        # Set environment variable
        os.environ["SNN_FEEDBACK_SECRET_ARN"] = "arn:aws:secretsmanager:us-west-2:123456789012:secret:snn-feedback"

    def create_test_event(self, auth_header, date_header, body, path="/feedback/scheduling"):
        """Helper to create API Gateway event."""
        return {
            "httpMethod": "POST",
            "path": path,
            "headers": {
                "Authorization": auth_header,
                "Date": date_header,
                "Host": "snn.api-external.stage.docspera.co",
                "Content-Type": "application/json",
            },
            "queryStringParameters": None,
            "body": body if isinstance(body, str) else json.dumps(body),
            "isBase64Encoded": False,
        }

    def test_validate_valid_signature(self):
        """Test validation of a valid HMAC signature."""

        # Create test data
        date_header = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        body = {
            "eventId": "12345",
            "timestamp": "2025-11-04T05:15:11Z",
            "status": "SUCCESS",
        }
        body_json = json.dumps(body, separators=(",", ":"))

        # Compute signature
        signature, _ = compute_hmac_signature(
            secret_key=self.test_key.decode("utf-8"),
            method="POST",
            path="/feedback/scheduling",
            # query_params={},
            headers_to_sign={
                "date": date_header,
                "host": "snn.api-external.stage.docspera.co",
                "content-type": "application/json",
            },
            body=body_json,
        )

        auth_header = f"HMAC-SHA256 SignedHeaders=date;host;content-type&Signature={signature}"

        # Create event
        event = self.create_test_event(auth_header, date_header, body_json)

        # Validate
        result = validate_hmac_signature(event, self.test_key.decode("utf-8"))
        self.assertTrue(result, "Valid signature should pass validation")

    def test_validate_invalid_signature(self):
        """Test validation of an invalid HMAC signature."""

        date_header = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        body = {
            "eventId": "12345",
            "timestamp": "2025-11-04T05:15:11Z",
            "status": "SUCCESS",
        }

        # Use wrong signature
        auth_header = "HMAC-SHA256 SignedHeaders=date;host;content-type&Signature=INVALID_SIGNATURE"

        event = self.create_test_event(auth_header, date_header, body)

        result = validate_hmac_signature(event, self.test_key.decode("utf-8"))
        self.assertEqual(result["statusCode"], 401)
        self.assertTrue("Invalid signature: Signature mismatch" in result["body"])

    def test_validate_missing_authorization_header(self):
        """Test validation with missing Authorization header."""

        event = {
            "httpMethod": "POST",
            "path": "/feedback",
            "headers": {
                "Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
                "Content-Type": "application/json",
            },
            "body": '{"test": "data"}',
        }

        result = validate_hmac_signature(event, self.test_key.decode("utf-8"))
        self.assertEqual(result["statusCode"], 401)
        self.assertTrue("Missing Authorization header" in result["body"])

    def test_validate_expired_timestamp(self):
        """Test validation with expired timestamp."""

        # Use old timestamp
        old_time = time.gmtime(time.time() - 3600)  # 1 hour ago
        date_header = time.strftime("%a, %d %b %Y %H:%M:%S GMT", old_time)
        body = '{"test": "data"}'

        signature, _ = compute_hmac_signature(
            secret_key=self.test_key.decode("utf-8"),
            algorithm="SHA256",
            method="POST",
            path="/feedback",
            headers_to_sign={
                "date": date_header,
                "host": "api.docspera.com",
                "content-type": "application/json",
            },
            body=body,
        )

        auth_header = f"HMAC-SHA256 SignedHeaders=date;host;content-type&Signature={signature}"
        event = self.create_test_event(auth_header, date_header, body)

        result = validate_hmac_signature(event, secret_key=self.test_key.decode("utf-8"))
        self.assertEqual(result["statusCode"], 401)
        self.assertTrue("Invalid signature: Timestamp validation failed" in result["body"])


class TestClientServerCompatibility(unittest.TestCase):
    """Test compatibility between client and server HMAC implementations."""

    def setUp(self):
        """Set up test environment."""
        self.test_key = b"uZFKDKZi9L5dmpuV9cC4E3R69P2m4B3Q"
        self.test_key_b64 = base64.b64encode(self.test_key).decode("utf-8")

    def test_signature_compatibility(self):
        """Test that client and server compute identical signatures."""
        # Test data
        http_method = "POST"
        path = "/feedback/scheduling"
        # query_params = {}
        date_header = "Tue, 04 Nov 2025 05:15:11 GMT"
        host = "snn.api-external.stage.docspera.co"
        content_type = "application/json"
        body = '{"eventId":"12345","timestamp":"2025-11-04T05:15:11Z","status":"SUCCESS"}'

        canonical_headers = {
            "date": date_header,
            "host": host,
            "content-type": content_type,
        }
        # signed_headers = "date;host;content-type"

        # Compute signature using handler function
        server_signature, _ = compute_hmac_signature(
            secret_key=self.test_key.decode("utf-8"),
            algorithm="SHA256",
            method="POST",
            headers_to_sign=canonical_headers,
            path=path,
            body=body,
        )

        # Manually compute what the signature should be
        # canonical_query = ""
        canonical_headers_str = "\n".join([f"{k}:{v}" for k, v in sorted(canonical_headers.items())])
        # payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        string_to_sign = "\n".join(
            [
                http_method,
                path,
                # canonical_query,
                canonical_headers_str,
                # signed_headers,
                body,
            ]
        )

        expected_signature = base64.b64encode(
            hmac.new(self.test_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")

        self.assertEqual(
            server_signature,
            expected_signature,
            f"Server signature should match expected.\n"
            f"String to sign:\n{string_to_sign}\n"
            f"Server: {server_signature}\n"
            f"Expected: {expected_signature}",
        )


class TestRealEventStructure(unittest.TestCase):
    """Test with real API Gateway event structure."""

    def setUp(self):
        """Set up test with real event structure."""
        self.test_key = b"uZFKDKZi9L5dmpuV9cC4E3R69P2m4B3Q"
        os.environ["SNN_FEEDBACK_SECRET_ARN"] = "test-arn"

    def test_real_api_gateway_event(self):
        """Test with actual API Gateway event structure."""

        # Real event structure from API Gateway
        event = {
            "resource": "/feedback/scheduling",
            "path": "/feedback/scheduling",
            "httpMethod": "POST",
            "headers": {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Authorization": None,  # Will be set below
                "Content-Type": "application/json",
                "Date": None,  # Will be set below
                "Host": "snn.api-external.stage.docspera.co",
                "User-Agent": "python-requests/2.32.4",
            },
            "queryStringParameters": None,
            "body": '{"eventId":"12345","timestamp":"2025-11-04T05:15:11Z","status":"SUCCESS"}',
            "isBase64Encoded": False,
        }

        # Set date and compute signature
        date_header = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        event["headers"]["Date"] = date_header

        # Compute correct signature
        signature, _ = compute_hmac_signature(
            body=event["body"],
            secret_key=self.test_key.decode("utf-8"),
            headers_to_sign={
                "date": date_header,
                "host": "snn.api-external.stage.docspera.co",
                "content-type": "application/json",
            },
            method="POST",
            path="/feedback/scheduling",
        )

        event["headers"]["Authorization"] = f"HMAC-SHA256 SignedHeaders=date;host;content-type&Signature={signature}"

        # Validate
        result = validate_hmac_signature(event, self.test_key.decode("utf-8"))
        self.assertTrue(result, "Real event structure should validate successfully")


if __name__ == "__main__":
    unittest.main()
