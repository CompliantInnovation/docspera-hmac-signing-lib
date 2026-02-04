"""
Unit tests for asymmetric key signing functionality.

Tests Ed25519 and RSA signature generation and verification.
"""

import base64
import unittest

from hmac_lib.asymmetric import (
    KeyType,
    compute_asymmetric_signature,
    create_signed_request_asymmetric,
    generate_key_pair,
    parse_asymmetric_header,
    verify_asymmetric_signature,
)


class TestKeyGeneration(unittest.TestCase):
    """Test key pair generation."""

    def test_generate_ed25519_key_pair(self):
        """Test Ed25519 key pair generation."""
        private_key, public_key = generate_key_pair(KeyType.ED25519)

        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertIn(b"PRIVATE KEY", private_key)
        self.assertIn(b"PUBLIC KEY", public_key)

    def test_generate_rsa_key_pair(self):
        """Test RSA key pair generation."""
        private_key, public_key = generate_key_pair(KeyType.RSA, key_size=2048)

        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertIn(b"PRIVATE KEY", private_key)
        self.assertIn(b"PUBLIC KEY", public_key)

    def test_generate_rsa_different_sizes(self):
        """Test RSA key generation with different sizes."""
        for key_size in (2048, 3072, 4096):
            private_key, public_key = generate_key_pair(KeyType.RSA, key_size=key_size)
            self.assertIsInstance(private_key, bytes)
            self.assertIsInstance(public_key, bytes)

    def test_generate_rsa_invalid_size(self):
        """Test RSA key generation with invalid size."""
        with self.assertRaises(ValueError):
            generate_key_pair(KeyType.RSA, key_size=1024)

    def test_generate_invalid_key_type(self):
        """Test key generation with invalid type."""
        with self.assertRaises(ValueError):
            generate_key_pair("InvalidType")

    def test_default_key_type_is_ed25519(self):
        """Test that default key type is Ed25519."""
        private_key, public_key = generate_key_pair()
        # Ed25519 keys are smaller, should work for signing/verifying
        signature, _ = compute_asymmetric_signature(
            body="test",
            private_key_pem=private_key,
            key_type=KeyType.ED25519,
        )
        is_valid, _ = verify_asymmetric_signature(
            body="test",
            public_key_pem=public_key,
            signature=signature,
            key_type=KeyType.ED25519,
        )
        self.assertTrue(is_valid)


class TestEd25519Signing(unittest.TestCase):
    """Test Ed25519 signature generation and verification."""

    def setUp(self):
        """Generate test key pair."""
        self.private_key, self.public_key = generate_key_pair(KeyType.ED25519)

    def test_sign_and_verify_basic(self):
        """Test basic signature and verification."""
        body = '{"test": "data"}'
        signature, canonical_string = compute_asymmetric_signature(
            body=body,
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
        )

        self.assertIsInstance(signature, str)
        # Ed25519 signatures are 64 bytes
        decoded = base64.b64decode(signature)
        self.assertEqual(len(decoded), 64)

        is_valid, error = verify_asymmetric_signature(
            body=body,
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.ED25519,
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_sign_with_headers(self):
        """Test signature with headers."""
        body = '{"test": "data"}'
        headers = {
            "date": "Wed, 04 Feb 2026 12:00:00 GMT",
            "host": "api.example.com",
            "content-type": "application/json",
        }

        signature, _ = compute_asymmetric_signature(
            body=body,
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
            headers_to_sign=headers,
            method="POST",
            path="/webhook",
        )

        is_valid, error = verify_asymmetric_signature(
            body=body,
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.ED25519,
            headers_to_sign=headers,
            method="POST",
            path="/webhook",
        )
        self.assertTrue(is_valid)

    def test_signature_changes_with_body(self):
        """Test that different bodies produce different signatures."""
        sig1, _ = compute_asymmetric_signature(
            body='{"a": 1}',
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
        )
        sig2, _ = compute_asymmetric_signature(
            body='{"a": 2}',
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
        )
        self.assertNotEqual(sig1, sig2)

    def test_verify_tampered_body_fails(self):
        """Test that verification fails with tampered body."""
        signature, _ = compute_asymmetric_signature(
            body='{"original": "data"}',
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
        )

        is_valid, error = verify_asymmetric_signature(
            body='{"tampered": "data"}',
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.ED25519,
        )
        self.assertFalse(is_valid)
        self.assertIn("Signature verification failed", error)

    def test_verify_wrong_key_fails(self):
        """Test that verification fails with wrong public key."""
        signature, _ = compute_asymmetric_signature(
            body='{"test": "data"}',
            private_key_pem=self.private_key,
            key_type=KeyType.ED25519,
        )

        # Generate different key pair
        _, wrong_public_key = generate_key_pair(KeyType.ED25519)

        is_valid, error = verify_asymmetric_signature(
            body='{"test": "data"}',
            public_key_pem=wrong_public_key,
            signature=signature,
            key_type=KeyType.ED25519,
        )
        self.assertFalse(is_valid)


class TestRSASigning(unittest.TestCase):
    """Test RSA signature generation and verification."""

    def setUp(self):
        """Generate test key pair."""
        self.private_key, self.public_key = generate_key_pair(KeyType.RSA, key_size=2048)

    def test_sign_and_verify_basic(self):
        """Test basic RSA signature and verification."""
        body = '{"test": "data"}'
        signature, _ = compute_asymmetric_signature(
            body=body,
            private_key_pem=self.private_key,
            key_type=KeyType.RSA,
        )

        self.assertIsInstance(signature, str)

        is_valid, error = verify_asymmetric_signature(
            body=body,
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.RSA,
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_sign_with_headers(self):
        """Test RSA signature with headers."""
        body = '{"test": "data"}'
        headers = {
            "date": "Wed, 04 Feb 2026 12:00:00 GMT",
            "host": "api.example.com",
        }

        signature, _ = compute_asymmetric_signature(
            body=body,
            private_key_pem=self.private_key,
            key_type=KeyType.RSA,
            headers_to_sign=headers,
        )

        is_valid, _ = verify_asymmetric_signature(
            body=body,
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.RSA,
            headers_to_sign=headers,
        )
        self.assertTrue(is_valid)

    def test_verify_tampered_body_fails(self):
        """Test that verification fails with tampered body."""
        signature, _ = compute_asymmetric_signature(
            body='{"original": "data"}',
            private_key_pem=self.private_key,
            key_type=KeyType.RSA,
        )

        is_valid, error = verify_asymmetric_signature(
            body='{"tampered": "data"}',
            public_key_pem=self.public_key,
            signature=signature,
            key_type=KeyType.RSA,
        )
        self.assertFalse(is_valid)


class TestKeyTypeMismatch(unittest.TestCase):
    """Test handling of key type mismatches."""

    def test_ed25519_key_with_rsa_type_fails(self):
        """Test that Ed25519 key fails when RSA type is specified."""
        private_key, public_key = generate_key_pair(KeyType.ED25519)

        with self.assertRaises(ValueError) as ctx:
            compute_asymmetric_signature(
                body="test",
                private_key_pem=private_key,
                key_type=KeyType.RSA,
            )
        self.assertIn("Key type mismatch", str(ctx.exception))

    def test_rsa_key_with_ed25519_type_fails(self):
        """Test that RSA key fails when Ed25519 type is specified."""
        private_key, public_key = generate_key_pair(KeyType.RSA)

        with self.assertRaises(ValueError) as ctx:
            compute_asymmetric_signature(
                body="test",
                private_key_pem=private_key,
                key_type=KeyType.ED25519,
            )
        self.assertIn("Key type mismatch", str(ctx.exception))


class TestAsymmetricHeaderParsing(unittest.TestCase):
    """Test asymmetric Authorization header parsing."""

    def test_parse_ed25519_header(self):
        """Test parsing Ed25519 header."""
        header = "ASYMMETRIC-Ed25519 KeyId=key123&SignedHeaders=date;host&Signature=abc123=="

        auth_type, params = parse_asymmetric_header(header)

        self.assertEqual(auth_type, "ASYMMETRIC-Ed25519")
        self.assertEqual(params["key_type"], KeyType.ED25519)
        self.assertEqual(params["key_id"], "key123")
        self.assertEqual(params["signed_headers"], "date;host")
        self.assertEqual(params["signature"], "abc123==")

    def test_parse_rsa_header(self):
        """Test parsing RSA header."""
        header = "ASYMMETRIC-RSA KeyId=rsa-key-1&SignedHeaders=date&Signature=xyz789"

        auth_type, params = parse_asymmetric_header(header)

        self.assertEqual(params["key_type"], KeyType.RSA)
        self.assertEqual(params["key_id"], "rsa-key-1")

    def test_parse_header_missing_keyid(self):
        """Test parsing header without KeyId fails."""
        header = "ASYMMETRIC-Ed25519 SignedHeaders=date&Signature=abc123"

        with self.assertRaises(ValueError) as ctx:
            parse_asymmetric_header(header)
        self.assertIn("Missing KeyId", str(ctx.exception))

    def test_parse_header_missing_signature(self):
        """Test parsing header without Signature fails."""
        header = "ASYMMETRIC-Ed25519 KeyId=key123&SignedHeaders=date"

        with self.assertRaises(ValueError) as ctx:
            parse_asymmetric_header(header)
        self.assertIn("Missing Signature", str(ctx.exception))

    def test_parse_invalid_header_format(self):
        """Test parsing invalid header format."""
        with self.assertRaises(ValueError):
            parse_asymmetric_header("InvalidHeader")

        with self.assertRaises(ValueError):
            parse_asymmetric_header("")

    def test_parse_unsupported_key_type(self):
        """Test parsing header with unsupported key type."""
        header = "ASYMMETRIC-UNKNOWN KeyId=key1&Signature=sig"

        with self.assertRaises(ValueError) as ctx:
            parse_asymmetric_header(header)
        self.assertIn("Unsupported key type", str(ctx.exception))


class TestCreateSignedRequestAsymmetric(unittest.TestCase):
    """Test creating signed requests with asymmetric keys."""

    def setUp(self):
        """Generate test key pairs."""
        self.ed25519_private, self.ed25519_public = generate_key_pair(KeyType.ED25519)
        self.rsa_private, self.rsa_public = generate_key_pair(KeyType.RSA)

    def test_create_signed_request_ed25519(self):
        """Test creating a signed request with Ed25519."""
        headers = create_signed_request_asymmetric(
            body='{"data": "test"}',
            private_key_pem=self.ed25519_private,
            key_id="my-key-v1",
            key_type=KeyType.ED25519,
        )

        self.assertIn("Authorization", headers)
        self.assertIn("Date", headers)
        self.assertIn("ASYMMETRIC-Ed25519", headers["Authorization"])
        self.assertIn("KeyId=my-key-v1", headers["Authorization"])

    def test_create_signed_request_rsa(self):
        """Test creating a signed request with RSA."""
        headers = create_signed_request_asymmetric(
            body='{"data": "test"}',
            private_key_pem=self.rsa_private,
            key_id="rsa-key-1",
            key_type=KeyType.RSA,
        )

        self.assertIn("ASYMMETRIC-RSA", headers["Authorization"])
        self.assertIn("KeyId=rsa-key-1", headers["Authorization"])

    def test_create_signed_request_with_additional_headers(self):
        """Test creating a signed request with additional headers."""
        headers = create_signed_request_asymmetric(
            body='{"data": "test"}',
            private_key_pem=self.ed25519_private,
            key_id="key1",
            additional_headers={
                "Host": "api.example.com",
                "Content-Type": "application/json",
            },
        )

        self.assertIn("Host", headers)
        self.assertIn("Content-Type", headers)
        self.assertIn("content-type", headers["Authorization"].lower())
        self.assertIn("host", headers["Authorization"].lower())

    def test_create_signed_request_without_date(self):
        """Test creating a signed request without Date header."""
        headers = create_signed_request_asymmetric(
            body='{"data": "test"}',
            private_key_pem=self.ed25519_private,
            key_id="key1",
            include_date=False,
        )

        self.assertNotIn("Date", headers)

    def test_roundtrip_sign_and_verify(self):
        """Test full roundtrip: create signed request, parse, verify."""
        body = '{"event": "test", "id": 123}'

        # Client creates signed request
        headers = create_signed_request_asymmetric(
            body=body,
            private_key_pem=self.ed25519_private,
            key_id="client-key-1",
            key_type=KeyType.ED25519,
            additional_headers={"Host": "api.server.com"},
            method="POST",
            path="/webhook",
        )

        # Server parses and verifies
        auth_type, params = parse_asymmetric_header(headers["Authorization"])

        # Extract signed headers
        signed_header_names = params["signed_headers"].split(";")
        headers_to_verify = {}
        for name in signed_header_names:
            for h_name, h_value in headers.items():
                if h_name.lower() == name.lower():
                    headers_to_verify[name] = h_value
                    break

        is_valid, error = verify_asymmetric_signature(
            body=body,
            public_key_pem=self.ed25519_public,
            signature=params["signature"],
            key_type=params["key_type"],
            headers_to_sign=headers_to_verify,
            method="POST",
            path="/webhook",
        )

        self.assertTrue(is_valid, f"Verification failed: {error}")


if __name__ == "__main__":
    unittest.main()
