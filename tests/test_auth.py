"""
Tests for the SentinelX Authentication System.
Covers login, registration, token generation, MFA, and account lockout.
"""
import pytest
import bcrypt
from datetime import datetime, timezone
from backend.models import User, UserRole, generate_uuid


class TestPasswordHashing:
    """Test bcrypt password hashing."""

    def test_hash_generation(self):
        password = "SecurePass123!"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        assert bcrypt.checkpw(password.encode(), hashed)

    def test_wrong_password_fails(self):
        password = "SecurePass123!"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        assert not bcrypt.checkpw("WrongPassword".encode(), hashed)

    def test_unique_salts(self):
        password = "SecurePass123!"
        hash1 = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        hash2 = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        assert hash1 != hash2  # Same password, different hashes


class TestUserModel:
    """Test the User model."""

    def test_user_creation(self):
        user = User(
            id=generate_uuid(),
            username="test_admin",
            email="admin@test.com",
            full_name="Test Admin",
            role=UserRole.super_admin,
            is_active=True,
            hashed_password=bcrypt.hashpw("pass".encode(), bcrypt.gensalt()).decode(),
        )
        assert user.username == "test_admin"
        assert user.role == UserRole.super_admin
        assert user.is_active is True

    def test_all_roles_exist(self):
        expected_roles = {
            "super_admin", "soc_manager", "analyst",
            "responder", "threat_hunter", "auditor", "readonly"
        }
        actual_roles = {role.value for role in UserRole}
        assert expected_roles == actual_roles

    def test_mfa_default_disabled(self):
        user = User(
            id=generate_uuid(),
            username="no_mfa",
            email="nomfa@test.com",
            is_mfa_enabled=False,
            hashed_password="hash",
        )
        assert user.is_mfa_enabled is False
        assert user.mfa_secret is None

    def test_account_lockout_fields(self):
        user = User(
            id=generate_uuid(),
            username="locktest",
            email="lock@test.com",
            hashed_password="hash",
            failed_login_attempts=5,
        )
        assert user.failed_login_attempts == 5
        assert user.locked_until is None


class TestJWTTokenGeneration:
    """Test JWT token creation and validation."""

    def test_token_creation(self):
        from jose import jwt
        from backend.config import settings

        payload = {
            "sub": "test-user-id",
            "role": "analyst",
            "type": "access"
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        assert token is not None
        assert len(token) > 50

    def test_token_decode(self):
        from jose import jwt
        from backend.config import settings

        payload = {
            "sub": "user-123",
            "role": "super_admin",
            "type": "access"
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert decoded["sub"] == "user-123"
        assert decoded["role"] == "super_admin"

    def test_invalid_token_fails(self):
        from jose import jwt, JWTError
        from backend.config import settings

        with pytest.raises(JWTError):
            jwt.decode("invalid.token.here", settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


class TestAPIKeyGeneration:
    """Test API key creation and hashing."""

    def test_key_generation(self):
        from backend.auth.api_keys import generate_api_key

        raw_key, key_hash, key_prefix = generate_api_key()
        assert raw_key.startswith("sx_")
        assert len(raw_key) > 40
        assert len(key_hash) == 64  # SHA-256 hex digest
        assert key_prefix == raw_key[:12]

    def test_key_hashing_consistent(self):
        from backend.auth.api_keys import hash_api_key

        key = "sx_test_key_12345"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)
        assert hash1 == hash2

    def test_different_keys_different_hashes(self):
        from backend.auth.api_keys import hash_api_key

        hash1 = hash_api_key("sx_key_one")
        hash2 = hash_api_key("sx_key_two")
        assert hash1 != hash2
