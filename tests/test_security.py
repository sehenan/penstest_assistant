"""
Unit Tests for Security Module
"""
import pytest
import time
from unittest.mock import Mock, patch
from fastapi import HTTPException, Request
from app.core import security
from app.core.security import (
    RateLimiter, verify_password, get_password_hash,
    create_access_token, decode_access_token, rate_limit
)


@pytest.fixture(autouse=True)
def _fresh_rate_limiter(monkeypatch):
    """Isole chaque test : remplace le singleton global par un limiteur mémoire
    neuf. Sinon l'état Redis persistant (si Redis tourne) contamine les tests de
    rate-limiting entre exécutions. Le décorateur résout `rate_limiter` dans les
    globals du module à chaque appel, donc le monkeypatch prend effet."""
    monkeypatch.setattr(security, "rate_limiter", RateLimiter(use_redis=False))

class TestPasswordHashing:
    """Test password hashing and verification"""

    def test_password_hashing(self):
        """Test that password hashing works correctly"""
        password = "test_password_123"
        hashed = get_password_hash(password)

        assert hashed != password
        assert hashed.startswith("$2b$")  # bcrypt hash prefix

    def test_password_verification(self):
        """Test password verification"""
        password = "test_password_123"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True
        assert verify_password("wrong_password", hashed) is False

class TestJWTToken:
    """Test JWT token creation and decoding"""

    def test_create_access_token(self):
        """Test JWT token creation"""
        data = {"sub": "user123", "role": "admin"}
        token = create_access_token(data)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_valid_token(self):
        """Test decoding a valid token"""
        data = {"sub": "user123", "role": "admin"}
        token = create_access_token(data)

        decoded = decode_access_token(token)

        assert decoded["sub"] == "user123"
        assert decoded["role"] == "admin"

    def test_decode_invalid_token(self):
        """Test decoding an invalid token"""
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token("invalid_token")

        assert exc_info.value.status_code == 401

class TestRateLimiter:
    """Test rate limiting functionality"""

    def test_rate_limiter_basic(self):
        """Test basic rate limiting"""
        limiter = RateLimiter(use_redis=False)

        # First request should be allowed
        assert limiter.is_allowed("test_key", limit=2, window=60) is True

        # Second request should be allowed
        assert limiter.is_allowed("test_key", limit=2, window=60) is True

        # Third request should be blocked
        assert limiter.is_allowed("test_key", limit=2, window=60) is False

    def test_rate_limiter_different_keys(self):
        """Test rate limiting with different keys"""
        limiter = RateLimiter(use_redis=False)

        # Different keys should have independent limits
        assert limiter.is_allowed("key1", limit=1, window=60) is True
        assert limiter.is_allowed("key1", limit=1, window=60) is False

        assert limiter.is_allowed("key2", limit=1, window=60) is True
        assert limiter.is_allowed("key2", limit=1, window=60) is False

    def test_rate_limiter_window_expiry(self):
        """Test rate limiting window expiry"""
        limiter = RateLimiter(use_redis=False)

        # Make requests up to limit
        assert limiter.is_allowed("test_key", limit=2, window=1) is True
        assert limiter.is_allowed("test_key", limit=2, window=1) is True
        assert limiter.is_allowed("test_key", limit=2, window=1) is False

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert limiter.is_allowed("test_key", limit=2, window=1) is True

class TestRateLimitDecorator:
    """Test rate limiting decorator"""

    @pytest.mark.asyncio
    async def test_rate_limit_decorator(self):
        """Test rate limiting decorator on async function"""
        call_count = 0

        @rate_limit(limit=2, window=60)
        async def test_function():
            nonlocal call_count
            call_count += 1
            return "success"

        # Create mock request
        mock_request = Mock(spec=Request)
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"

        # First call should succeed
        result = await test_function(request=mock_request)
        assert result == "success"
        assert call_count == 1

        # Second call should succeed
        result = await test_function(request=mock_request)
        assert result == "success"
        assert call_count == 2

        # Third call should raise rate limit error
        with pytest.raises(HTTPException) as exc_info:
            await test_function(request=mock_request)

        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in str(exc_info.value.detail)

class TestSecurityIntegration:
    """Integration tests for security module"""

    def test_full_authentication_flow(self):
        """Test complete authentication flow"""
        # 1. Hash password
        password = "secure_password_123"
        hashed = get_password_hash(password)

        # 2. Verify password
        assert verify_password(password, hashed) is True

        # 3. Create token
        user_data = {"sub": "user123", "role": "user"}
        token = create_access_token(user_data)

        # 4. Decode token
        decoded = decode_access_token(token)

        assert decoded["sub"] == "user123"
        assert decoded["role"] == "user"

    def test_security_with_rate_limiting(self):
        """Test security features combined with rate limiting"""
        limiter = RateLimiter(use_redis=False)

        # Simulate user authentication
        user_id = "user123"
        password = "password123"
        hashed = get_password_hash(password)

        # Verify credentials
        assert verify_password(password, hashed) is True

        # Create token
        token = create_access_token({"sub": user_id, "role": "user"})

        # Apply rate limiting per user
        user_key = f"auth_attempts:{user_id}"
        assert limiter.is_allowed(user_key, limit=5, window=60) is True

        # Decode token
        decoded = decode_access_token(token)
        assert decoded["sub"] == user_id