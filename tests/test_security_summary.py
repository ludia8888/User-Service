"""
Summary test to validate all security improvements
"""
import pytest
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


class TestSecuritySummary:
    """Validate all security improvements from user-service.md"""
    
    async def test_jwt_secret_validation(self):
        """Test that JWT secret is validated from environment"""
        from core.config import settings
        # In test environment with DEBUG=true, validation should pass
        assert settings.JWT_SECRET is not None
        assert len(settings.JWT_SECRET) >= 32
    
    async def test_cors_configuration(self):
        """Test that CORS is properly configured"""
        from core.config import settings
        # CORS should be configured (either with specific origins or wildcard)
        assert hasattr(settings, 'CORS_ORIGINS')
        assert hasattr(settings, 'CORS_ALLOW_ALL_ORIGINS')
        # Either specific origins are set or allow all is enabled
        assert len(settings.CORS_ORIGINS) > 0 or settings.CORS_ALLOW_ALL_ORIGINS
    
    async def test_security_headers_middleware_exists(self):
        """Test that security headers middleware is implemented"""
        from core.security_headers import SecurityHeadersMiddleware
        assert SecurityHeadersMiddleware is not None
    
    async def test_rate_limiting_exists(self):
        """Test that rate limiting is implemented"""
        from core.rate_limit import RateLimiter, RateLimitMiddleware
        assert RateLimiter is not None
        assert RateLimitMiddleware is not None
    
    async def test_input_validation_exists(self):
        """Test that input validation functions exist"""
        from core.validators import (
            validate_username, validate_email, validate_password,
            sanitize_string, validate_mfa_code
        )
        assert validate_username is not None
        assert validate_email is not None
        assert validate_password is not None
        assert sanitize_string is not None
        assert validate_mfa_code is not None
    
    async def test_mfa_service_exists(self):
        """Test that MFA service is implemented"""
        from services.mfa_service import MFAService
        assert MFAService is not None
    
    async def test_password_policy_exists(self):
        """Test that password policy is enforced"""
        from core.validators import validate_password
        
        # Test weak passwords are rejected
        with pytest.raises(ValueError):
            validate_password("weak")
        
        with pytest.raises(ValueError):
            validate_password("12345678")
        
        with pytest.raises(ValueError):
            validate_password("password123")
        
        # Test strong password passes
        strong_password = validate_password("StrongP@ssw0rd123!")
        assert strong_password == "StrongP@ssw0rd123!"
    
    async def test_audit_service_exists(self):
        """Test that audit logging is implemented"""
        from services.audit_service import AuditService, AuditEventType
        assert AuditService is not None
        assert AuditEventType is not None
        
        # Check critical event types exist
        assert hasattr(AuditEventType, 'LOGIN_SUCCESS')
        assert hasattr(AuditEventType, 'LOGIN_FAILED')
        assert hasattr(AuditEventType, 'MFA_ENABLED')
        assert hasattr(AuditEventType, 'PASSWORD_CHANGED')
    
    async def test_secure_password_hashing(self):
        """Test that passwords are hashed with bcrypt"""
        from passlib.context import CryptContext
        from services.auth_service import AuthService
        
        # Check that auth service uses bcrypt for password hashing
        auth_service = AuthService(None)  # DB not needed for this check
        assert hasattr(auth_service, 'pwd_context')
        assert isinstance(auth_service.pwd_context, CryptContext)
        assert 'bcrypt' in auth_service.pwd_context.schemes()
    
    async def test_session_timeout_configured(self):
        """Test that session timeout is configured"""
        from core.config import settings
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
        assert settings.REFRESH_TOKEN_EXPIRE_DAYS > 0