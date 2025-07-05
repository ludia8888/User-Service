"""
Security tests for User Service
Tests authentication, authorization, and security features
"""
import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import app
from core.config import settings
from models.user import Base, User
from services.auth_service import AuthService
from services.user_service import UserService
from core.validators import validate_password


# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def test_db():
    """Create test database"""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with AsyncSessionLocal() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
async def client():
    """Create test client"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def test_user(test_db):
    """Create test user"""
    user_service = UserService(test_db)
    user = await user_service.create_user(
        username="testuser",
        email="test@example.com",
        password="Test@Password123",
        full_name="Test User",
        created_by="test"
    )
    await test_db.commit()
    return user


@pytest.fixture
async def auth_token(test_db, test_user):
    """Create auth token for test user"""
    auth_service = AuthService(test_db)
    token = auth_service.create_access_token(test_user)
    return token


class TestAuthentication:
    """Test authentication functionality"""
    
    @pytest.mark.asyncio
    async def test_login_success(self, client, test_user):
        """Test successful login"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "testuser",
                "password": "Test@Password123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, test_user):
        """Test login with invalid credentials"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "nonexistent",
                "password": "password"
            }
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client, test_user):
        """Test rate limiting on login endpoint"""
        # Make multiple requests
        for i in range(12):  # Exceed the 10/minute limit
            response = await client.post(
                "/auth/login",
                data={
                    "username": "testuser",
                    "password": "wrongpassword"
                }
            )
        
        # Last request should be rate limited
        assert response.status_code == 429
        assert "X-RateLimit-Limit" in response.headers


class TestPasswordSecurity:
    """Test password security features"""
    
    def test_password_validation_success(self):
        """Test password validation with valid password"""
        valid_password = "SecureP@ssw0rd123"
        result = validate_password(valid_password)
        assert result == valid_password
    
    def test_password_validation_too_short(self):
        """Test password validation with short password"""
        with pytest.raises(ValueError) as exc:
            validate_password("Short1!")
        assert "at least 8 characters" in str(exc.value)
    
    def test_password_validation_no_uppercase(self):
        """Test password validation without uppercase"""
        with pytest.raises(ValueError) as exc:
            validate_password("password123!")
        assert "uppercase letter" in str(exc.value)
    
    def test_password_validation_no_special(self):
        """Test password validation without special character"""
        with pytest.raises(ValueError) as exc:
            validate_password("Password123")
        assert "special character" in str(exc.value)
    
    def test_password_validation_common_pattern(self):
        """Test password validation with common patterns"""
        with pytest.raises(ValueError) as exc:
            validate_password("Password123!")
        assert "common patterns" in str(exc.value)
    
    @pytest.mark.asyncio
    async def test_password_change_validation(self, client, auth_token):
        """Test password change with validation"""
        response = await client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "old_password": "Test@Password123",
                "new_password": "NewSecure@Pass456"
            }
        )
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_password_change_weak_password(self, client, auth_token):
        """Test password change with weak password"""
        response = await client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "old_password": "Test@Password123",
                "new_password": "weak"
            }
        )
        assert response.status_code == 400


class TestInputValidation:
    """Test input validation"""
    
    @pytest.mark.asyncio
    async def test_register_validation_success(self, client):
        """Test registration with valid data"""
        response = await client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "SecureP@ss123",
                "full_name": "New User"
            }
        )
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_register_invalid_username(self, client):
        """Test registration with invalid username"""
        response = await client.post(
            "/auth/register",
            json={
                "username": "a",  # Too short
                "email": "test@example.com",
                "password": "SecureP@ss123"
            }
        )
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_register_invalid_email(self, client):
        """Test registration with invalid email"""
        response = await client.post(
            "/auth/register",
            json={
                "username": "validuser",
                "email": "invalid-email",
                "password": "SecureP@ss123"
            }
        )
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, client):
        """Test SQL injection protection"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "admin' OR '1'='1",
                "password": "password"
            }
        )
        assert response.status_code == 401


class TestJWTSecurity:
    """Test JWT token security"""
    
    @pytest.mark.asyncio
    async def test_jwt_token_structure(self, test_db, test_user):
        """Test JWT token contains required claims"""
        auth_service = AuthService(test_db)
        token = auth_service.create_access_token(test_user)
        
        # Decode without verification to check structure
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        
        assert "sub" in payload
        assert "username" in payload
        assert "exp" in payload
        assert "iat" in payload
        assert "sid" in payload  # Session ID
    
    @pytest.mark.asyncio
    async def test_expired_token(self, client, test_db, test_user):
        """Test expired token rejection"""
        auth_service = AuthService(test_db)
        
        # Create expired token
        settings.ACCESS_TOKEN_EXPIRE_MINUTES = -1
        expired_token = auth_service.create_access_token(test_user)
        settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        
        response = await client.get(
            "/auth/userinfo",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_invalid_token(self, client):
        """Test invalid token rejection"""
        response = await client.get(
            "/auth/userinfo",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401


class TestSecurityHeaders:
    """Test security headers"""
    
    @pytest.mark.asyncio
    async def test_security_headers_present(self, client):
        """Test security headers are present"""
        response = await client.get("/health")
        
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert "Permissions-Policy" in response.headers


class TestMFA:
    """Test Multi-Factor Authentication"""
    
    @pytest.mark.asyncio
    async def test_mfa_setup(self, client, auth_token):
        """Test MFA setup process"""
        response = await client.post(
            "/auth/mfa/setup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code" in data
    
    @pytest.mark.asyncio
    async def test_mfa_enable_invalid_code(self, client, auth_token):
        """Test MFA enable with invalid code"""
        # Setup MFA first
        setup_response = await client.post(
            "/auth/mfa/setup",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Try to enable with invalid code
        response = await client.post(
            "/auth/mfa/enable",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"code": "000000"}
        )
        assert response.status_code == 400


class TestAuditLogging:
    """Test audit logging functionality"""
    
    @pytest.mark.asyncio
    async def test_login_audit_log(self, client, test_user, test_db):
        """Test login creates audit log"""
        # Perform login
        response = await client.post(
            "/auth/login",
            data={
                "username": "testuser",
                "password": "Test@Password123"
            }
        )
        assert response.status_code == 200
        
        # Check audit log was created
        # Note: In real implementation, check database or log files
        # This is a placeholder for the actual implementation
    
    @pytest.mark.asyncio
    async def test_failed_login_audit_log(self, client, test_user):
        """Test failed login creates audit log"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401
        # Check audit log for failed attempt


if __name__ == "__main__":
    pytest.main([__file__])