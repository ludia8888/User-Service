"""
Integration tests for User Service
"""
import pytest
import asyncio
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


class TestAuthenticationIntegration:
    """Integration tests for authentication"""
    
    async def test_user_registration_flow(self, client: AsyncClient):
        """Test complete user registration flow"""
        # Register new user
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecureP@ssw0rd123",
            "full_name": "New User"
        }
        
        response = await client.post("/auth/register", json=user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["user"]["username"] == "newuser"
        assert data["user"]["email"] == "newuser@example.com"
        assert data["user"]["mfa_enabled"] is False
        assert "user" in data["user"]["roles"]
    
    async def test_duplicate_registration(self, client: AsyncClient, test_user_data):
        """Test duplicate user registration"""
        # First registration
        response = await client.post("/auth/register", json=test_user_data)
        assert response.status_code == 200
        
        # Try to register again with same username
        response = await client.post("/auth/register", json=test_user_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    async def test_login_flow(self, client: AsyncClient, registered_user, test_user_data):
        """Test login flow"""
        response = await client.post(
            "/auth/login",
            data={
                "username": test_user_data["username"],
                "password": test_user_data["password"]
            }
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
    
    async def test_invalid_login(self, client: AsyncClient, registered_user):
        """Test login with invalid credentials"""
        response = await client.post(
            "/auth/login",
            data={
                "username": "testuser",
                "password": "WrongPassword123!"
            }
        )
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    async def test_token_refresh(self, client: AsyncClient, registered_user, test_user_data):
        """Test token refresh flow"""
        # Login first
        login_response = await client.post(
            "/auth/login",
            data={
                "username": test_user_data["username"],
                "password": test_user_data["password"]
            }
        )
        refresh_token = login_response.json()["refresh_token"]
        
        # Refresh token
        response = await client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
    
    async def test_user_info(self, client: AsyncClient, auth_headers):
        """Test getting user info"""
        response = await client.get("/auth/userinfo", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "user_id" in data
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert "roles" in data
        assert "permissions" in data
    
    async def test_logout(self, client: AsyncClient, auth_headers):
        """Test logout"""
        response = await client.post("/auth/logout", headers=auth_headers)
        assert response.status_code == 200
        assert "Successfully logged out" in response.json()["message"]


class TestPasswordManagement:
    """Test password-related features"""
    
    async def test_password_change(self, client: AsyncClient, auth_headers, test_user_data):
        """Test password change"""
        response = await client.post(
            "/auth/change-password",
            headers=auth_headers,
            json={
                "old_password": test_user_data["password"],
                "new_password": "NewSecure@Pass456"
            }
        )
        assert response.status_code == 200
        
        # Try login with new password
        response = await client.post(
            "/auth/login",
            data={
                "username": test_user_data["username"],
                "password": "NewSecure@Pass456"
            }
        )
        assert response.status_code == 200
    
    async def test_weak_password_rejection(self, client: AsyncClient):
        """Test weak password rejection"""
        user_data = {
            "username": "weakpassuser",
            "email": "weak@example.com",
            "password": "weak",  # Too short
            "full_name": "Weak Pass User"
        }
        
        response = await client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        assert "at least 8 characters" in str(response.json())


class TestRateLimiting:
    """Test rate limiting"""
    
    async def test_login_rate_limit(self, client: AsyncClient, registered_user):
        """Test rate limiting on login endpoint"""
        # Make multiple failed login attempts
        tasks = []
        for i in range(15):  # Exceed the 10/minute limit
            task = client.post(
                "/auth/login",
                data={
                    "username": "testuser",
                    "password": "wrongpassword"
                }
            )
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check that some requests were rate limited
        status_codes = [r.status_code for r in responses if hasattr(r, 'status_code')]
        assert 429 in status_codes  # Too Many Requests
        
        # Check rate limit headers
        for response in responses:
            if hasattr(response, 'headers') and response.status_code == 429:
                assert "X-RateLimit-Limit" in response.headers
                assert "Retry-After" in response.headers
                break


class TestSecurityHeaders:
    """Test security headers"""
    
    async def test_security_headers_present(self, client: AsyncClient):
        """Test that security headers are present"""
        response = await client.get("/health")
        
        headers = response.headers
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("x-xss-protection") == "1; mode=block"
        # HSTS is only added for HTTPS or when strict=True
        # Since we're in debug mode (strict=False) with HTTP test client, it won't be present
        assert "content-security-policy" in headers
        assert "permissions-policy" in headers


class TestInputValidation:
    """Test input validation and security"""
    
    async def test_sql_injection_prevention(self, client: AsyncClient):
        """Test SQL injection prevention"""
        # Try SQL injection in username
        response = await client.post(
            "/auth/login",
            data={
                "username": "admin' OR '1'='1",
                "password": "password"
            }
        )
        assert response.status_code == 401
        
        # Try SQL injection in registration
        response = await client.post(
            "/auth/register",
            json={
                "username": "test'; DROP TABLE users; --",
                "email": "test@test.com",
                "password": "Test@Pass123"
            }
        )
        assert response.status_code == 422  # Validation error
    
    async def test_xss_prevention(self, client: AsyncClient):
        """Test XSS prevention"""
        response = await client.post(
            "/auth/register",
            json={
                "username": "testxss",
                "email": "xss@test.com",
                "password": "Test@Pass123",
                "full_name": "<script>alert('xss')</script>"
            }
        )
        # Should either reject or sanitize
        if response.status_code == 200:
            user_data = response.json()["user"]
            assert "<script>" not in user_data.get("full_name", "")


class TestMFAIntegration:
    """Test MFA functionality"""
    
    async def test_mfa_setup_flow(self, client: AsyncClient, auth_headers):
        """Test MFA setup flow"""
        # Setup MFA
        response = await client.post("/auth/mfa/setup", headers=auth_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "secret" in data
        assert "qr_code" in data
        assert data["qr_code"].startswith("data:image/png;base64,")
    
    async def test_mfa_enable_with_invalid_code(self, client: AsyncClient, auth_headers):
        """Test MFA enable with invalid code"""
        # Setup MFA first
        setup_response = await client.post("/auth/mfa/setup", headers=auth_headers)
        assert setup_response.status_code == 200
        
        # Try to enable with invalid code
        response = await client.post(
            "/auth/mfa/enable",
            headers=auth_headers,
            json={"code": "000000"}
        )
        assert response.status_code == 400
        assert "Invalid verification code" in response.json()["detail"]


class TestIAMAdapter:
    """Test IAM adapter endpoints"""
    
    async def test_token_validation(self, client: AsyncClient, auth_headers):
        """Test token validation endpoint"""
        token = auth_headers["Authorization"].replace("Bearer ", "")
        
        response = await client.post(
            "/iam/validate-token",
            json={"token": token}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["valid"] is True
        assert "user_id" in data
        assert "username" in data
        assert "roles" in data
        assert "permissions" in data
    
    async def test_invalid_token_validation(self, client: AsyncClient):
        """Test invalid token validation"""
        response = await client.post(
            "/iam/validate-token",
            json={"token": "invalid.token.here"}
        )
        assert response.status_code == 200
        assert response.json()["valid"] is False
    
    async def test_check_permission(self, client: AsyncClient, auth_headers):
        """Test permission checking"""
        response = await client.post(
            "/check-permission",
            headers=auth_headers,
            json={
                "user_id": "test-user-id",
                "resource": "ontology",
                "action": "read",
                "resource_id": "*"
            }
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "allowed" in data
        assert data["allowed"] is True  # Default user has read permissions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])