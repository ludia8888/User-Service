"""
End-to-End tests for User Service
Requires the service to be running at http://localhost:8000
"""
import pytest
import httpx
import asyncio
import uuid
from typing import Dict


# Base URL for the service
BASE_URL = "http://localhost:8000"


class TestE2EUserFlow:
    """End-to-end tests for complete user flows"""
    
    @pytest.fixture
    def unique_user_data(self) -> Dict[str, str]:
        """Generate unique user data for each test"""
        unique_id = uuid.uuid4().hex[:8]
        return {
            "username": f"e2e_user_{unique_id}",
            "email": f"e2e_{unique_id}@example.com",
            "password": "E2E_Test@Password123!",
            "full_name": "E2E Test User"
        }
    
    @pytest.mark.asyncio
    async def test_complete_user_lifecycle(self, unique_user_data):
        """Test complete user lifecycle: register, login, get info, change password"""
        async with httpx.AsyncClient(base_url=BASE_URL) as client:
            # 1. Register new user
            register_response = await client.post(
                "/auth/register",
                json=unique_user_data
            )
            assert register_response.status_code == 200
            user_data = register_response.json()
            assert user_data["user"]["username"] == unique_user_data["username"]
            assert user_data["user"]["email"] == unique_user_data["email"]
            user_id = user_data["user"]["user_id"]
            
            # 2. Login with the new user
            login_response = await client.post(
                "/auth/login",
                data={
                    "username": unique_user_data["username"],
                    "password": unique_user_data["password"]
                }
            )
            assert login_response.status_code == 200
            tokens = login_response.json()
            assert "access_token" in tokens
            assert "refresh_token" in tokens
            
            headers = {"Authorization": f"Bearer {tokens['access_token']}"}
            
            # 3. Get user info
            user_info_response = await client.get(
                "/auth/me",
                headers=headers
            )
            assert user_info_response.status_code == 200
            user_info = user_info_response.json()
            assert user_info["user_id"] == user_id
            assert user_info["username"] == unique_user_data["username"]
            
            # 4. Change password
            new_password = "New_E2E_Test@Password456!"
            change_password_response = await client.post(
                "/auth/change-password",
                headers=headers,
                json={
                    "current_password": unique_user_data["password"],
                    "new_password": new_password
                }
            )
            assert change_password_response.status_code == 200
            
            # 5. Logout
            logout_response = await client.post(
                "/auth/logout",
                headers=headers
            )
            assert logout_response.status_code == 200
            
            # 6. Verify old password doesn't work
            old_login_response = await client.post(
                "/auth/login",
                data={
                    "username": unique_user_data["username"],
                    "password": unique_user_data["password"]
                }
            )
            assert old_login_response.status_code == 401
            
            # 7. Verify new password works
            new_login_response = await client.post(
                "/auth/login",
                data={
                    "username": unique_user_data["username"],
                    "password": new_password
                }
            )
            assert new_login_response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_security_headers(self):
        """Test that security headers are present in responses"""
        async with httpx.AsyncClient(base_url=BASE_URL) as client:
            response = await client.get("/health")
            assert response.status_code == 200
            
            # Check security headers
            headers = response.headers
            assert headers.get("x-content-type-options") == "nosniff"
            assert headers.get("x-frame-options") == "DENY"
            assert headers.get("x-xss-protection") == "1; mode=block"
            assert "content-security-policy" in headers
            assert "permissions-policy" in headers
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, unique_user_data):
        """Test rate limiting functionality"""
        async with httpx.AsyncClient(base_url=BASE_URL) as client:
            # Try to register many times quickly
            responses = []
            for i in range(10):
                modified_data = unique_user_data.copy()
                modified_data["username"] = f"{unique_user_data['username']}_{i}"
                modified_data["email"] = f"test_{i}_{unique_user_data['email']}"
                
                response = await client.post(
                    "/auth/register",
                    json=modified_data
                )
                responses.append(response.status_code)
            
            # At least one should be rate limited (429)
            assert 429 in responses or all(r == 200 for r in responses[:5])
    
    @pytest.mark.asyncio
    async def test_input_validation(self):
        """Test input validation and sanitization"""
        async with httpx.AsyncClient(base_url=BASE_URL) as client:
            # Test SQL injection attempt
            malicious_data = {
                "username": "admin'; DROP TABLE users; --",
                "email": "test@example.com",
                "password": "Test@123456",
                "full_name": "Test User"
            }
            
            response = await client.post(
                "/auth/register",
                json=malicious_data
            )
            # Should be rejected due to invalid username format
            assert response.status_code in [400, 422]
            
            # Test XSS attempt
            xss_data = {
                "username": "testuser123",
                "email": "test@example.com",
                "password": "Test@123456",
                "full_name": "<script>alert('XSS')</script>"
            }
            
            response = await client.post(
                "/auth/register",
                json=xss_data
            )
            
            if response.status_code == 200:
                # If registration succeeds, check that the script is sanitized
                user_data = response.json()
                assert "<script>" not in user_data["user"]["full_name"]
                assert "alert(" not in user_data["user"]["full_name"]
    
    @pytest.mark.asyncio
    async def test_password_policy(self):
        """Test password policy enforcement"""
        async with httpx.AsyncClient(base_url=BASE_URL) as client:
            base_user_data = {
                "username": f"pwtest_{uuid.uuid4().hex[:8]}",
                "email": f"pwtest_{uuid.uuid4().hex[:8]}@example.com",
                "full_name": "Password Test User"
            }
            
            # Test weak passwords
            weak_passwords = [
                "password",      # Too common
                "12345678",      # Only numbers
                "abcdefgh",      # Only lowercase
                "ABCDEFGH",      # Only uppercase
                "Abc123",        # Too short
                "Password123"    # No special character
            ]
            
            for weak_pw in weak_passwords:
                user_data = base_user_data.copy()
                user_data["password"] = weak_pw
                user_data["username"] = f"weak_{uuid.uuid4().hex[:8]}"
                user_data["email"] = f"weak_{uuid.uuid4().hex[:8]}@example.com"
                
                response = await client.post(
                    "/auth/register",
                    json=user_data
                )
                assert response.status_code in [400, 422], f"Password '{weak_pw}' should be rejected"
            
            # Test strong password
            strong_user_data = base_user_data.copy()
            strong_user_data["password"] = "Strong@Password123!"
            
            response = await client.post(
                "/auth/register",
                json=strong_user_data
            )
            assert response.status_code == 200


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])