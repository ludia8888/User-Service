#!/usr/bin/env python3
"""
Test script to verify JWT authentication is working properly after the fix
"""
import os
import sys
import asyncio
import httpx
import json
from datetime import datetime

# Set environment variables before importing anything else
os.environ["JWT_SECRET"] = "your_super_secret_key_for_user_service_with_32_chars"
os.environ["JWT_ALGORITHM"] = "RS256"
os.environ["JWT_ISSUER"] = "user-service"
os.environ["JWT_AUDIENCE"] = "oms"
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:password@localhost/audit_db"
os.environ["ENVIRONMENT"] = "development"

# Base URLs
USER_SERVICE_URL = "http://localhost:8000"
AUDIT_SERVICE_URL = "http://localhost:8002"
OMS_SERVICE_URL = "http://localhost:8007"

async def test_jwt_authentication():
    """Test JWT authentication flow"""
    print("\n=== JWT Authentication Test ===")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Login to get JWT token
        print("\n1. Logging in to user service...")
        login_data = {
            "username": "testuser",
            "password": "Test123!@#"
        }
        
        try:
            response = await client.post(
                f"{USER_SERVICE_URL}/api/auth/login",
                json=login_data
            )
            
            if response.status_code != 200:
                print(f"Login failed: {response.status_code}")
                print(f"Response: {response.text}")
                return
            
            token_data = response.json()
            access_token = token_data.get("access_token")
            print(f"✓ Login successful, got token: {access_token[:50]}...")
            
        except Exception as e:
            print(f"✗ Login failed: {e}")
            return
        
        # Step 2: Test audit service debug endpoints
        print("\n2. Testing audit service debug endpoints...")
        
        # Test JWT config endpoint (no auth required)
        try:
            response = await client.get(f"{AUDIT_SERVICE_URL}/api/v2/events/debug-jwt-config")
            print(f"\nJWT Config Response:")
            print(json.dumps(response.json(), indent=2))
        except Exception as e:
            print(f"✗ JWT config endpoint failed: {e}")
        
        # Test auth debug endpoint (requires auth)
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await client.post(
                f"{AUDIT_SERVICE_URL}/api/v2/events/debug-auth",
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"\n✓ Auth debug successful:")
                print(json.dumps(response.json(), indent=2))
            else:
                print(f"\n✗ Auth debug failed: {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"✗ Auth debug endpoint failed: {e}")
        
        # Step 3: Test creating an audit event
        print("\n3. Testing audit event creation...")
        
        audit_event = {
            "event_type": "test.authentication",
            "event_category": "testing",
            "severity": "INFO",
            "user_id": "test-user-id",
            "username": "testuser",
            "target_type": "Authentication",
            "target_id": "jwt-test",
            "operation": "verify",
            "metadata": {
                "test": True,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        try:
            response = await client.post(
                f"{AUDIT_SERVICE_URL}/api/v2/events/single",
                json=audit_event,
                headers=headers
            )
            
            if response.status_code == 201:
                print(f"✓ Audit event created successfully:")
                print(json.dumps(response.json(), indent=2))
            else:
                print(f"✗ Audit event creation failed: {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"✗ Audit event creation failed: {e}")
        
        # Step 4: Test OMS integration
        print("\n4. Testing OMS service with JWT...")
        
        try:
            response = await client.get(
                f"{OMS_SERVICE_URL}/api/ontologies",
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"✓ OMS service authenticated successfully")
                ontologies = response.json()
                print(f"Found {len(ontologies)} ontologies")
            else:
                print(f"✗ OMS service authentication failed: {response.status_code}")
                print(f"Response: {response.text}")
        except Exception as e:
            print(f"✗ OMS service request failed: {e}")

async def main():
    """Main test function"""
    print("JWT Authentication Fix Test")
    print("=" * 50)
    
    # Show environment status
    print("\nEnvironment Variables:")
    for key in ["JWT_SECRET", "JWT_ALGORITHM", "JWT_ISSUER", "JWT_AUDIENCE", "ENVIRONMENT"]:
        value = os.getenv(key)
        if value and "SECRET" in key:
            print(f"{key}: {value[:20]}...")
        else:
            print(f"{key}: {value}")
    
    await test_jwt_authentication()
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    asyncio.run(main())