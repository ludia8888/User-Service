"""
Integration test configuration
"""
import pytest
import asyncio
import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from httpx import AsyncClient
from unittest.mock import AsyncMock

# Set test environment variables
os.environ.update({
    "DEBUG": "true",
    "DATABASE_URL": "sqlite+aiosqlite:///./test.db",
    "REDIS_URL": "redis://localhost:6380",
    "JWT_SECRET": "test-secret-key-for-testing-purposes-only-minimum-32-characters",
    "RATE_LIMIT_ENABLED": "true",
    "PASSWORD_MIN_LENGTH": "8",
    "PASSWORD_REQUIRE_UPPERCASE": "true",
    "PASSWORD_REQUIRE_LOWERCASE": "true", 
    "PASSWORD_REQUIRE_DIGITS": "true",
    "PASSWORD_REQUIRE_SPECIAL": "true",
    "PASSWORD_HISTORY_COUNT": "5",
    "MFA_ISSUER": "TestService",
    "MFA_BACKUP_CODES_COUNT": "10",
    "RATE_LIMIT_PER_MINUTE": "60",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "JWT_ALGORITHM": "HS256",
    "REDIS_PREFIX": "test",
    "PASSWORD_COMMON_PATTERNS": "[]",
    "PASSWORD_COMMON_PATTERNS_LIST": "",
    "AUDIT_SERVICE_ENABLED": "false",
    "RATE_LIMIT_ENABLED": "false",
    # Crypto keys for common_security
    "ENVIRONMENT": "development",
    "CRYPTO_KEY_MFA_SECRET": "dGVzdC1tZmEtc2VjcmV0LWtleS1mb3ItdGVzdGluZy1wdXJwb3Nlcw==",  # base64 encoded test key
    "CRYPTO_KEY_ENCRYPTION_KEY": "dGVzdC1lbmNyeXB0aW9uLWtleS1mb3ItdGVzdGluZy1wdXJwb3Nlcw==",  # base64 encoded test key
    "ENCRYPTION_KEY": "test-encryption-key-for-testing-purposes"  # fallback
})

import sys
# Add src directory
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
# Add common packages to path
common_packages_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'packages', 'backend')
if os.path.exists(common_packages_path):
    sys.path.insert(0, common_packages_path)

from main import app
from models.user import Base as UserBase
# Note: AuditBase removed as audit functionality migrated to Audit Service
from core.database import get_db
from .fake_redis import get_fake_redis, reset_fake_redis


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def engine():
    """Create test database engine"""
    engine = create_async_engine(
        os.environ["DATABASE_URL"],
        echo=False,
        pool_pre_ping=True
    )
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def setup_database(engine):
    """Create all database tables"""
    async with engine.begin() as conn:
        # Drop all tables
        await conn.run_sync(UserBase.metadata.drop_all)
        # Create all tables
        await conn.run_sync(UserBase.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(UserBase.metadata.drop_all)


@pytest.fixture
async def db_session(engine, setup_database):
    """Create a test database session"""
    async_session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        async with session.begin():
            yield session
            # Rollback will happen automatically when context exits


@pytest.fixture
async def client(db_session):
    """Create test client with database override"""
    # Reset fake Redis for each test
    reset_fake_redis()
    
    async def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    # Comprehensive Redis patching
    import unittest.mock
    fake_redis = get_fake_redis()
    
    # Mock audit service to avoid network calls
    async def mock_log_event(*args, **kwargs):
        pass  # Do nothing in tests
    
    # Mock HTTP client for audit service
    mock_http_client = AsyncMock()
    mock_http_client.post.return_value.status_code = 200
    mock_http_client.aclose = AsyncMock()
    
    patches = [
        unittest.mock.patch('core.redis.get_redis_client', return_value=fake_redis),
        unittest.mock.patch('core.rate_limit.get_redis_client', return_value=fake_redis),
        unittest.mock.patch('redis.Redis.from_url', return_value=fake_redis),
        unittest.mock.patch('redis.asyncio.Redis.from_url', return_value=fake_redis),
        unittest.mock.patch('redis.asyncio.from_url', return_value=fake_redis),
        # Mock audit service
        unittest.mock.patch('services.audit_service.AuditService.log_event', side_effect=mock_log_event),
        unittest.mock.patch('httpx.AsyncClient', return_value=mock_http_client),
    ]
    
    for patch in patches:
        patch.start()
    
    try:
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac
    finally:
        for patch in patches:
            patch.stop()
        app.dependency_overrides.clear()


@pytest.fixture
def test_user_data():
    """Test user data"""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "Test@Password123",
        "full_name": "Test User"
    }


@pytest.fixture
async def registered_user(client, test_user_data):
    """Create a registered user"""
    # Use a unique username for each test
    unique_user_data = test_user_data.copy()
    import uuid
    unique_user_data["username"] = f"testuser_{uuid.uuid4().hex[:8]}"
    unique_user_data["email"] = f"test_{uuid.uuid4().hex[:8]}@example.com"
    
    response = await client.post("/auth/register", json=unique_user_data)
    assert response.status_code == 200
    
    result = response.json()
    # Add the password to the result for login tests
    result["password"] = unique_user_data["password"]
    result["username"] = unique_user_data["username"]
    return result


@pytest.fixture
async def auth_headers(client, registered_user):
    """Get authentication headers"""
    # Login with the registered user
    response = await client.post(
        "/auth/login",
        json={
            "username": registered_user["username"],
            "password": registered_user["password"]
        }
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}