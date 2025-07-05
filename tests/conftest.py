"""
Integration test configuration
"""
import pytest
import asyncio
import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from httpx import AsyncClient

# Set test environment variables
os.environ.update({
    "DEBUG": "true",
    "DATABASE_URL": "postgresql+asyncpg://test_user:test_password@localhost:5433/test_user_service",
    "REDIS_URL": "redis://localhost:6380",
    "JWT_SECRET": "test-secret-key-for-testing-purposes-only-minimum-32-characters",
    "RATE_LIMIT_ENABLED": "true",
})

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import app
from models.user import Base as UserBase
# Note: AuditBase removed as audit functionality migrated to Audit Service
from core.database import get_db


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
    async def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
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
        data={
            "username": registered_user["username"],
            "password": registered_user["password"]
        }
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}