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
from models.user import Base
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
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session(engine, setup_database) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session"""
    async_session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with database override"""
    def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest.fixture
async def test_user_data():
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
    response = await client.post("/auth/register", json=test_user_data)
    assert response.status_code == 200
    return response.json()


@pytest.fixture
async def auth_headers(client, test_user_data):
    """Get authentication headers"""
    # Login
    response = await client.post(
        "/auth/login",
        json={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}