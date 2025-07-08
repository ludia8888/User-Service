"""
Database configuration and models
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .config import settings

# Create async engine with conditional pooling for SQLite compatibility
# Detect SQLite URLs in various forms (e.g. "sqlite:///", "sqlite+aiosqlite:///")
if settings.DATABASE_URL.startswith("sqlite") or settings.DATABASE_URL.startswith("sqlite+"):
    # SQLite doesn't support connection pooling
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        future=True
    )
else:
    # PostgreSQL and other databases with pooling support
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=settings.DEBUG,
        future=True
    )

# Create async session factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Create base class for models
Base = declarative_base()


# Dependency to get DB session
async def get_db():
    """
    Get database session with automatic transaction management
    - Commits on successful completion
    - Rollbacks on exceptions
    - Proper transaction boundaries per request
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            # Auto-commit if no exception occurred
            await session.commit()
        except Exception:
            # Rollback on any exception
            try:
                await session.rollback()
            except Exception:
                pass
            raise
        finally:
            await session.close()


# Transaction context manager for explicit transaction control
class DatabaseTransaction:
    """Context manager for explicit database transaction control"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._committed = False
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # Exception occurred, rollback
            try:
                await self.session.rollback()
            except Exception:
                pass
        elif not self._committed:
            # No exception but not explicitly committed, rollback
            try:
                await self.session.rollback()
            except Exception:
                pass
    
    async def commit(self):
        """Explicitly commit the transaction"""
        await self.session.commit()
        self._committed = True
    
    async def rollback(self):
        """Explicitly rollback the transaction"""
        await self.session.rollback()


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        # Import models to ensure they are registered
        from models.user import User  # noqa
        
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)


async def test_connection():
    """Test database connection"""
    try:
        async with engine.begin() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        print("Database connection successful")
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False