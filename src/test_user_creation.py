"""
Test user creation script
"""
import asyncio
from sqlalchemy import select
from core.database import AsyncSessionLocal, init_db
from models.user import User
from services.user_service import UserService

async def test_create_user():
    """Test creating default user"""
    await init_db()
    
    async with AsyncSessionLocal() as db:
        # Check if user exists
        result = await db.execute(select(User).where(User.username == "testuser"))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            print(f"User already exists: {existing_user.username}")
            print(f"Email: {existing_user.email}")
            print(f"Roles: {existing_user.roles}")
            print(f"Status: {existing_user.status}")
        else:
            # Create user
            user_service = UserService(db)
            user = await user_service.create_user(
                username="testuser",
                email="test@example.com",
                password="Test123!",
                full_name="Test User",
                roles=["admin"],
                created_by="system"
            )
            
            # Set permissions
            user.permissions = [
                "ontology:*:*",
                "schema:*:*", 
                "branch:*:*",
                "proposal:*:*",
                "audit:*:read",
                "system:*:admin"
            ]
            user.teams = ["backend", "platform"]
            await db.commit()
            
            print(f"User created: {user.username}")
            print(f"Password hash: {user.password_hash[:20]}...")

if __name__ == "__main__":
    asyncio.run(test_create_user())