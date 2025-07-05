"""
User Service
User management business logic
"""
from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from models.user import User, UserStatus
from core.config import settings
# from .audit_event_publisher import AuditEventPublisher

# Password hashing - Use bcrypt as default for compatibility
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    default="bcrypt",
    deprecated="auto"
)


class UserService:
    """User management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        # self.audit_publisher = AuditEventPublisher()
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        roles: List[str] = None,
        created_by: str = "system"
    ) -> User:
        """
        Create new user
        
        Note: Audit logging is handled by publishing events to Audit Service
        """
        # Check if user exists
        existing = await self.db.execute(
            select(User).where(
                or_(User.username == username, User.email == email)
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("User already exists")
        
        # Validate password
        if not self._validate_password(password):
            raise ValueError("Password does not meet requirements")
        
        # Hash password
        password_hash = pwd_context.hash(password)
        
        # Create user
        user = User(
            id=str(uuid4()),
            username=username,
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            roles=roles or ["user"],
            permissions=[],
            teams=[],
            status=UserStatus.ACTIVE,
            password_changed_at=datetime.now(timezone.utc),
            password_history=[password_hash],
            created_by=created_by,
            created_at=datetime.now(timezone.utc)
        )
        
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        
        # Publish audit event
        # await self.audit_publisher.publish_user_created(
        #     user_id=user.id,
        #     username=user.username,
        #     email=user.email,
        #     roles=user.roles,
        #     created_by=created_by
        # )
        
        return user
    
    async def update_user(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        roles: Optional[List[str]] = None,
        teams: Optional[List[str]] = None,
        updated_by: str = "system"
    ) -> User:
        """Update user information"""
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Track changes for audit
        changes = {}
        
        # Update fields
        if full_name is not None:
            changes["full_name"] = {"old": user.full_name, "new": full_name}
            user.full_name = full_name
        
        if roles is not None:
            changes["roles"] = {"old": user.roles, "new": roles}
            user.roles = roles
        
        if teams is not None:
            changes["teams"] = {"old": user.teams, "new": teams}
            user.teams = teams
        
        user.updated_by = updated_by
        user.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(user)
        
        # Publish audit event if changes were made
        # if changes:
        #     await self.audit_publisher.publish_user_updated(
        #         user_id=user.id,
        #         username=user.username,
        #         changes=changes,
        #         updated_by=updated_by
        #     )
        
        return user
    
    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        changed_by: str
    ) -> User:
        """Change user password"""
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Verify old password
        if not pwd_context.verify(old_password, user.password_hash):
            # await self.audit_publisher.publish_password_change_failed(
            #     user_id=user.id,
            #     username=user.username,
            #     reason="Invalid old password"
            # )
            raise ValueError("Invalid old password")
        
        # Validate new password
        if not self._validate_password(new_password):
            raise ValueError("Password does not meet requirements")
        
        # Check password history
        new_hash = pwd_context.hash(new_password)
        for old_hash in user.password_history[-settings.PASSWORD_HISTORY_COUNT:]:
            if pwd_context.verify(new_password, old_hash):
                raise ValueError("Password was used recently")
        
        # Update password
        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        user.password_history = (user.password_history or []) + [new_hash]
        user.password_history = user.password_history[-settings.PASSWORD_HISTORY_COUNT:]
        
        await self.db.commit()
        
        # Publish audit event
        # await self.audit_publisher.publish_password_changed(
        #     user_id=user.id,
        #     username=user.username,
        #     changed_by=changed_by
        # )
        
        return user
    
    async def update_last_login(self, user_id: str):
        """Update user's last login time"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if user:
            user.last_login = datetime.now(timezone.utc)
            user.last_activity = datetime.now(timezone.utc)
            await self.db.commit()
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def create_default_user(self):
        """Create default test user if it doesn't exist"""
        existing_user = await self.get_user_by_username("testuser")
        if not existing_user:
            user = await self.create_user(
                username="testuser",
                email="test@example.com",
                password="Test123!",
                full_name="Test User",
                roles=["admin"],
                created_by="system"
            )
            
            # Set permissions and teams for default user
            user.permissions = [
                "ontology:*:*",
                "schema:*:*", 
                "branch:*:*",
                "proposal:*:*",
                "audit:*:read",
                "system:*:admin"
            ]
            user.teams = ["backend", "platform"]
            await self.db.commit()
            return user
        return existing_user
    
    def _validate_password(self, password: str) -> bool:
        """Validate password against policy"""
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not has_upper:
            return False
        if settings.PASSWORD_REQUIRE_LOWERCASE and not has_lower:
            return False
        if settings.PASSWORD_REQUIRE_DIGITS and not has_digit:
            return False
        if settings.PASSWORD_REQUIRE_SPECIAL and not has_special:
            return False
        
        return True