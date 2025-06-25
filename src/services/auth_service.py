"""
Authentication Service
Core authentication logic
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.user import User, UserStatus
from core.redis import get_redis_client

# Password hashing
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    argon2__rounds=4,
    argon2__memory_cost=65536,
    argon2__parallelism=2,
)


class AuthService:
    """Authentication service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.redis = get_redis_client()
    
    async def authenticate(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str],
        ip_address: str,
        user_agent: str
    ) -> User:
        """
        Authenticate user
        
        Returns:
            User object if authentication successful
            
        Raises:
            ValueError: If authentication fails
        """
        # Get user
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("Invalid username or password")
        
        # Check account status
        if user.status == UserStatus.LOCKED:
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                raise ValueError("Account is locked")
            else:
                # Unlock account
                user.status = UserStatus.ACTIVE
                user.locked_until = None
                user.failed_login_attempts = 0
        
        if user.status != UserStatus.ACTIVE:
            raise ValueError(f"Account is {user.status}")
        
        # Verify password
        if not pwd_context.verify(password, user.password_hash):
            # Increment failed attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(timezone.utc)
            
            # Lock account if too many failures
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.status = UserStatus.LOCKED
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.LOCKOUT_DURATION_MINUTES
                )
                await self.db.commit()
                raise ValueError("Account locked due to too many failed attempts")
            
            await self.db.commit()
            raise ValueError("Invalid username or password")
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise ValueError("MFA code required")
            
            # Verify MFA code (implement MFA service)
            # if not await self.verify_mfa(user, mfa_code):
            #     raise ValueError("Invalid MFA code")
        
        # Reset failed attempts
        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)
        user.last_activity = datetime.now(timezone.utc)
        
        await self.db.commit()
        return user
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        payload = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "permissions": user.permissions,
            "teams": user.teams,
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
            "iat": datetime.now(timezone.utc),
            "sid": str(uuid.uuid4())  # Session ID
        }
        
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM
        )
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        payload = {
            "sub": user.id,
            "type": "refresh",
            "exp": datetime.now(timezone.utc) + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
            "iat": datetime.now(timezone.utc)
        }
        
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM
        )
    
    def decode_token(self, token: str) -> dict:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def revoke_session(self, session_id: str, user_id: str):
        """Revoke a session"""
        # Add to revoked sessions in Redis
        key = f"revoked_session:{session_id}"
        await self.redis.setex(
            key,
            settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_id
        )
    
    async def is_session_revoked(self, session_id: str) -> bool:
        """Check if session is revoked"""
        key = f"revoked_session:{session_id}"
        return await self.redis.exists(key)