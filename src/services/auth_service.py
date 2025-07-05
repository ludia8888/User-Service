"""
Authentication service
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.config import settings
from models.user import User, UserStatus


class AuthService:
    """Authentication service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash password"""
        return self.pwd_context.hash(password)
    
    async def authenticate(
        self, 
        username: str, 
        password: str, 
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> User:
        """Authenticate user"""
        # Get user by username
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("Invalid credentials")
        
        # Verify password
        if not self.verify_password(password, user.password_hash):
            raise ValueError("Invalid credentials")
        
        # Check if user is active
        if user.status != UserStatus.ACTIVE:
            raise ValueError("Account is not active")
        
        # Verify MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise ValueError("MFA code required")
            
            from services.mfa_service import MFAService
            mfa_service = MFAService(self.db)
            
            if not await mfa_service.verify_mfa(user, mfa_code):
                raise ValueError("Invalid MFA code")
        
        return user
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        payload = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles or [],
            "permissions": user.permissions or [],
            "teams": user.teams or [],
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
            "iat": datetime.now(timezone.utc),
            "iss": getattr(settings, 'JWT_ISSUER', 'user-service'),  # Issuer claim
            "aud": getattr(settings, 'JWT_AUDIENCE', 'oms'),  # Audience claim
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
            "iat": datetime.now(timezone.utc),
            "iss": getattr(settings, 'JWT_ISSUER', 'user-service'),  # Issuer claim
            "aud": getattr(settings, 'JWT_AUDIENCE', 'oms'),  # Audience claim
            "sid": str(uuid.uuid4())
        }
        
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM
        )
    
    def decode_token(self, token: str) -> dict:
        """Decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.JWTError:
            raise ValueError("Invalid token")
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def revoke_session(self, session_id: str, user_id: str):
        """Revoke user session"""
        # In a real implementation, this would remove the session from Redis
        # For now, we'll just pass
        pass