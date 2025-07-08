"""
Authentication service
"""
import uuid
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol, Dict, Any
from enum import Enum

import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.config import settings
from models.user import User, UserStatus

logger = logging.getLogger(__name__)


class AuthStep(Enum):
    """Authentication step enumeration"""
    CREDENTIALS = "credentials"
    MFA_REQUIRED = "mfa_required"
    COMPLETE = "complete"


class AuthChallenge:
    """Authentication challenge for two-step flow"""
    def __init__(self, challenge_token: str, user_id: str, expires_at: datetime, step: AuthStep):
        self.challenge_token = challenge_token
        self.user_id = user_id
        self.expires_at = expires_at
        self.step = step


# Protocol for MFA service to avoid circular imports
class MFAServiceProtocol(Protocol):
    """Protocol defining MFA service interface for type hints"""
    async def verify_mfa(self, user: User, code: str) -> bool: ...


class AuthService:
    """Authentication service with dependency injection"""
    
    def __init__(self, db: AsyncSession, mfa_service: Optional[MFAServiceProtocol] = None):
        self.db = db
        self.mfa_service = mfa_service
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
        
        # Use generic error message to prevent information disclosure
        generic_error = "Invalid username or password"
        
        if not user:
            raise ValueError(generic_error)
        
        # Verify password
        if not self.verify_password(password, user.password_hash):
            raise ValueError(generic_error)
        
        # Check if user is active
        if user.status != UserStatus.ACTIVE:
            raise ValueError(generic_error)
        
        # Verify MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                raise ValueError(generic_error)
            
            # Use injected MFA service or lazy load if not provided
            if self.mfa_service is None:
                # Fallback to lazy loading for backward compatibility
                from services.mfa_service import MFAService
                mfa_service = MFAService(self.db)
            else:
                mfa_service = self.mfa_service
            
            if not await mfa_service.verify_mfa(user, mfa_code):
                raise ValueError(generic_error)
        
        return user
    
    async def authenticate_step1(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Step 1: Authenticate username and password only
        Returns challenge token if MFA required, or success if not
        """
        # Get user by username
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        
        # Use generic error message to prevent information disclosure
        generic_error = "Invalid username or password"
        
        if not user:
            raise ValueError(generic_error)
        
        # Verify password
        if not self.verify_password(password, user.password_hash):
            raise ValueError(generic_error)
        
        # Check if user is active
        if user.status != UserStatus.ACTIVE:
            raise ValueError(generic_error)
        
        # Always proceed to step 2 regardless of MFA status for timing consistency
        # Generate challenge token
        challenge_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)  # 5-minute expiry
        
        # Store challenge in Redis for scalability
        await self._store_challenge(
            challenge_token=challenge_token,
            user_id=str(user.id),
            expires_at=expires_at,
            step=AuthStep.MFA_REQUIRED if user.mfa_enabled else AuthStep.COMPLETE
        )
        
        # Return response that doesn't leak MFA status
        if user.mfa_enabled:
            return {
                "step": "mfa_required",
                "challenge_token": challenge_token,
                "message": "Please provide your MFA code"
            }
        else:
            return {
                "step": "complete",
                "challenge_token": challenge_token,
                "message": "Authentication successful"
            }
    
    async def authenticate_step2(
        self,
        challenge_token: str,
        mfa_code: Optional[str] = None
    ) -> User:
        """
        Step 2: Complete authentication with MFA code (if required)
        """
        # Validate challenge token
        challenge_data = await self._get_challenge(challenge_token)
        if not challenge_data:
            raise ValueError("Invalid or expired challenge token")
        
        # Get user
        user = await self.get_user_by_id(challenge_data["user_id"])
        if not user:
            await self._delete_challenge(challenge_token)
            raise ValueError("User not found")
        
        # If no MFA required, complete authentication
        if challenge_data["step"] == AuthStep.COMPLETE.value:
            await self._delete_challenge(challenge_token)
            return user
        
        # MFA is required
        if not mfa_code:
            raise ValueError("MFA code is required")
        
        # Verify MFA code
        if self.mfa_service is None:
            from services.mfa_service import MFAService
            mfa_service = MFAService(self.db)
        else:
            mfa_service = self.mfa_service
        
        if not await mfa_service.verify_mfa(user, mfa_code):
            # Don't delete challenge on failed MFA to prevent enumeration
            raise ValueError("Invalid MFA code")
        
        # Clean up challenge
        await self._delete_challenge(challenge_token)
        return user
    
    async def _store_challenge(
        self, 
        challenge_token: str, 
        user_id: str, 
        expires_at: datetime, 
        step: AuthStep
    ):
        """Store challenge in Redis"""
        from core.redis import get_redis_client
        import json
        
        redis_client = get_redis_client()
        challenge_key = f"{settings.REDIS_PREFIX}:auth_challenge:{challenge_token}"
        
        challenge_data = {
            "user_id": user_id,
            "expires_at": expires_at.isoformat(),
            "step": step.value
        }
        
        # Store with TTL (time to live)
        ttl_seconds = int((expires_at - datetime.now(timezone.utc)).total_seconds())
        await redis_client.setex(
            challenge_key,
            ttl_seconds,
            json.dumps(challenge_data)
        )
    
    async def _get_challenge(self, challenge_token: str) -> Optional[Dict[str, Any]]:
        """Get challenge from Redis"""
        from core.redis import get_redis_client
        import json
        
        redis_client = get_redis_client()
        challenge_key = f"{settings.REDIS_PREFIX}:auth_challenge:{challenge_token}"
        
        data = await redis_client.get(challenge_key)
        if data:
            return json.loads(data)
        return None
    
    async def _delete_challenge(self, challenge_token: str):
        """Delete challenge from Redis"""
        from core.redis import get_redis_client
        
        redis_client = get_redis_client()
        challenge_key = f"{settings.REDIS_PREFIX}:auth_challenge:{challenge_token}"
        await redis_client.delete(challenge_key)
    
    async def create_access_token(self, user: User) -> str:
        """Create JWT access token with user permissions and roles"""
        # Get user permissions from RBAC service
        from services.rbac_service import RBACService
        rbac_service = RBACService(self.db)
        
        # Get user roles and permissions
        user_roles = await rbac_service.get_user_roles(user.id)
        role_names = [role.name for role in user_roles]
        
        # Get all permissions
        permissions = await rbac_service.get_user_permissions(user.id)
        
        # Convert permissions to scopes for OMS compatibility
        from api.iam_adapter import _convert_permissions_to_scopes
        scopes = _convert_permissions_to_scopes(list(permissions))
        
        payload = {
            "sub": user.id,  # Subject - user identifier
            "type": "access",  # Token type
            "exp": datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
            "iat": datetime.now(timezone.utc),  # Issued at
            "iss": getattr(settings, 'JWT_ISSUER', 'user-service'),  # Issuer
            "aud": getattr(settings, 'JWT_AUDIENCE', 'oms'),  # Audience
            "sid": str(uuid.uuid4()),  # Session ID for revocation
            "roles": role_names,  # User roles
            "scopes": scopes  # User permissions as scopes
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
                algorithms=[settings.JWT_ALGORITHM],
                audience=getattr(settings, 'JWT_AUDIENCE', 'oms'),
                issuer=getattr(settings, 'JWT_ISSUER', 'user-service')
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except (jwt.InvalidTokenError, jwt.DecodeError, jwt.InvalidSignatureError):
            raise ValueError("Invalid token")
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def revoke_session(self, session_id: str, user_id: str):
        """Revoke user session by adding to blacklist"""
        from core.redis import get_redis_client
        
        redis_client = get_redis_client()
        
        # Create blacklist key
        blacklist_key = f"{settings.REDIS_PREFIX}:token_blacklist:{session_id}"
        
        # Calculate TTL based on token expiry
        # Store for slightly longer than token validity to ensure coverage
        ttl = (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60) + 300  # +5 minutes buffer
        
        # Add to blacklist with expiry
        await redis_client.setex(
            blacklist_key,
            ttl,
            user_id
        )
        
        # Also revoke all active sessions for this user if needed
        user_sessions_key = f"{settings.REDIS_PREFIX}:user_sessions:{user_id}"
        await redis_client.sadd(user_sessions_key, session_id)
        await redis_client.expire(user_sessions_key, ttl)
    
    async def is_session_revoked(self, session_id: str) -> bool:
        """Check if session is revoked"""
        from core.redis import get_redis_client
        
        redis_client = get_redis_client()
        blacklist_key = f"{settings.REDIS_PREFIX}:token_blacklist:{session_id}"
        
        return await redis_client.exists(blacklist_key) > 0
    
    async def verify_token(self, token: str) -> dict:
        """Verify JWT token and check if revoked"""
        # First decode the token
        payload = self.decode_token(token)
        
        # Check if session is revoked
        session_id = payload.get("sid")
        if session_id and await self.is_session_revoked(session_id):
            raise ValueError("Token has been revoked")
        
        return payload
    
    async def get_user_permissions(self, user_id: str) -> Dict[str, Any]:
        """
        Get real-time user permissions with Redis caching
        Returns current user data including roles, permissions, and teams
        """
        # Try cache first
        cached_data = await self._get_cached_user_permissions(user_id)
        if cached_data:
            return cached_data
        
        # Fetch from database
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Extract role names and permissions from relationships
        role_names = [role.name for role in user.roles]
        
        # Collect all permissions (from roles and direct permissions)
        all_permissions = set()
        for role in user.roles:
            for permission in role.permissions:
                all_permissions.add(permission.name)
        for permission in user.direct_permissions:
            all_permissions.add(permission.name)
        
        team_names = [team.name for team in user.teams]
        
        user_data = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": role_names,
            "permissions": list(all_permissions),
            "teams": team_names,
            "status": user.status.value if hasattr(user.status, 'value') else str(user.status),
            "mfa_enabled": user.mfa_enabled
        }
        
        # Cache the result
        await self._cache_user_permissions(user_id, user_data)
        
        return user_data
    
    async def _get_cached_user_permissions(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user permissions from Redis cache"""
        from core.redis import get_redis_client
        import json
        
        redis_client = get_redis_client()
        cache_key = f"{settings.REDIS_PREFIX}:user_permissions:{user_id}"
        
        data = await redis_client.get(cache_key)
        if data:
            return json.loads(data)
        return None
    
    async def _cache_user_permissions(self, user_id: str, user_data: Dict[str, Any]):
        """Cache user permissions in Redis with TTL"""
        from core.redis import get_redis_client
        import json
        
        redis_client = get_redis_client()
        cache_key = f"{settings.REDIS_PREFIX}:user_permissions:{user_id}"
        
        # Cache for 15 minutes (shorter than token expiry for security)
        cache_ttl = 15 * 60  # 15 minutes
        await redis_client.setex(
            cache_key,
            cache_ttl,
            json.dumps(user_data)
        )
    
    async def invalidate_user_permissions_cache(self, user_id: str):
        """Invalidate user permissions cache when permissions change"""
        from core.redis import get_redis_client
        
        redis_client = get_redis_client()
        cache_key = f"{settings.REDIS_PREFIX}:user_permissions:{user_id}"
        await redis_client.delete(cache_key)
    
    async def verify_token_and_get_user_data(self, token: str) -> Dict[str, Any]:
        """
        Verify token and return real-time user data
        This replaces the old method that relied on token payload
        """
        # Verify token structure and signature
        payload = await self.verify_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise ValueError("Invalid token: missing user ID")
        
        # Get real-time user permissions
        user_data = await self.get_user_permissions(user_id)
        
        # Get the actual user object for IAM adapter compatibility
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Add the user object to user_data
        user_data["user"] = user
        
        # Add token metadata
        user_data["session_id"] = payload.get("sid")
        user_data["token_issued_at"] = payload.get("iat")
        user_data["token_expires_at"] = payload.get("exp")
        user_data["token_data"] = {
            "exp": payload.get("exp")
        }
        
        return user_data