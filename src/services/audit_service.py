"""
Audit Logging Service
Logs security-related events for compliance and monitoring
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base

from core.redis import get_redis_client
from core.config import settings


Base = declarative_base()


class AuditEventType(str, Enum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    
    # Account events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    
    # Password events
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    
    # MFA events
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    
    # Permission events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_TOKEN = "invalid_token"


class AuditEvent(Base):
    """Audit event model"""
    __tablename__ = "audit_events"
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(String(36), index=True)
    username = Column(String(100), index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class AuditService:
    """Service for managing audit logs"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logging.getLogger("audit")
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup structured logging for audit events"""
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"event": %(message)s}'
            )
        )
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True
    ):
        """Log an audit event"""
        try:
            # Create audit event
            event = AuditEvent(
                event_type=event_type,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {},
                timestamp=datetime.now(timezone.utc)
            )
            
            # Store in database
            self.db.add(event)
            await self.db.commit()
            
            # Log to structured logger
            log_data = {
                "event_type": event_type,
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details,
                "success": success,
                "timestamp": event.timestamp.isoformat()
            }
            
            if success:
                self.logger.info(json.dumps(log_data))
            else:
                self.logger.warning(json.dumps(log_data))
            
            # Store in Redis for real-time monitoring
            await self._store_in_redis(event_type, log_data)
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
    
    async def _store_in_redis(self, event_type: str, data: dict):
        """Store event in Redis for real-time monitoring"""
        try:
            redis_client = get_redis_client()
            key = f"{settings.REDIS_PREFIX}:audit:{event_type}"
            
            # Add to sorted set with timestamp as score
            await redis_client.zadd(
                key,
                {json.dumps(data): datetime.now().timestamp()}
            )
            
            # Expire old events
            await redis_client.expire(key, 86400)  # 24 hours
            
        except Exception as e:
            self.logger.error(f"Failed to store audit event in Redis: {e}")
    
    # Convenience methods for common events
    
    async def log_login_success(
        self,
        user_id: str,
        username: str,
        ip_address: str,
        user_agent: str
    ):
        """Log successful login"""
        await self.log_event(
            AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
    
    async def log_login_failed(
        self,
        username: str,
        ip_address: str,
        user_agent: str,
        reason: str
    ):
        """Log failed login attempt"""
        await self.log_event(
            AuditEventType.LOGIN_FAILED,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"reason": reason},
            success=False
        )
    
    async def log_logout(
        self,
        user_id: str,
        username: str,
        session_id: Optional[str] = None
    ):
        """Log user logout"""
        await self.log_event(
            AuditEventType.LOGOUT,
            user_id=user_id,
            username=username,
            details={"session_id": session_id} if session_id else None
        )
    
    async def log_password_changed(
        self,
        user_id: str,
        username: str,
        changed_by: str,
        ip_address: Optional[str] = None
    ):
        """Log password change"""
        await self.log_event(
            AuditEventType.PASSWORD_CHANGED,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            details={"changed_by": changed_by}
        )
    
    async def log_mfa_enabled(
        self,
        user_id: str,
        username: str,
        ip_address: Optional[str] = None
    ):
        """Log MFA enablement"""
        await self.log_event(
            AuditEventType.MFA_ENABLED,
            user_id=user_id,
            username=username,
            ip_address=ip_address
        )
    
    async def log_mfa_disabled(
        self,
        user_id: str,
        username: str,
        ip_address: Optional[str] = None
    ):
        """Log MFA disablement"""
        await self.log_event(
            AuditEventType.MFA_DISABLED,
            user_id=user_id,
            username=username,
            ip_address=ip_address
        )
    
    async def log_user_created(
        self,
        user_id: str,
        username: str,
        email: str,
        created_by: str,
        roles: list
    ):
        """Log user creation"""
        await self.log_event(
            AuditEventType.USER_CREATED,
            user_id=user_id,
            username=username,
            details={
                "email": email,
                "created_by": created_by,
                "roles": roles
            }
        )
    
    async def log_suspicious_activity(
        self,
        user_id: Optional[str],
        ip_address: str,
        activity: str,
        details: Dict[str, Any]
    ):
        """Log suspicious activity"""
        await self.log_event(
            AuditEventType.SUSPICIOUS_ACTIVITY,
            user_id=user_id,
            ip_address=ip_address,
            details={
                "activity": activity,
                **details
            },
            success=False
        )