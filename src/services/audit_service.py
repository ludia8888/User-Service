"""
Audit Service Client
Sends audit events to centralized Audit Service
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from enum import Enum

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from core.redis import get_redis_client
from core.config import settings


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


class AuditService:
    """Client for sending audit events to centralized Audit Service"""
    
    def __init__(self, db: AsyncSession = None):
        self.db = db  # Deprecated, will be removed after migration
        self.logger = logging.getLogger("audit")
        self._setup_logger()
        self.audit_service_url = settings.AUDIT_SERVICE_URL
        self.http_client = httpx.AsyncClient(timeout=2.0)
    
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
        """Send audit event to centralized Audit Service"""
        try:
            # Prepare event data for Audit Service API
            event_data = {
                "event_type": f"auth.{event_type.value}",
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "service": "user-service",
                "action": event_type.value,
                "result": "success" if success else "failure",
                "details": details or {},
                "compliance_tags": ["SOX", "GDPR"],
                "data_classification": "internal"
            }
            
            # Send to Audit Service
            await self._send_to_audit_service(event_data)
            
            # Log locally for immediate visibility
            log_data = {
                "event_type": event_type.value,
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            if success:
                self.logger.info(json.dumps(log_data))
            else:
                self.logger.warning(json.dumps(log_data))
            
        except Exception as e:
            self.logger.error(f"Failed to send audit event: {e}")
            # Fallback to Redis queue for retry
            await self._queue_for_retry(event_type, user_id, username, ip_address, user_agent, details, success)
    
    async def _send_to_audit_service(self, event_data: dict):
        """Send event to centralized Audit Service"""
        try:
            response = await self.http_client.post(
                f"{self.audit_service_url}/api/v2/events",
                json=event_data
            )
            response.raise_for_status()
            
        except httpx.RequestError as e:
            self.logger.error(f"Failed to send audit event to service: {e}")
            raise
        except httpx.HTTPStatusError as e:
            self.logger.error(f"Audit service returned error: {e}")
            raise
    
    async def _queue_for_retry(self, event_type: AuditEventType, user_id: str, username: str, ip_address: str, user_agent: str, details: dict, success: bool):
        """Queue failed events for retry"""
        try:
            redis_client = get_redis_client()
            retry_data = {
                "event_type": event_type.value,
                "user_id": user_id,
                "username": username,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "retry_count": 0
            }
            
            # Add to retry queue
            await redis_client.lpush(
                f"{settings.REDIS_PREFIX}:audit:retry_queue",
                json.dumps(retry_data)
            )
            
            # Expire after 7 days
            await redis_client.expire(f"{settings.REDIS_PREFIX}:audit:retry_queue", 604800)
            
        except Exception as e:
            self.logger.error(f"Failed to queue audit event for retry: {e}")
    
    async def close(self):
        """Close HTTP client"""
        await self.http_client.aclose()
    
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
    
    async def log_password_change_failed(
        self,
        user_id: str,
        username: str,
        reason: str,
        ip_address: Optional[str] = None
    ):
        """Log failed password change attempt"""
        await self.log_event(
            AuditEventType.SUSPICIOUS_ACTIVITY,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            details={
                "activity": "password_change_failed",
                "reason": reason
            },
            success=False
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
    
    async def log_user_updated(
        self,
        user_id: str,
        username: str,
        changes: Dict[str, Any],
        updated_by: str,
        ip_address: Optional[str] = None
    ):
        """Log user update"""
        await self.log_event(
            AuditEventType.USER_UPDATED,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            details={
                "changes": changes,
                "updated_by": updated_by
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