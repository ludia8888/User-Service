"""
User model
"""
import uuid
from datetime import datetime
from typing import List, Optional
from enum import Enum

from sqlalchemy import Column, String, DateTime, Boolean, Integer, JSON, Index
from sqlalchemy.sql import func

from core.database import Base


class UserStatus(str, Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class User(Base):
    """User model"""
    __tablename__ = "users"
    
    # Primary fields
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    
    # Status and roles
    status = Column(String(20), default=UserStatus.PENDING_VERIFICATION)
    roles = Column(JSON, default=list)  # ["admin", "developer", "reviewer"]
    permissions = Column(JSON, default=list)  # ["schema:*:*", "branch:*:read"]
    teams = Column(JSON, default=list)  # ["backend", "platform"]
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32))
    backup_codes = Column(JSON)  # Encrypted backup codes
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True))
    locked_until = Column(DateTime(timezone=True))
    password_changed_at = Column(DateTime(timezone=True))
    password_history = Column(JSON, default=list)  # List of previous password hashes
    
    # Session management
    active_sessions = Column(JSON, default=list)
    last_login = Column(DateTime(timezone=True))
    last_activity = Column(DateTime(timezone=True))
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(50))
    updated_by = Column(String(50))
    
    # User preferences
    preferences = Column(JSON, default=dict)
    notification_settings = Column(JSON, default=dict)
    
    # Compliance
    terms_accepted_at = Column(DateTime(timezone=True))
    privacy_accepted_at = Column(DateTime(timezone=True))
    data_retention_consent = Column(Boolean, default=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'status'),
        Index('idx_user_created_at', 'created_at'),
        Index('idx_user_last_login', 'last_login'),
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "status": self.status,
            "roles": self.roles,
            "teams": self.teams,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        # Admin has all permissions
        if "admin" in self.roles:
            return True
        
        # Check direct permissions
        for perm in self.permissions:
            if self._match_permission(perm, permission):
                return True
        
        return False
    
    def _match_permission(self, user_perm: str, required_perm: str) -> bool:
        """Match permission patterns"""
        user_parts = user_perm.split(":")
        required_parts = required_perm.split(":")
        
        if len(user_parts) != 3 or len(required_parts) != 3:
            return False
        
        for user_part, required_part in zip(user_parts, required_parts):
            if user_part != "*" and user_part != required_part:
                return False
        
        return True