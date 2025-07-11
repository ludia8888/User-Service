"""
Normalized User model
Proper relational design without JSON abuse
"""
import uuid
from datetime import datetime
from typing import List, Optional, Set
from enum import Enum

from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, ForeignKey, Index
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func

from core.database import Base
from models.rbac import user_roles, user_permissions, user_teams, Permission
from models.organization import user_organizations


class UserStatus(str, Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class User(Base):
    """Normalized User model with proper relationships"""
    __tablename__ = "users"
    
    # Primary fields
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    
    # Status
    status = Column(String(20), default=UserStatus.PENDING_VERIFICATION, index=True)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False, index=True)
    mfa_secret = Column(String(32))
    mfa_enabled_at = Column(DateTime(timezone=True))
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True))
    locked_until = Column(DateTime(timezone=True))
    password_changed_at = Column(DateTime(timezone=True))
    
    # Session management
    last_login = Column(DateTime(timezone=True))
    last_activity = Column(DateTime(timezone=True))
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(36), ForeignKey('users.id'))
    updated_by = Column(String(36), ForeignKey('users.id'))
    
    # Compliance
    terms_accepted_at = Column(DateTime(timezone=True))
    privacy_accepted_at = Column(DateTime(timezone=True))
    data_retention_consent = Column(Boolean, default=True)
    
    # Relationships to RBAC entities
    roles = relationship(
        'Role',
        secondary=user_roles,
        lazy='dynamic'
    )
    
    direct_permissions = relationship(
        'Permission',
        secondary=user_permissions,
        lazy='dynamic'
    )
    
    teams = relationship(
        'Team',
        secondary=user_teams,
        lazy='dynamic'
    )
    
    # Organizations relationship
    organizations = relationship(
        'Organization',
        secondary=user_organizations,
        back_populates='users',
        lazy='dynamic'
    )
    
    # Self-referential relationships for audit
    created_by_user = relationship('User', remote_side=[id], foreign_keys=[created_by])
    updated_by_user = relationship('User', remote_side=[id], foreign_keys=[updated_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'status'),
        Index('idx_user_created_at', 'created_at'),
        Index('idx_user_last_login', 'last_login'),
        Index('idx_user_mfa_enabled', 'mfa_enabled'),
        Index('idx_user_password_changed_at', 'password_changed_at'),
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "status": self.status,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "roles": [role.name for role in self.roles],
            "teams": [team.name for team in self.teams],
            "direct_permissions": [perm.name for perm in self.direct_permissions]
        }
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return self.roles.filter_by(name=role_name).first() is not None
    
    def get_all_permissions(self) -> Set[str]:
        """Get all permissions (direct + from roles + from teams)"""
        permissions = set()
        
        # Direct permissions
        for perm in self.direct_permissions:
            permissions.add(perm.name)
        
        # Permissions from roles
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.name)
        
        # Permissions from teams
        for team in self.teams:
            for perm in team.permissions:
                permissions.add(perm.name)
        
        return permissions
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        # Admin role has all permissions
        if self.has_role("admin"):
            return True
        
        # Check direct permissions
        for perm in self.direct_permissions:
            if perm.matches(permission):
                return True
        
        # Check permissions from roles
        for role in self.roles:
            for perm in role.permissions:
                if perm.matches(permission):
                    return True
        
        # Check permissions from teams
        for team in self.teams:
            for perm in team.permissions:
                if perm.matches(permission):
                    return True
        
        return False
    
    def get_role_names(self) -> List[str]:
        """Get list of role names"""
        return [role.name for role in self.roles]
    
    def get_team_names(self) -> List[str]:
        """Get list of team names"""
        return [team.name for team in self.teams]
    
    def get_permission_names(self) -> List[str]:
        """Get list of all permission names"""
        return list(self.get_all_permissions())
    
    def is_member_of_team(self, team_name: str) -> bool:
        """Check if user is member of a specific team"""
        return self.teams.filter_by(name=team_name).first() is not None
    
    def get_team_role(self, team_name: str) -> Optional[str]:
        """Get user's role in a specific team"""
        # This would require querying the association table
        # For now, return None - would need to implement with proper query
        return None
    
    def add_role(self, role) -> None:
        """Add a role to user"""
        if not self.has_role(role.name):
            self.roles.append(role)
    
    def remove_role(self, role_name: str) -> None:
        """Remove a role from user"""
        role = self.roles.filter_by(name=role_name).first()
        if role:
            self.roles.remove(role)
    
    def add_to_team(self, team) -> None:
        """Add user to team"""
        if not self.is_member_of_team(team.name):
            self.teams.append(team)
    
    def remove_from_team(self, team_name: str) -> None:
        """Remove user from team"""
        team = self.teams.filter_by(name=team_name).first()
        if team:
            self.teams.remove(team)
    
    def add_permission(self, permission) -> None:
        """Add direct permission to user"""
        if permission not in self.direct_permissions:
            self.direct_permissions.append(permission)
    
    def remove_permission(self, permission_name: str) -> None:
        """Remove direct permission from user"""
        perm = self.direct_permissions.filter_by(name=permission_name).first()
        if perm:
            self.direct_permissions.remove(perm)
    
    @property
    def is_active(self) -> bool:
        """Check if user is active"""
        return self.status == UserStatus.ACTIVE
    
    @property
    def is_locked(self) -> bool:
        """Check if user is locked"""
        if self.status == UserStatus.LOCKED:
            return True
        
        # Check if locked_until is set and still in effect
        if self.locked_until and self.locked_until > datetime.now():
            return True
        
        return False
    
    def can_login(self) -> bool:
        """Check if user can login"""
        return self.is_active and not self.is_locked
    
    def __repr__(self):
        return f"<User {self.username}>"


class UserSession(Base):
    """User session tracking - separate table for better performance"""
    __tablename__ = "user_sessions"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    
    # Session metadata
    ip_address = Column(String(45))  # Support IPv6
    user_agent = Column(Text)
    device_fingerprint = Column(String(255))
    
    # Session status
    is_active = Column(Boolean, default=True, index=True)
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    ended_at = Column(DateTime(timezone=True))
    end_reason = Column(String(50))  # logout, timeout, forced_logout, etc.
    
    # Relationship
    user = relationship('User', backref=backref('active_sessions', lazy='dynamic'))
    
    # Indexes
    __table_args__ = (
        Index('idx_user_sessions_user_id', 'user_id'),
        Index('idx_user_sessions_token', 'session_token'),
        Index('idx_user_sessions_active', 'is_active'),
        Index('idx_user_sessions_expires_at', 'expires_at'),
    )
    
    def __repr__(self):
        return f"<UserSession {self.user_id}>"
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now() > self.expires_at
    
    def end_session(self, reason: str = "logout") -> None:
        """End the session"""
        self.is_active = False
        self.ended_at = datetime.now()
        self.end_reason = reason


class MFABackupCode(Base):
    """MFA backup codes - separate table for better security"""
    __tablename__ = "mfa_backup_codes"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    code_hash = Column(String(255), nullable=False)
    
    # Status
    is_used = Column(Boolean, default=False, index=True)
    used_at = Column(DateTime(timezone=True))
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    user = relationship('User', backref=backref('backup_codes', lazy='dynamic'))
    
    # Indexes
    __table_args__ = (
        Index('idx_mfa_backup_codes_user_id', 'user_id'),
        Index('idx_mfa_backup_codes_is_used', 'is_used'),
    )
    
    def __repr__(self):
        return f"<MFABackupCode {self.user_id}>"
    
    def mark_used(self) -> None:
        """Mark backup code as used"""
        self.is_used = True
        self.used_at = datetime.now()


class UserPreference(Base):
    """User preferences - separate table for better performance and flexibility"""
    __tablename__ = "user_preferences"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    
    # Preference key-value
    preference_key = Column(String(100), nullable=False, index=True)
    preference_value = Column(Text)
    preference_type = Column(String(20), default="string")  # string, boolean, integer, json
    
    # Metadata
    is_sensitive = Column(Boolean, default=False)  # For preferences that need encryption
    category = Column(String(50), default="general")  # general, notification, security, etc.
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship
    user = relationship('User', backref=backref('preferences', lazy='dynamic'))
    
    # Indexes
    __table_args__ = (
        Index('idx_user_preferences_user_id', 'user_id'),
        Index('idx_user_preferences_key', 'preference_key'),
        Index('idx_user_preferences_category', 'category'),
        # Unique constraint for user_id + preference_key
        Index('idx_user_preferences_unique', 'user_id', 'preference_key', unique=True),
    )
    
    def __repr__(self):
        return f"<UserPreference {self.user_id}:{self.preference_key}>"