"""
Role-Based Access Control (RBAC) Models
Proper relational design for roles, permissions, and teams
"""
import uuid
from datetime import datetime
from typing import List, Optional
from enum import Enum

from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, ForeignKey, Table, Index
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func

from core.database import Base


class PermissionType(str, Enum):
    """Permission types for better categorization"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    EXECUTE = "execute"


class ResourceType(str, Enum):
    """Resource types in the system"""
    SCHEMA = "schema"
    ONTOLOGY = "ontology"
    BRANCH = "branch"
    PROPOSAL = "proposal"
    AUDIT = "audit"
    SYSTEM = "system"
    SERVICE = "service"
    WEBHOOK = "webhook"
    USER = "user"
    TEAM = "team"
    ROLE = "role"


# Association Tables for Many-to-Many relationships
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id'), primary_key=True),
    Column('role_id', String(36), ForeignKey('roles.id'), primary_key=True),
    Column('assigned_at', DateTime(timezone=True), server_default=func.now()),
    Column('expires_at', DateTime(timezone=True), nullable=True),
    Index('idx_user_roles_user_id', 'user_id'),
    Index('idx_user_roles_role_id', 'role_id'),
    Index('idx_user_roles_expires_at', 'expires_at')
)

user_permissions = Table(
    'user_permissions',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id'), primary_key=True),
    Column('permission_id', String(36), ForeignKey('permissions.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('expires_at', DateTime(timezone=True), nullable=True),
    Index('idx_user_permissions_user_id', 'user_id'),
    Index('idx_user_permissions_permission_id', 'permission_id'),
    Index('idx_user_permissions_expires_at', 'expires_at')
)

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', String(36), ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', String(36), ForeignKey('permissions.id'), primary_key=True),
    Column('assigned_at', DateTime(timezone=True), server_default=func.now()),
    Index('idx_role_permissions_role_id', 'role_id'),
    Index('idx_role_permissions_permission_id', 'permission_id')
)

user_teams = Table(
    'user_teams',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id'), primary_key=True),
    Column('team_id', String(36), ForeignKey('teams.id'), primary_key=True),
    Column('joined_at', DateTime(timezone=True), server_default=func.now()),
    Column('role_in_team', String(50), default='member'),  # member, lead, admin
    Index('idx_user_teams_user_id', 'user_id'),
    Index('idx_user_teams_team_id', 'team_id')
)

team_permissions = Table(
    'team_permissions',
    Base.metadata,
    Column('team_id', String(36), ForeignKey('teams.id'), primary_key=True),
    Column('permission_id', String(36), ForeignKey('permissions.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Index('idx_team_permissions_team_id', 'team_id'),
    Index('idx_team_permissions_permission_id', 'permission_id')
)


class Role(Base):
    """Role model with proper metadata"""
    __tablename__ = "roles"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Role metadata
    is_system_role = Column(Boolean, default=False)  # Cannot be modified/deleted
    is_default = Column(Boolean, default=False)      # Assigned to new users
    priority = Column(Integer, default=100)          # Higher priority = more permissions
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(36), ForeignKey('users.id'))
    updated_by = Column(String(36), ForeignKey('users.id'))
    
    # Relationships
    permissions = relationship(
        'Permission',
        secondary=role_permissions,
        lazy='dynamic'
    )
    
    users = relationship(
        'User',
        secondary=user_roles,
        lazy='dynamic'
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_role_name', 'name'),
        Index('idx_role_priority', 'priority'),
        Index('idx_role_is_default', 'is_default'),
    )
    
    def __repr__(self):
        return f"<Role {self.name}>"
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "is_system_role": self.is_system_role,
            "is_default": self.is_default,
            "priority": self.priority,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Permission(Base):
    """Permission model with resource-based structure"""
    __tablename__ = "permissions"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Permission structure: resource_type:resource_id:permission_type
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(100), default="*", index=True)  # * means all resources
    permission_type = Column(String(50), nullable=False, index=True)
    
    # Permission metadata
    is_system_permission = Column(Boolean, default=False)  # Cannot be modified/deleted
    is_dangerous = Column(Boolean, default=False)          # Requires special approval
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(36), ForeignKey('users.id'))
    updated_by = Column(String(36), ForeignKey('users.id'))
    
    # Indexes
    __table_args__ = (
        Index('idx_permission_name', 'name'),
        Index('idx_permission_resource', 'resource_type', 'resource_id'),
        Index('idx_permission_type', 'permission_type'),
        Index('idx_permission_dangerous', 'is_dangerous'),
    )
    
    def __repr__(self):
        return f"<Permission {self.name}>"
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "permission_type": self.permission_type,
            "is_system_permission": self.is_system_permission,
            "is_dangerous": self.is_dangerous,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
    
    def matches(self, required_permission: str) -> bool:
        """Check if this permission matches the required permission"""
        # Parse required permission: resource_type:resource_id:permission_type
        try:
            req_parts = required_permission.split(":")
            if len(req_parts) != 3:
                return False
            
            req_resource_type, req_resource_id, req_permission_type = req_parts
            
            # Check resource type
            if self.resource_type != req_resource_type:
                return False
            
            # Check resource ID (wildcard support)
            if self.resource_id != "*" and self.resource_id != req_resource_id:
                return False
            
            # Check permission type (wildcard support)
            if self.permission_type != "*" and self.permission_type != req_permission_type:
                return False
            
            return True
        except Exception:
            return False


class Team(Base):
    """Team model with proper metadata"""
    __tablename__ = "teams"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Team metadata
    is_active = Column(Boolean, default=True)
    team_type = Column(String(50), default="project")  # project, department, functional
    parent_team_id = Column(String(36), ForeignKey('teams.id'), nullable=True)
    
    # Team settings
    max_members = Column(Integer, default=None)  # NULL means unlimited
    requires_approval = Column(Boolean, default=False)
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(36), ForeignKey('users.id'))
    updated_by = Column(String(36), ForeignKey('users.id'))
    
    # Relationships
    members = relationship(
        'User',
        secondary=user_teams,
        lazy='dynamic'
    )
    
    permissions = relationship(
        'Permission',
        secondary=team_permissions,
        lazy='dynamic'
    )
    
    # Self-referential relationship for parent/child teams
    parent_team = relationship('Team', remote_side=[id], backref='child_teams')
    
    # Indexes
    __table_args__ = (
        Index('idx_team_name', 'name'),
        Index('idx_team_active', 'is_active'),
        Index('idx_team_type', 'team_type'),
        Index('idx_team_parent', 'parent_team_id'),
    )
    
    def __repr__(self):
        return f"<Team {self.name}>"
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "is_active": self.is_active,
            "team_type": self.team_type,
            "parent_team_id": self.parent_team_id,
            "max_members": self.max_members,
            "requires_approval": self.requires_approval,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_member_count(self) -> int:
        """Get current member count"""
        return self.members.count()
    
    def can_add_member(self) -> bool:
        """Check if team can accept new members"""
        if not self.is_active:
            return False
        if self.max_members is None:
            return True
        return self.get_member_count() < self.max_members


class PasswordHistory(Base):
    """Password history for users - separate table for better performance"""
    __tablename__ = "password_history"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    user = relationship('User', backref=backref('password_history_entries', lazy='dynamic'))
    
    # Indexes
    __table_args__ = (
        Index('idx_password_history_user_id', 'user_id'),
        Index('idx_password_history_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<PasswordHistory {self.user_id}>"