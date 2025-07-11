"""
Organization model for multi-tenant support
Proper relational design for organizations
"""
import uuid
from datetime import datetime
from typing import List, Optional
from enum import Enum

from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, ForeignKey, Table, Index
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func

from core.database import Base


class OrganizationStatus(str, Enum):
    """Organization status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class OrganizationType(str, Enum):
    """Organization types"""
    ENTERPRISE = "enterprise"
    TEAM = "team"
    PERSONAL = "personal"
    TRIAL = "trial"


# Association table for users belonging to organizations
user_organizations = Table(
    'user_organizations',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id'), primary_key=True),
    Column('organization_id', String(36), ForeignKey('organizations.id'), primary_key=True),
    Column('joined_at', DateTime(timezone=True), server_default=func.now()),
    Column('role', String(50), default='member'),  # owner, admin, member
    Column('is_primary', Boolean, default=False),  # Primary organization for the user
    Index('idx_user_organizations_user_id', 'user_id'),
    Index('idx_user_organizations_org_id', 'organization_id'),
    Index('idx_user_organizations_primary', 'user_id', 'is_primary')
)


class Organization(Base):
    """Organization model for multi-tenant support"""
    __tablename__ = "organizations"
    
    # Primary fields
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)  # URL-friendly identifier
    description = Column(Text)
    
    # Organization details
    type = Column(String(20), default=OrganizationType.TEAM, index=True)
    status = Column(String(20), default=OrganizationStatus.ACTIVE, index=True)
    
    # Contact information
    email = Column(String(255))
    phone = Column(String(50))
    website = Column(String(255))
    
    # Address
    address_line1 = Column(String(255))
    address_line2 = Column(String(255))
    city = Column(String(100))
    state = Column(String(100))
    postal_code = Column(String(20))
    country = Column(String(2))  # ISO country code
    
    # Billing information
    billing_email = Column(String(255))
    tax_id = Column(String(50))
    
    # Limits and quotas
    max_users = Column(Integer, default=5)
    max_teams = Column(Integer, default=1)
    max_schemas = Column(Integer, default=10)
    storage_quota_mb = Column(Integer, default=1000)
    
    # Features flags
    features = Column(Text)  # JSON string of enabled features
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String(36), ForeignKey('users.id'))
    updated_by = Column(String(36), ForeignKey('users.id'))
    
    # Relationships
    users = relationship(
        "User",
        secondary=user_organizations,
        back_populates="organizations",
        lazy="select"
    )
    
    teams = relationship(
        "Team",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    # Creator relationship
    creator = relationship(
        "User",
        foreign_keys=[created_by],
        backref=backref("created_organizations", lazy="select")
    )
    
    # Updater relationship
    updater = relationship(
        "User",
        foreign_keys=[updated_by],
        backref=backref("updated_organizations", lazy="select")
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_organizations_status_type', 'status', 'type'),
        Index('idx_organizations_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Organization(id={self.id}, name={self.name}, slug={self.slug})>"
    
    @property
    def is_active(self) -> bool:
        """Check if organization is active"""
        return self.status == OrganizationStatus.ACTIVE
    
    @property
    def member_count(self) -> int:
        """Get current member count"""
        return len(self.users)
    
    @property
    def team_count(self) -> int:
        """Get current team count"""
        return len(self.teams)
    
    def can_add_user(self) -> bool:
        """Check if organization can add more users"""
        return self.member_count < self.max_users
    
    def can_add_team(self) -> bool:
        """Check if organization can add more teams"""
        return self.team_count < self.max_teams