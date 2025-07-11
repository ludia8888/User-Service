"""
Organization schemas
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, validator
import re

from models.organization import OrganizationType, OrganizationStatus


class OrganizationBase(BaseModel):
    """Base organization schema"""
    name: str = Field(..., min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    type: OrganizationType = OrganizationType.TEAM
    
    # Contact information
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    
    # Address
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = Field(None, max_length=2)  # ISO country code
    
    @validator('slug')
    def validate_slug(cls, v):
        if v and not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if v and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):
            raise ValueError('Invalid email format')
        return v


class OrganizationCreate(OrganizationBase):
    """Schema for creating organization"""
    pass


class OrganizationUpdate(BaseModel):
    """Schema for updating organization"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    status: Optional[OrganizationStatus] = None
    
    # Contact information
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    
    # Address
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = Field(None, max_length=2)
    
    # Limits
    max_users: Optional[int] = Field(None, ge=1)
    max_teams: Optional[int] = Field(None, ge=0)
    max_schemas: Optional[int] = Field(None, ge=0)
    storage_quota_mb: Optional[int] = Field(None, ge=0)
    
    @validator('slug')
    def validate_slug(cls, v):
        if v and not re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if v and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', v):
            raise ValueError('Invalid email format')
        return v


class OrganizationResponse(OrganizationBase):
    """Organization response schema"""
    id: str
    status: OrganizationStatus
    
    # Limits
    max_users: int
    max_teams: int
    max_schemas: int
    storage_quota_mb: int
    
    # Counts
    member_count: int = 0
    team_count: int = 0
    
    # Audit fields
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[str]
    updated_by: Optional[str]
    
    class Config:
        orm_mode = True
        
    @classmethod
    def from_orm(cls, obj):
        # Add computed properties
        data = {
            **obj.__dict__,
            'member_count': obj.member_count,
            'team_count': obj.team_count
        }
        return cls(**data)


class OrganizationListResponse(BaseModel):
    """Simplified organization for list views"""
    id: str
    name: str
    slug: str
    type: OrganizationType
    status: OrganizationStatus
    member_count: int = 0
    created_at: datetime
    
    class Config:
        orm_mode = True
        
    @classmethod
    def from_orm(cls, obj):
        data = {
            **obj.__dict__,
            'member_count': obj.member_count
        }
        return cls(**data)


class OrganizationMemberResponse(BaseModel):
    """Organization with user membership details"""
    id: str
    name: str
    slug: str
    type: OrganizationType
    status: OrganizationStatus
    role: str  # owner, admin, member
    is_primary: bool
    
    class Config:
        orm_mode = True