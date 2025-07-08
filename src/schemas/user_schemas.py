"""
User-related Pydantic schemas for normalized data model
Consistent response schemas across all API endpoints
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user fields"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)


class UserCreate(UserBase):
    """Schema for creating a new user"""
    password: str = Field(..., min_length=8, max_length=128)
    role_names: Optional[List[str]] = Field(default=["user"])


class UserUpdate(BaseModel):
    """Schema for updating user information"""
    full_name: Optional[str] = Field(None, max_length=100)
    role_names: Optional[List[str]] = None
    team_names: Optional[List[str]] = None


class UserResponse(BaseModel):
    """Standard user response schema"""
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    role_names: List[str]
    permission_names: List[str]
    team_names: List[str]
    status: str
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Response schema for user lists"""
    users: List[UserResponse]
    total: int
    page: int
    per_page: int


class UserBasicInfo(BaseModel):
    """Minimal user information for security-sensitive responses"""
    user_id: str
    username: str
    email: str
    status: str

    class Config:
        from_attributes = True


class UserCreateResponse(BaseModel):
    """Secure response schema for user creation - minimal information only"""
    user: UserBasicInfo
    message: str = "User registered successfully. Please check your email for verification instructions."
    next_steps: list[str] = [
        "Check your email for verification link",
        "Verify your email address",
        "Login with your credentials"
    ]


class UserUpdateResponse(BaseModel):
    """Response schema for user updates"""
    user: UserResponse
    message: str = "User updated successfully"


class RoleResponse(BaseModel):
    """Role information in responses"""
    name: str
    description: Optional[str]
    permissions: List[str]

    class Config:
        from_attributes = True


class TeamResponse(BaseModel):
    """Team information in responses"""
    name: str
    description: Optional[str]
    member_count: int

    class Config:
        from_attributes = True


class PermissionResponse(BaseModel):
    """Permission information in responses"""
    name: str
    description: Optional[str]
    resource_type: Optional[str]

    class Config:
        from_attributes = True


class UserProfileResponse(BaseModel):
    """Detailed user profile - only for authenticated profile access"""
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    status: str
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    roles: List[str] = []
    scopes: List[str] = []  # OMS-compatible scopes
    # Note: Detailed permissions/roles/teams available via separate endpoints
    # This prevents accidental exposure of privilege escalation information

    class Config:
        from_attributes = True


class UserPermissionsResponse(BaseModel):
    """User permissions - separate endpoint for security"""
    user_id: str
    roles: List[RoleResponse]
    direct_permissions: List[PermissionResponse]
    teams: List[TeamResponse]
    effective_permissions: List[str]  # Computed list of all permissions
    
    class Config:
        from_attributes = True