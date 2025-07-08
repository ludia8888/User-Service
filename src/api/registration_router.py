"""
User Registration Router
Handles new user registration
"""
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, field_validator, constr
from schemas.user_schemas import UserCreate, UserCreateResponse, UserBasicInfo

from core.database import get_db
from core.rate_limit import rate_limit
from core.validators import (
    validate_username, validate_email, validate_password,
    validate_full_name, sanitize_string
)
from services.user_service import UserService
from services.audit_service import AuditService

router = APIRouter()


class RegisterRequest(BaseModel):
    username: constr(min_length=3, max_length=32)
    email: EmailStr
    password: constr(min_length=8, max_length=128)
    full_name: Optional[constr(min_length=2, max_length=100)] = None
    role_names: Optional[list[str]] = ["user"]
    
    @field_validator('username')
    @classmethod
    def validate_username_field(cls, v):
        return validate_username(v)
    
    @field_validator('email')
    @classmethod
    def validate_email_field(cls, v):
        return validate_email(v)
    
    @field_validator('password')
    @classmethod
    def validate_password_field(cls, v):
        return validate_password(v)
    
    @field_validator('full_name')
    @classmethod
    def validate_name_field(cls, v):
        return validate_full_name(v)
    
    @field_validator('role_names')
    @classmethod
    def validate_roles(cls, v):
        # Only validate format - business logic validation moved to service layer
        if v and not isinstance(v, list):
            raise ValueError("role_names must be a list")
        if v:
            for role in v:
                if not isinstance(role, str) or not role.strip():
                    raise ValueError("Each role must be a non-empty string")
        return v


class UserInfoResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    role_names: list[str]
    permission_names: list[str]
    team_names: list[str]
    mfa_enabled: bool


class RegisterResponse(BaseModel):
    user: UserInfoResponse
    message: str = "User registered successfully"


@router.post("/register", response_model=RegisterResponse)
@rate_limit(requests=5, window=300)  # 5 registrations per 5 minutes
async def register(
    request: Request,
    register_request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    
    - Validates input data
    - Checks for existing users
    - Creates new user account
    - Sets default permissions based on roles
    """
    user_service = UserService(db)
    audit_service = AuditService(db)
    
    
    # Check if user already exists - do both checks in parallel to prevent timing attacks
    username_check, email_check = await asyncio.gather(
        user_service.get_user_by_username(register_request.username),
        user_service.get_user_by_email(register_request.email),
        return_exceptions=True
    )
    
    # Check results - use generic error message to prevent user enumeration
    if username_check and not isinstance(username_check, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    if email_check and not isinstance(email_check, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user with proper transaction management
    user = None
    try:
        # Create user with normalized model
        user = await user_service.create_user(
            username=register_request.username,
            email=register_request.email,
            password=register_request.password,
            full_name=register_request.full_name,
            role_names=register_request.role_names,
            created_by="self-registration"
        )
        
        # User creation includes audit logging in the service layer
        # Database transaction will be committed by the service
        
        # Return minimal response for security (no permission/role/team exposure)
        return UserCreateResponse(
            user=UserBasicInfo(
                user_id=str(user.id),
                username=user.username,
                email=user.email,
                status=user.status
            )
        )
        
    except Exception as e:
        # Log error without exposing internal details
        try:
            await audit_service.log_suspicious_activity(
                user_id=str(user.id) if user else None,
                ip_address=request.client.host if request.client else "unknown",
                activity="registration_error",
                details={
                    "username": register_request.username, 
                    "error": "registration_failed",
                    "exception_type": type(e).__name__
                }
            )
        except Exception:
            # If audit logging fails, log locally
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Registration failed for {register_request.username}: {e}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )