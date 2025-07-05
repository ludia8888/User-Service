"""
Authentication API endpoints
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, field_validator, constr

from core.database import get_db
from core.config import settings
from core.rate_limit import rate_limit
from core.validators import (
    validate_username, validate_email, validate_password,
    validate_mfa_code, validate_full_name, sanitize_string
)
from services.auth_service import AuthService
from services.user_service import UserService

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class LoginRequest(BaseModel):
    username: constr(min_length=1, max_length=255)
    password: constr(min_length=1, max_length=255)
    mfa_code: Optional[str] = None
    
    @field_validator('username')
    @classmethod
    def sanitize_username(cls, v):
        return sanitize_string(v)
    
    @field_validator('mfa_code')
    @classmethod
    def validate_mfa(cls, v):
        return validate_mfa_code(v)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefreshRequest(BaseModel):
    refresh_token: constr(min_length=1, max_length=2048)
    
    @field_validator('refresh_token')
    @classmethod
    def validate_token(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Refresh token cannot be empty")
        return v


class UserInfoResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    roles: list[str]
    permissions: list[str]
    teams: list[str]
    mfa_enabled: bool


class RegisterRequest(BaseModel):
    username: constr(min_length=3, max_length=32)
    email: EmailStr
    password: constr(min_length=8, max_length=128)
    full_name: Optional[constr(min_length=2, max_length=100)] = None
    roles: Optional[list[str]] = ["user"]
    
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
    
    @field_validator('roles')
    @classmethod
    def validate_roles(cls, v):
        if v:
            allowed_roles = ["user", "admin", "operator"]
            for role in v:
                if role not in allowed_roles:
                    raise ValueError(f"Invalid role: {role}")
        return v


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
    """
    user_service = UserService(db)
    
    # Check if user already exists
    existing_user = await user_service.get_user_by_username(register_request.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    existing_email = await user_service.get_user_by_email(register_request.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    try:
        user = await user_service.create_user(
            username=register_request.username,
            email=register_request.email,
            password=register_request.password,
            full_name=register_request.full_name,
            roles=register_request.roles,
            created_by="self-registration"
        )
        
        # Set default permissions for new users
        user.permissions = [
            "ontology:read:*",
            "schema:read:*",
            "branch:read:*"
        ]
        user.teams = ["users"]
        await db.commit()
        
        return RegisterResponse(
            user=UserInfoResponse(
                user_id=str(user.id),
                username=user.username,
                email=user.email,
                full_name=user.full_name,
                roles=user.roles,
                permissions=user.permissions,
                teams=user.teams,
                mfa_enabled=user.mfa_enabled
            )
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register user: {str(e)}"
        )


@router.post("/login", response_model=LoginResponse)
@rate_limit(requests=10, window=60)  # 10 login attempts per minute
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    User login endpoint
    
    - Validates credentials
    - Checks MFA if enabled
    - Returns JWT tokens
    """
    auth_service = AuthService(db)
    user_service = UserService(db)
    
    # Get client info
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Authenticate user
        user = await auth_service.authenticate(
            username=form_data.username,
            password=form_data.password,
            mfa_code=mfa_code,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Generate tokens
        access_token = auth_service.create_access_token(user)
        refresh_token = auth_service.create_refresh_token(user)
        
        # Update last login
        await user_service.update_last_login(user.id)
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    User logout endpoint
    
    - Invalidates current session
    - Clears session cache
    """
    auth_service = AuthService(db)
    
    try:
        # Extract user info from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        
        if user_id and session_id:
            await auth_service.revoke_session(session_id, user_id)
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        # Even if logout fails, return success
        return {"message": "Logged out"}


@router.post("/refresh", response_model=LoginResponse)
@rate_limit(requests=30, window=60)  # 30 refresh attempts per minute
async def refresh_token(
    request: Request,
    token_request: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token
    
    - Validates refresh token
    - Returns new access token
    """
    auth_service = AuthService(db)
    
    try:
        # Validate refresh token
        payload = auth_service.decode_token(token_request.refresh_token)
        
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")
        
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # Generate new access token
        access_token = auth_service.create_access_token(user)
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=token_request.refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/userinfo", response_model=UserInfoResponse)
async def get_user_info(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user information
    
    - Returns user details from token
    - Includes roles and permissions
    """
    auth_service = AuthService(db)
    
    try:
        # Decode token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        
        # Get fresh user data
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        return UserInfoResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            roles=user.roles,
            permissions=user.permissions,
            teams=user.teams,
            mfa_enabled=user.mfa_enabled
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/check-permission")
async def check_permission(
    user_id: str,
    resource_type: str,
    resource_id: str,
    action: str,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user has specific permission
    
    This endpoint is called by OMS for permission verification
    """
    auth_service = AuthService(db)
    
    # Verify the caller is authorized (e.g., OMS service)
    try:
        payload = auth_service.decode_token(token)
        # Could check if caller is a service account
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Get user
    user = await auth_service.get_user_by_id(user_id)
    if not user:
        return {"allowed": False}
    
    # Check permission
    permission = f"{resource_type}:{resource_id}:{action}"
    allowed = user.has_permission(permission)
    
    return {"allowed": allowed}