"""
Authentication API endpoints
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr

from core.database import get_db
from core.config import settings
from services.auth_service import AuthService
from services.user_service import UserService

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class UserInfoResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    roles: list[str]
    permissions: list[str]
    teams: list[str]
    mfa_enabled: bool


@router.post("/login", response_model=LoginResponse)
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
async def refresh_token(
    request: TokenRefreshRequest,
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
        payload = auth_service.decode_token(request.refresh_token)
        
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
            refresh_token=request.refresh_token,
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