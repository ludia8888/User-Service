"""
Core Authentication Router
Handles login, logout, and token refresh
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, constr, field_validator

from core.database import get_db
from core.config import settings
from core.rate_limit import rate_limit
from services.auth_service import AuthService
from services.user_service import UserService
from services.audit_service import AuditService
from services.service_factory import create_service_factory

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


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


class LoginRequest(BaseModel):
    username: constr(min_length=1, max_length=255)
    password: constr(min_length=1, max_length=255)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v:
            raise ValueError("Password cannot be empty")
        return v


class MFARequest(BaseModel):
    challenge_token: constr(min_length=1)
    mfa_code: Optional[constr(min_length=6, max_length=8)] = None
    
    @field_validator('challenge_token')
    @classmethod
    def validate_challenge_token(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Challenge token cannot be empty")
        return v
    
    @field_validator('mfa_code')
    @classmethod
    def validate_mfa_code(cls, v):
        if v is not None:
            v = v.strip()
            if not v:
                return None
            # MFA codes are either 6-digit TOTP or 8-character backup codes
            if not (v.isdigit() and len(v) == 6) and not (v.isalnum() and len(v) == 8):
                raise ValueError("MFA code must be a 6-digit number or 8-character backup code")
        return v


class AuthChallengeResponse(BaseModel):
    step: str
    challenge_token: Optional[str] = None
    message: str


@router.post("/login", response_model=AuthChallengeResponse)
@rate_limit(requests=10, window=60)  # 10 login attempts per minute
async def login_step1(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Step 1: User login with username and password
    
    - Validates credentials
    - Returns challenge token for step 2
    - Does not reveal MFA status for security
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    audit_service = service_factory.get_audit_service()
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Step 1 authentication
        result = await auth_service.authenticate_step1(
            username=login_data.username,
            password=login_data.password,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return AuthChallengeResponse(
            step=result["step"],
            challenge_token=result["challenge_token"],
            message=result["message"]
        )
        
    except ValueError as e:
        # Log failed login without exposing specific failure reason
        await audit_service.log_login_failed(
            username=login_data.username,
            ip_address=client_ip,
            user_agent=user_agent,
            reason="Authentication failed"  # Generic reason for security
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/login/complete", response_model=LoginResponse)
@rate_limit(requests=10, window=60)  # 10 MFA attempts per minute
async def login_step2(
    request: Request,
    mfa_data: MFARequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Step 2: Complete login with MFA code (if required)
    
    - Validates challenge token and MFA code
    - Returns JWT tokens on success
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    user_service = service_factory.get_user_service()
    audit_service = service_factory.get_audit_service()
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Step 2 authentication
        user = await auth_service.authenticate_step2(
            challenge_token=mfa_data.challenge_token,
            mfa_code=mfa_data.mfa_code
        )
        
        # Generate tokens
        access_token = await auth_service.create_access_token(user)
        refresh_token = auth_service.create_refresh_token(user)
        
        # Update last login
        await user_service.update_last_login(user.id)
        
        # Log successful login
        await audit_service.log_login_success(
            user_id=user.id,
            username=user.username,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except ValueError as e:
        # Log failed MFA attempt
        await audit_service.log_login_failed(
            username="unknown",  # Don't expose username in step 2
            ip_address=client_ip,
            user_agent=user_agent,
            reason="MFA verification failed"
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/login/legacy", response_model=LoginResponse)
@rate_limit(requests=5, window=60)  # More restrictive for legacy endpoint
async def login_legacy(
    request: Request,
    login_data: LoginRequest,
    mfa_code: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Legacy single-step login endpoint (deprecated)
    
    - Supports old authentication flow
    - Should be migrated to two-step flow
    - More restrictive rate limiting
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    user_service = service_factory.get_user_service()
    audit_service = service_factory.get_audit_service()
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    
    try:
        # Legacy single-step authentication
        user = await auth_service.authenticate(
            username=login_data.username,
            password=login_data.password,
            mfa_code=mfa_code,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Generate tokens
        access_token = await auth_service.create_access_token(user)
        refresh_token = auth_service.create_refresh_token(user)
        
        # Update last login
        await user_service.update_last_login(user.id)
        
        # Log successful login
        await audit_service.log_login_success(
            user_id=user.id,
            username=user.username,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except ValueError as e:
        # Log failed login without exposing specific failure reason
        await audit_service.log_login_failed(
            username=login_data.username,
            ip_address=client_ip,
            user_agent=user_agent,
            reason="Authentication failed"  # Generic reason for security
        )
        
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
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    audit_service = service_factory.get_audit_service()
    
    try:
        # Extract user info from token
        payload = await auth_service.verify_token(token)
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        
        if user_id and session_id:
            await auth_service.revoke_session(session_id, user_id)
            
            # Get user info for audit log
            user = await auth_service.get_user_by_id(user_id)
            if user:
                await audit_service.log_logout(
                    user_id=user_id,
                    username=user.username,
                    session_id=session_id
                )
        
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
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    
    try:
        # Validate refresh token
        payload = await auth_service.verify_token(token_request.refresh_token)
        
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")
        
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # Generate new access token
        access_token = await auth_service.create_access_token(user)
        
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


@router.get("/account/userinfo")
async def get_user_info(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user information from JWT token
    
    - Returns user details including roles and scopes
    - Used by OMS AuthMiddleware for token validation
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    rbac_service = service_factory.get_rbac_service()
    
    try:
        # Verify token and get user data
        user_data = await auth_service.verify_token_and_get_user_data(token)
        
        if not user_data or not user_data.get("user"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        user = user_data.get("user")
        
        # Get user roles and permissions
        user_roles = await rbac_service.get_user_roles(user.id)
        role_names = [role.name for role in user_roles]
        
        permissions = await rbac_service.get_user_permissions(user.id)
        
        # Convert permissions to scopes for OMS compatibility
        from api.iam_adapter import _convert_permissions_to_scopes
        scopes = _convert_permissions_to_scopes(list(permissions))
        
        return {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "roles": role_names,
            "permissions": list(permissions),
            "scopes": scopes,
            "teams": user_data.get("teams", []),
            "is_active": user.is_active,
            "mfa_enabled": user.mfa_enabled
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )