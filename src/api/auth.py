"""
Authentication API endpoints
"""
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, List

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
from services.mfa_service import MFAService
from services.audit_service import AuditService

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
    audit_service = AuditService(db)
    
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
        
        # Log user creation
        await audit_service.log_user_created(
            user_id=str(user.id),
            username=user.username,
            email=user.email,
            created_by="self-registration",
            roles=user.roles
        )
        
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
    audit_service = AuditService(db)
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
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
        # Log failed login
        await audit_service.log_login_failed(
            username=form_data.username,
            ip_address=client_ip,
            user_agent=user_agent,
            reason=str(e)
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
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    try:
        # Extract user info from token
        payload = auth_service.decode_token(token)
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


# MFA Endpoints

class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: Optional[List[str]] = None


class MFAEnableRequest(BaseModel):
    code: constr(min_length=6, max_length=6)
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v):
        if not v.isdigit():
            raise ValueError("MFA code must be 6 digits")
        return v


class MFADisableRequest(BaseModel):
    password: constr(min_length=1, max_length=255)
    code: constr(min_length=6, max_length=6)


@router.post("/mfa/setup")
async def setup_mfa(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Setup MFA for authenticated user
    
    Returns secret and QR code for authenticator app
    """
    auth_service = AuthService(db)
    mfa_service = MFAService(db)
    
    try:
        # Get user from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if user.mfa_enabled:
            raise ValueError("MFA already enabled")
        
        # Generate MFA secret
        secret, provisioning_uri = await mfa_service.generate_mfa_secret(user)
        
        # Generate QR code
        qr_code_bytes = mfa_service.generate_qr_code(provisioning_uri)
        qr_code_base64 = base64.b64encode(qr_code_bytes).decode()
        
        return MFASetupResponse(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}"
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup MFA"
        )


@router.post("/mfa/enable")
async def enable_mfa(
    request: MFAEnableRequest,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Enable MFA after verifying initial code
    
    Returns backup codes
    """
    auth_service = AuthService(db)
    mfa_service = MFAService(db)
    audit_service = AuditService(db)
    
    try:
        # Get user from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # Enable MFA
        backup_codes = await mfa_service.enable_mfa(user, request.code)
        
        # Log MFA enablement
        await audit_service.log_mfa_enabled(
            user_id=user.id,
            username=user.username
        )
        
        return {
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable MFA"
        )


@router.post("/mfa/disable")
async def disable_mfa(
    request: MFADisableRequest,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Disable MFA for user
    
    Requires password and current MFA code
    """
    auth_service = AuthService(db)
    mfa_service = MFAService(db)
    audit_service = AuditService(db)
    
    try:
        # Get user from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not user.mfa_enabled:
            raise ValueError("MFA not enabled")
        
        # Verify password
        if not auth_service.verify_password(request.password, user.password_hash):
            raise ValueError("Invalid password")
        
        # Verify MFA code
        if not await mfa_service.verify_totp(user, request.code):
            raise ValueError("Invalid MFA code")
        
        # Disable MFA
        await mfa_service.disable_mfa(user, request.password)
        
        # Log MFA disablement
        await audit_service.log_mfa_disabled(
            user_id=user.id,
            username=user.username
        )
        
        return {"message": "MFA disabled successfully"}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA"
        )


@router.post("/mfa/regenerate-backup-codes")
async def regenerate_backup_codes(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Regenerate backup codes for MFA
    """
    auth_service = AuthService(db)
    mfa_service = MFAService(db)
    
    try:
        # Get user from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not user.mfa_enabled:
            raise ValueError("MFA not enabled")
        
        # Regenerate codes
        backup_codes = await mfa_service.regenerate_backup_codes(user)
        
        return {
            "message": "Backup codes regenerated successfully",
            "backup_codes": backup_codes
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes"
        )


# Password Management Endpoints

class PasswordChangeRequest(BaseModel):
    old_password: constr(min_length=1, max_length=255)
    new_password: constr(min_length=8, max_length=128)
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        return validate_password(v)


@router.post("/change-password")
async def change_password(
    request: Request,
    password_request: PasswordChangeRequest,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Change user password
    
    Validates:
    - Old password is correct
    - New password meets policy requirements
    - New password not in history
    """
    auth_service = AuthService(db)
    user_service = UserService(db)
    audit_service = AuditService(db)
    
    try:
        # Get user from token
        payload = auth_service.decode_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise ValueError("Invalid token")
        
        # Change password
        user = await user_service.change_password(
            user_id=user_id,
            old_password=password_request.old_password,
            new_password=password_request.new_password,
            changed_by=user_id
        )
        
        # Log password change
        client_ip = request.client.host if request.client else "unknown"
        await audit_service.log_password_changed(
            user_id=user_id,
            username=user.username,
            changed_by=user_id,
            ip_address=client_ip
        )
        
        return {"message": "Password changed successfully"}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
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