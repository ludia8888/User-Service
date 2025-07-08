"""
Multi-Factor Authentication Router
Handles MFA setup, enable/disable, and backup codes
"""
import base64
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, constr, field_validator

from core.database import get_db
from services.auth_service import AuthService
from services.mfa_service import MFAService
from services.audit_service import AuditService
from services.service_factory import create_service_factory

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


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


@router.post("/setup")
async def setup_mfa(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Setup MFA for authenticated user
    
    Returns secret and QR code for authenticator app
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    mfa_service = service_factory.get_mfa_service()
    
    try:
        # Get user from token
        payload = await auth_service.verify_token(token)
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


@router.post("/enable")
async def enable_mfa(
    request: MFAEnableRequest,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Enable MFA after verifying initial code
    
    Returns backup codes
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    mfa_service = service_factory.get_mfa_service()
    audit_service = service_factory.get_audit_service()
    
    try:
        # Get user from token
        payload = await auth_service.verify_token(token)
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


@router.post("/disable")
async def disable_mfa(
    request: MFADisableRequest,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Disable MFA for user
    
    Requires password and current MFA code
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    mfa_service = service_factory.get_mfa_service()
    audit_service = service_factory.get_audit_service()
    
    try:
        # Get user from token
        payload = await auth_service.verify_token(token)
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


@router.post("/regenerate-backup-codes")
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
        payload = await auth_service.verify_token(token)
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