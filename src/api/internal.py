"""
Internal API endpoints for service-to-service communication
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from core.database import get_db
from services.user_service import UserService
from services.auth_service import AuthService
from services.service_factory import create_service_factory
from middleware.api_key_auth import require_service_auth

router = APIRouter(prefix="/internal", tags=["Internal"])


class UserValidationRequest(BaseModel):
    """Request to validate user"""
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None


class UserValidationResponse(BaseModel):
    """Response for user validation"""
    valid: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    is_active: bool = False
    mfa_enabled: bool = False


class TokenValidationRequest(BaseModel):
    """Request to validate JWT token"""
    token: str


class TokenValidationResponse(BaseModel):
    """Response for token validation"""
    valid: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    expires_at: Optional[str] = None


@router.post("/validate-user", response_model=UserValidationResponse)
async def validate_user(
    request: UserValidationRequest,
    db: AsyncSession = Depends(get_db),
    service_name: str = Depends(require_service_auth(["audit-service", "oms-service"]))
):
    """
    Validate user existence and get basic info
    Used by other services to validate users
    """
    user_service = UserService(db)
    
    user = None
    if request.user_id:
        user = await user_service.get_user_by_id(request.user_id)
    elif request.username:
        user = await user_service.get_user_by_username(request.username)
    elif request.email:
        user = await user_service.get_user_by_email(request.email)
    
    if not user:
        return UserValidationResponse(valid=False)
    
    return UserValidationResponse(
        valid=True,
        user_id=str(user.id),
        username=user.username,
        email=user.email,
        roles=user.roles or [],
        permissions=user.permissions or [],
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled
    )


@router.post("/validate-token", response_model=TokenValidationResponse)
async def validate_token(
    request: TokenValidationRequest,
    db: AsyncSession = Depends(get_db),
    service_name: str = Depends(require_service_auth(["audit-service", "oms-service"]))
):
    """
    Validate JWT token and get user info
    Used by other services to validate user tokens
    """
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    
    try:
        # Validate token
        payload = auth_service.verify_token(request.token)
        user_id = payload.get("sub")
        
        if not user_id:
            return TokenValidationResponse(valid=False)
        
        # Get user info
        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)
        
        if not user or not user.is_active:
            return TokenValidationResponse(valid=False)
        
        return TokenValidationResponse(
            valid=True,
            user_id=str(user.id),
            username=user.username,
            email=user.email,
            roles=user.roles or [],
            permissions=user.permissions or [],
            expires_at=payload.get("exp")
        )
    
    except Exception:
        return TokenValidationResponse(valid=False)


@router.get("/users/{user_id}/permissions")
async def get_user_permissions(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    service_name: str = Depends(require_service_auth(["oms-service"]))
):
    """
    Get user permissions
    Used by OMS for authorization
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {
        "user_id": str(user.id),
        "username": user.username,
        "roles": user.roles or [],
        "permissions": user.permissions or [],
        "teams": user.teams or []
    }


@router.get("/health")
async def internal_health_check(
    service_name: str = Depends(require_service_auth())
):
    """
    Internal health check for service-to-service monitoring
    """
    return {
        "status": "healthy",
        "service": "user-service",
        "version": "1.0.0",
        "requester": service_name
    }