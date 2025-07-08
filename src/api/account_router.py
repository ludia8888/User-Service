"""
Account Management Router
Handles user profile, password changes, and permissions
"""
from typing import Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, constr, field_validator
from schemas.user_schemas import UserProfileResponse
from api.registration_router import UserInfoResponse

from core.database import get_db
from core.validators import validate_password
from services.auth_service import AuthService
from services.user_service import UserService
from services.audit_service import AuditService
from services.service_factory import create_service_factory
from middleware.auth_dependencies import CurrentUser, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Deprecated: Use UserProfileResponse from schemas instead


class PasswordChangeRequest(BaseModel):
    old_password: constr(min_length=1, max_length=255)
    new_password: constr(min_length=8, max_length=128)
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        return validate_password(v)


@router.get("/userinfo")
async def get_user_info(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user information
    
    - Returns user details from token
    - Includes roles and permissions
    """
    
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    
    try:
        # Verify token and get user
        payload = await auth_service.verify_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise ValueError("No user ID in token")
            
        # Get basic user info without loading relationships
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # For now, return basic scopes based on username
        # Admin users get full access
        permissions = []
        roles = []
        if user.username == "admin":
            roles = ["admin"]
            permissions = [
                "ontology:*:read", "ontology:*:write", "ontology:*:admin",
                "schema:*:read", "schema:*:write", "schema:*:admin",
                "system:*:admin"
            ]
        else:
            roles = ["user"]
            permissions = ["ontology:*:read", "schema:*:read"]
        scope_mapping = {
            "ontology:*:read": "api:ontologies:read",
            "ontology:*:write": "api:ontologies:write",
            "ontology:*:admin": "api:ontologies:admin",
            "schema:*:read": "api:schemas:read",
            "schema:*:write": "api:schemas:write",
            "schema:*:admin": "api:schemas:admin",
            "branch:*:read": "api:branches:read",
            "branch:*:write": "api:branches:write",
            "proposal:*:read": "api:proposals:read",
            "proposal:*:write": "api:proposals:write",
            "proposal:*:approve": "api:proposals:approve",
            "audit:*:read": "api:audit:read",
            "system:*:admin": "api:system:admin",
            "service:*:account": "api:service:account",
            "webhook:*:execute": "api:webhook:execute"
        }
        
        scopes = []
        for perm in permissions:
            if perm in scope_mapping:
                scopes.append(scope_mapping[perm])
            else:
                # Handle wildcard permissions
                if perm.endswith(":*:*"):
                    base = perm.replace(":*:*", "")
                    scopes.extend([
                        f"api:{base}:read",
                        f"api:{base}:write",
                        f"api:{base}:admin"
                    ])
                else:
                    # Default mapping
                    scopes.append(f"api:{perm.replace(':', ':')}")
        
        # Return a simple dict response that includes scopes
        return {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "status": user.status,
            "mfa_enabled": user.mfa_enabled if user.mfa_enabled is not None else False,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "roles": roles,
            "scopes": scopes
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/userinfo/optimized", response_model=UserInfoResponse)
async def get_user_info_optimized(
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Get current user information with real-time permissions (optimized)
    
    - Returns user details with latest permissions
    - Uses Redis caching for performance
    - Automatically handles token verification
    - Demonstrates new authentication system
    """
    return UserInfoResponse(
        user_id=current_user.user_id,
        username=current_user.username,
        email=current_user.email,
        full_name=None,  # Not included in optimized token, fetch from cache/db if needed
        roles=current_user.roles,
        permissions=current_user.permissions,
        teams=current_user.teams,
        mfa_enabled=current_user.mfa_enabled
    )


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
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    user_service = service_factory.get_user_service()
    audit_service = service_factory.get_audit_service()
    
    try:
        # Get user from token
        payload = await auth_service.verify_token(token)
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
    # Use service factory for proper dependency injection
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    
    # Verify the caller is authorized (e.g., OMS service)
    try:
        payload = await auth_service.verify_token(token)
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