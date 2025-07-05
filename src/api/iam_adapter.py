"""
IAM Service Adapter for OMS Compatibility
Provides OMS-compatible endpoints that map to User-Service functionality
"""
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, field_validator, constr

from core.database import get_db
from core.config import settings
from core.validators import sanitize_string
from services.auth_service import AuthService
from services.user_service import UserService

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# OMS-Compatible Request/Response Models
class TokenValidationRequest(BaseModel):
    token: constr(min_length=1, max_length=2048)
    required_scopes: Optional[List[str]] = None
    
    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Token cannot be empty")
        return v


class TokenValidationResponse(BaseModel):
    valid: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    teams: Optional[List[str]] = None
    scopes: Optional[List[str]] = None
    exp: Optional[int] = None
    error: Optional[str] = None


class UserInfoRequest(BaseModel):
    user_id: Optional[constr(min_length=1, max_length=255)] = None
    username: Optional[constr(min_length=1, max_length=255)] = None
    email: Optional[constr(min_length=1, max_length=255)] = None
    
    @field_validator('user_id', 'username', 'email')
    @classmethod
    def sanitize_fields(cls, v):
        if v:
            return sanitize_string(v)
        return v


class UserInfoResponse(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: Optional[str]
    roles: List[str]
    permissions: List[str]
    teams: List[str]
    mfa_enabled: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ScopeCheckRequest(BaseModel):
    user_id: str
    required_scopes: List[str]


class ScopeCheckResponse(BaseModel):
    authorized: bool
    user_id: str
    granted_scopes: List[str]
    missing_scopes: List[str]


class ServiceAuthRequest(BaseModel):
    service_id: str
    service_secret: str
    requested_scopes: List[str]


class ServiceAuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    granted_scopes: List[str]


class IAMHealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    services: dict


# OMS-Compatible Endpoints
@router.post("/api/v1/auth/validate", response_model=TokenValidationResponse)
async def validate_token(
    request: TokenValidationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    OMS-compatible token validation endpoint
    Maps to User-Service token validation
    """
    auth_service = AuthService(db)
    
    try:
        # Decode and validate token
        payload = auth_service.decode_token(request.token)
        
        # Get user data
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            return TokenValidationResponse(
                valid=False,
                error="User not found"
            )
        
        # Check required scopes (map to permissions)
        if request.required_scopes:
            user_permissions = set(user.permissions)
            required_permissions = set(request.required_scopes)
            
            if not required_permissions.issubset(user_permissions):
                return TokenValidationResponse(
                    valid=False,
                    error="Insufficient permissions"
                )
        
        # Convert permissions to scopes for OMS compatibility
        scopes = _convert_permissions_to_scopes(user.permissions)
        
        return TokenValidationResponse(
            valid=True,
            user_id=user.id,
            username=user.username,
            email=user.email,
            roles=user.roles,
            permissions=user.permissions,
            teams=user.teams,
            scopes=scopes,
            exp=payload.get("exp")
        )
        
    except Exception as e:
        return TokenValidationResponse(
            valid=False,
            error=str(e)
        )


@router.post("/api/v1/users/info", response_model=UserInfoResponse)
async def get_user_info_by_id(
    request: UserInfoRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    OMS-compatible user info endpoint
    Maps to User-Service user lookup
    """
    auth_service = AuthService(db)
    user_service = UserService(db)
    
    try:
        user = None
        
        # Try to find user by provided identifier
        if request.user_id:
            user = await auth_service.get_user_by_id(request.user_id)
        elif request.username:
            user = await user_service.get_user_by_username(request.username)
        elif request.email:
            user = await user_service.get_user_by_email(request.email)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserInfoResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            roles=user.roles,
            permissions=user.permissions,
            teams=user.teams,
            mfa_enabled=user.mfa_enabled,
            is_active=user.is_active,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/api/v1/auth/check-scopes", response_model=ScopeCheckResponse)
async def check_scopes(
    request: ScopeCheckRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    OMS-compatible scope checking endpoint
    Maps to User-Service permission checking
    """
    auth_service = AuthService(db)
    
    try:
        # Get user
        user = await auth_service.get_user_by_id(request.user_id)
        
        if not user:
            return ScopeCheckResponse(
                authorized=False,
                user_id=request.user_id,
                granted_scopes=[],
                missing_scopes=request.required_scopes
            )
        
        # Convert scopes to permissions for checking
        required_permissions = _convert_scopes_to_permissions(request.required_scopes)
        user_permissions = set(user.permissions)
        
        # Check which permissions are granted
        granted_permissions = []
        missing_permissions = []
        
        for perm in required_permissions:
            if user.has_permission(perm):
                granted_permissions.append(perm)
            else:
                missing_permissions.append(perm)
        
        # Convert back to scopes
        granted_scopes = _convert_permissions_to_scopes(granted_permissions)
        missing_scopes = _convert_permissions_to_scopes(missing_permissions)
        
        return ScopeCheckResponse(
            authorized=len(missing_permissions) == 0,
            user_id=request.user_id,
            granted_scopes=granted_scopes,
            missing_scopes=missing_scopes
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/api/v1/auth/service", response_model=ServiceAuthResponse)
async def service_auth(
    request: ServiceAuthRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    OMS-compatible service authentication endpoint
    Creates service tokens for inter-service communication
    """
    auth_service = AuthService(db)
    
    try:
        # Validate service credentials
        if not _validate_service_credentials(request.service_id, request.service_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service credentials"
            )
        
        # Get or create service user
        service_user = await _get_or_create_service_user(
            request.service_id, 
            request.requested_scopes,
            db
        )
        
        # Create service token
        access_token = auth_service.create_access_token(service_user)
        
        return ServiceAuthResponse(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            granted_scopes=_convert_permissions_to_scopes(service_user.permissions)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/api/v1/auth/refresh")
async def refresh_token_iam(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    OMS-compatible token refresh endpoint
    Maps to User-Service token refresh
    """
    auth_service = AuthService(db)
    
    try:
        # Validate refresh token
        payload = auth_service.decode_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")
        
        user_id = payload.get("sub")
        user = await auth_service.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # Generate new access token
        access_token = auth_service.create_access_token(user)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/iam/validate-token", response_model=TokenValidationResponse)
async def validate_token_iam(
    request: TokenValidationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    IAM-compatible token validation endpoint
    """
    return await validate_token(request, db)


@router.get("/health", response_model=IAMHealthResponse)
async def health_check():
    """
    OMS-compatible health check endpoint
    """
    return IAMHealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc),
        services={
            "database": "healthy",
            "redis": "healthy",
            "authentication": "healthy"
        }
    )


# Helper functions
def _convert_permissions_to_scopes(permissions: List[str]) -> List[str]:
    """
    Convert User-Service permissions to OMS-compatible scopes
    """
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
    
    return scopes


def _convert_scopes_to_permissions(scopes: List[str]) -> List[str]:
    """
    Convert OMS scopes to User-Service permissions
    """
    permission_mapping = {
        "api:ontologies:read": "ontology:*:read",
        "api:ontologies:write": "ontology:*:write",
        "api:ontologies:admin": "ontology:*:admin",
        "api:schemas:read": "schema:*:read",
        "api:schemas:write": "schema:*:write",
        "api:schemas:admin": "schema:*:admin",
        "api:branches:read": "branch:*:read",
        "api:branches:write": "branch:*:write",
        "api:proposals:read": "proposal:*:read",
        "api:proposals:write": "proposal:*:write",
        "api:proposals:approve": "proposal:*:approve",
        "api:audit:read": "audit:*:read",
        "api:system:admin": "system:*:admin",
        "api:service:account": "service:*:account",
        "api:webhook:execute": "webhook:*:execute"
    }
    
    permissions = []
    for scope in scopes:
        if scope in permission_mapping:
            permissions.append(permission_mapping[scope])
        else:
            # Default mapping
            permissions.append(scope.replace("api:", "").replace(":", ":*:"))
    
    return permissions


def _validate_service_credentials(service_id: str, service_secret: str) -> bool:
    """
    Validate service credentials
    In production, this would check against a service registry
    """
    # Simple validation for demo
    valid_services = {
        "oms-monolith": settings.JWT_SECRET,
        "oms-service": settings.JWT_SECRET
    }
    
    return service_id in valid_services and valid_services[service_id] == service_secret


async def _get_or_create_service_user(
    service_id: str, 
    requested_scopes: List[str],
    db: AsyncSession
):
    """
    Get or create a service user for inter-service communication
    """
    from models.user import User, UserStatus
    from services.user_service import UserService
    
    user_service = UserService(db)
    
    # Try to get existing service user
    service_user = await user_service.get_user_by_username(f"service-{service_id}")
    
    if not service_user:
        # Create service user
        permissions = _convert_scopes_to_permissions(requested_scopes)
        
        service_user = await user_service.create_user(
            username=f"service-{service_id}",
            email=f"{service_id}@system.local",
            password="service-account-password",
            full_name=f"Service Account: {service_id}",
            roles=["service"],
            created_by="system"
        )
        
        # Set permissions and teams (update after creation)
        service_user.permissions = permissions
        service_user.teams = ["system"]
        service_user.status = UserStatus.ACTIVE
        await db.commit()
    
    return service_user