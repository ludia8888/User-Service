"""
User Profile Router
Secure access to detailed user information - requires authentication
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from middleware.auth_dependencies import get_current_user
from schemas.user_schemas import UserProfileResponse, UserPermissionsResponse, RoleResponse, TeamResponse, PermissionResponse
from services.user_service import UserService
from models.user import User

router = APIRouter()


@router.get("/profile", response_model=UserProfileResponse)
async def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's profile information
    
    Returns basic profile information without exposing detailed permissions.
    Use separate endpoints for permission details if needed.
    """
    return UserProfileResponse(
        user_id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        status=current_user.status,
        mfa_enabled=current_user.mfa_enabled,
        created_at=current_user.created_at,
        last_login=current_user.last_login
    )


@router.get("/profile/{user_id}", response_model=UserProfileResponse)
async def get_user_profile_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get another user's profile information (admin only)
    
    Security: Only accessible by admin users
    """
    # Check if current user has permission to view other profiles
    if not current_user.has_permission("user:read") and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view user profile"
        )
    
    user_service = UserService(db)
    target_user = await user_service.get_user_by_id(user_id)
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserProfileResponse(
        user_id=str(target_user.id),
        username=target_user.username,
        email=target_user.email,
        full_name=target_user.full_name,
        status=target_user.status,
        mfa_enabled=target_user.mfa_enabled,
        created_at=target_user.created_at,
        last_login=target_user.last_login
    )


@router.get("/permissions", response_model=UserPermissionsResponse)
async def get_user_permissions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's detailed permission information
    
    Security: Separate endpoint to prevent accidental exposure
    Only returns permissions for the authenticated user
    """
    # Build role responses
    roles = []
    for role in current_user.roles:
        role_permissions = [perm.name for perm in role.permissions]
        roles.append(RoleResponse(
            name=role.name,
            description=role.description,
            permissions=role_permissions
        ))
    
    # Build direct permissions
    direct_perms = []
    for perm in current_user.direct_permissions:
        direct_perms.append(PermissionResponse(
            name=perm.name,
            description=perm.description,
            resource_type=perm.resource_type
        ))
    
    # Build teams
    teams = []
    for team in current_user.teams:
        teams.append(TeamResponse(
            name=team.name,
            description=team.description,
            member_count=team.members.count()
        ))
    
    # Get effective permissions
    effective_permissions = list(current_user.get_all_permissions())
    
    return UserPermissionsResponse(
        user_id=str(current_user.id),
        roles=roles,
        direct_permissions=direct_perms,
        teams=teams,
        effective_permissions=effective_permissions
    )


@router.get("/permissions/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get another user's permission information (admin only)
    
    Security: Only accessible by admin users or users with user:permissions:read
    """
    # Check if current user has permission to view other users' permissions
    if not current_user.has_permission("user:permissions:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view user permissions"
        )
    
    user_service = UserService(db)
    target_user = await user_service.get_user_by_id(user_id)
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Build responses (same logic as above)
    roles = []
    for role in target_user.roles:
        role_permissions = [perm.name for perm in role.permissions]
        roles.append(RoleResponse(
            name=role.name,
            description=role.description,
            permissions=role_permissions
        ))
    
    direct_perms = []
    for perm in target_user.direct_permissions:
        direct_perms.append(PermissionResponse(
            name=perm.name,
            description=perm.description,
            resource_type=perm.resource_type
        ))
    
    teams = []
    for team in target_user.teams:
        teams.append(TeamResponse(
            name=team.name,
            description=team.description,
            member_count=team.members.count()
        ))
    
    effective_permissions = list(target_user.get_all_permissions())
    
    return UserPermissionsResponse(
        user_id=str(target_user.id),
        roles=roles,
        direct_permissions=direct_perms,
        teams=teams,
        effective_permissions=effective_permissions
    )