"""
Admin API Routes for User Management
관리자용 사용자/권한/역할 관리 API
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from core.database import get_db
from middleware.auth_dependencies import require_roles, get_current_user
from services.service_factory import create_service_factory
from models.user import User as UserModel

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


# Request/Response Models
class RoleAssignmentRequest(BaseModel):
    user_id: str = Field(..., description="사용자 ID")
    role_name: str = Field(..., description="할당할 역할 이름")
    expires_at: Optional[str] = Field(None, description="만료 시간 (ISO 8601)")


class PermissionAssignmentRequest(BaseModel):
    user_id: str = Field(..., description="사용자 ID")
    permission_name: str = Field(..., description="할당할 권한 이름")
    expires_at: Optional[str] = Field(None, description="만료 시간 (ISO 8601)")


class TeamAssignmentRequest(BaseModel):
    user_id: str = Field(..., description="사용자 ID")
    team_name: str = Field(..., description="팀 이름")
    role_in_team: str = Field("member", description="팀 내 역할 (member/lead/admin)")


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, description="전체 이름")
    roles: Optional[List[str]] = Field(None, description="역할 목록")
    teams: Optional[List[str]] = Field(None, description="팀 목록")
    is_active: Optional[bool] = Field(None, description="활성 상태")


class BulkRoleAssignmentRequest(BaseModel):
    assignments: List[RoleAssignmentRequest] = Field(..., description="일괄 할당 목록")


# Admin endpoints
@router.post("/users/{user_id}/roles", 
    summary="Assign role to user",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def assign_role_to_user(
    user_id: str,
    request: RoleAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자에게 역할 할당"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.assign_role_to_user(
            user_id=user_id,
            role_name=request.role_name,
            assigned_by=current_user.id,
            expires_at=request.expires_at
        )
        
        await db.commit()
        
        if success:
            return {"message": f"Role {request.role_name} assigned to user {user_id}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to assign role. Role may already be assigned."
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/users/{user_id}/roles/{role_name}",
    summary="Remove role from user",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def remove_role_from_user(
    user_id: str,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자로부터 역할 제거"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.remove_role_from_user(user_id, role_name)
        await db.commit()
        
        if success:
            return {"message": f"Role {role_name} removed from user {user_id}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found or not assigned to user"
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/users/{user_id}/permissions",
    summary="Assign direct permission to user",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def assign_permission_to_user(
    user_id: str,
    request: PermissionAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자에게 직접 권한 할당"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.assign_permission_to_user(
            user_id=user_id,
            permission_name=request.permission_name,
            granted_by=current_user.id,
            expires_at=request.expires_at
        )
        
        await db.commit()
        
        if success:
            return {"message": f"Permission {request.permission_name} assigned to user {user_id}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to assign permission. Permission may already be assigned."
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/users/{user_id}/permissions/{permission_name}",
    summary="Remove direct permission from user",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def remove_permission_from_user(
    user_id: str,
    permission_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자로부터 직접 권한 제거"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.remove_permission_from_user(user_id, permission_name)
        await db.commit()
        
        if success:
            return {"message": f"Permission {permission_name} removed from user {user_id}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found or not assigned to user"
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/users/{user_id}/teams",
    summary="Add user to team",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def add_user_to_team(
    user_id: str,
    request: TeamAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자를 팀에 추가"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.add_user_to_team(
            user_id=user_id,
            team_name=request.team_name,
            role_in_team=request.role_in_team,
            added_by=current_user.id
        )
        
        await db.commit()
        
        if success:
            return {"message": f"User {user_id} added to team {request.team_name}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to add user to team. User may already be a member."
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/users/{user_id}/teams/{team_name}",
    summary="Remove user from team",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def remove_user_from_team(
    user_id: str,
    team_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자를 팀에서 제거"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        success = await rbac_service.remove_user_from_team(user_id, team_name)
        await db.commit()
        
        if success:
            return {"message": f"User {user_id} removed from team {team_name}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in team"
            )
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.patch("/users/{user_id}",
    summary="Update user information and permissions",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자 정보 및 권한 업데이트"""
    service_factory = create_service_factory(db)
    user_service = service_factory.get_user_service()
    
    try:
        user = await user_service.update_user(
            user_id=user_id,
            full_name=request.full_name,
            role_names=request.roles,
            team_names=request.teams,
            updated_by=current_user.id
        )
        
        if request.is_active is not None:
            # Update active status separately
            user.is_active = request.is_active
        
        await db.commit()
        
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "roles": [role.name for role in user.roles],
            "teams": [team.name for team in user.teams],
            "is_active": user.is_active
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/roles/bulk-assign",
    summary="Bulk assign roles to multiple users",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def bulk_assign_roles(
    request: BulkRoleAssignmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """여러 사용자에게 역할 일괄 할당"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    
    try:
        assignments = [
            {
                "user_id": assignment.user_id,
                "role_name": assignment.role_name,
                "assigned_by": current_user.id,
                "expires_at": assignment.expires_at
            }
            for assignment in request.assignments
        ]
        
        results = await rbac_service.bulk_assign_roles(assignments)
        await db.commit()
        
        successful = sum(1 for v in results.values() if v)
        failed = len(results) - successful
        
        return {
            "message": f"Bulk assignment completed",
            "successful": successful,
            "failed": failed,
            "details": results
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/users/{user_id}/permissions",
    summary="Get all permissions for a user",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def get_user_permissions(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자의 모든 권한 조회 (직접 + 역할 + 팀)"""
    service_factory = create_service_factory(db)
    rbac_service = service_factory.get_rbac_service()
    auth_service = service_factory.get_auth_service()
    
    try:
        # Get permissions from RBAC service
        permissions = await rbac_service.get_user_permissions(user_id)
        
        # Get user roles and teams
        roles = await rbac_service.get_user_roles(user_id)
        teams = await rbac_service.get_user_teams(user_id)
        
        # Get cached permissions from auth service
        cached_permissions = await auth_service.get_user_permissions(user_id)
        
        return {
            "user_id": user_id,
            "permissions": sorted(list(permissions)),
            "cached_permissions": sorted(cached_permissions) if cached_permissions else [],
            "roles": [role.name for role in roles],
            "teams": [team.name for team in teams],
            "cache_status": "in_sync" if set(permissions) == set(cached_permissions or []) else "out_of_sync"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/cache/invalidate/{user_id}",
    summary="Invalidate user permissions cache",
    dependencies=[Depends(require_roles(["admin"]))]
)
async def invalidate_user_cache(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """사용자 권한 캐시 무효화"""
    service_factory = create_service_factory(db)
    auth_service = service_factory.get_auth_service()
    
    try:
        await auth_service.invalidate_user_permissions_cache(user_id)
        
        return {
            "message": f"Cache invalidated for user {user_id}",
            "user_id": user_id,
            "invalidated_by": current_user.id
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )