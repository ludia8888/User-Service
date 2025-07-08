"""
Authentication Dependencies for FastAPI
Provides real-time permission checking without relying on token payload
"""
from typing import Dict, Any, List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from services.service_factory import create_service_factory

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


class CurrentUser:
    """Current authenticated user with real-time permissions"""
    
    def __init__(self, user_data: Dict[str, Any]):
        self.user_id = user_data["user_id"]
        self.username = user_data["username"]
        self.email = user_data["email"]
        self.roles = user_data["roles"]
        self.permissions = user_data["permissions"]
        self.teams = user_data["teams"]
        self.status = user_data["status"]
        self.mfa_enabled = user_data["mfa_enabled"]
        self.session_id = user_data.get("session_id")
        self.token_issued_at = user_data.get("token_issued_at")
        self.token_expires_at = user_data.get("token_expires_at")
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        # Check exact match
        if permission in self.permissions:
            return True
        
        # Check wildcard permissions
        for user_perm in self.permissions:
            if self._match_permission(user_perm, permission):
                return True
        
        return False
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles
    
    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self.roles for role in roles)
    
    def is_in_team(self, team: str) -> bool:
        """Check if user is in a specific team"""
        return team in self.teams
    
    def is_in_any_team(self, teams: List[str]) -> bool:
        """Check if user is in any of the specified teams"""
        return any(team in self.teams for team in teams)
    
    def _match_permission(self, user_perm: str, required_perm: str) -> bool:
        """Match permission with wildcard support (resource:action:scope)"""
        user_parts = user_perm.split(':')
        required_parts = required_perm.split(':')
        
        if len(user_parts) != len(required_parts):
            return False
        
        for user_part, required_part in zip(user_parts, required_parts):
            if user_part != '*' and user_part != required_part:
                return False
        
        return True


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """
    Get current authenticated user with real-time permissions
    This replaces the old method that relied on token payload
    """
    try:
        service_factory = create_service_factory(db)
        auth_service = service_factory.get_auth_service()
        
        # Get real-time user data
        user_data = await auth_service.verify_token_and_get_user_data(token)
        
        return CurrentUser(user_data)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permissions(permissions: List[str]):
    """
    Dependency factory for requiring specific permissions
    
    Usage:
    @app.get("/protected")
    async def protected_endpoint(
        current_user: CurrentUser = Depends(require_permissions(["resource:read:*"]))
    ):
        pass
    """
    async def check_permissions(
        current_user: CurrentUser = Depends(get_current_user)
    ) -> CurrentUser:
        for permission in permissions:
            if not current_user.has_permission(permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied. Required: {permission}"
                )
        return current_user
    
    return check_permissions


def require_roles(roles: List[str]):
    """
    Dependency factory for requiring specific roles
    
    Usage:
    @app.get("/admin")
    async def admin_endpoint(
        current_user: CurrentUser = Depends(require_roles(["admin"]))
    ):
        pass
    """
    async def check_roles(
        current_user: CurrentUser = Depends(get_current_user)
    ) -> CurrentUser:
        if not current_user.has_any_role(roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(roles)}"
            )
        return current_user
    
    return check_roles


def require_teams(teams: List[str]):
    """
    Dependency factory for requiring team membership
    
    Usage:
    @app.get("/team-resource")
    async def team_endpoint(
        current_user: CurrentUser = Depends(require_teams(["backend", "platform"]))
    ):
        pass
    """
    async def check_teams(
        current_user: CurrentUser = Depends(get_current_user)
    ) -> CurrentUser:
        if not current_user.is_in_any_team(teams):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required teams: {', '.join(teams)}"
            )
        return current_user
    
    return check_teams


async def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[CurrentUser]:
    """
    Get current user if token is provided, otherwise return None
    Useful for endpoints that have optional authentication
    """
    if not token:
        return None
    
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None