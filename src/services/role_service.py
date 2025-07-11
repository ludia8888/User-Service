"""
Role-based Access Control (RBAC) Service
Handles role management and permission assignment
This is a compatibility layer that delegates to the database-backed RBACService
"""
from typing import List, Dict, Set, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from core.config import settings
from services.rbac_service import RBACService
import logging

logger = logging.getLogger(__name__)


class RoleService:
    """
    Service for managing roles and permissions.
    
    This service acts as a compatibility layer between the old config-based
    role management and the new database-backed RBAC system. It provides
    synchronous methods for backward compatibility while delegating to
    the async RBACService when possible.
    
    For new code, consider using RBACService directly for better performance
    and full async support.
    """
    """Service for managing roles and permissions"""
    
    def __init__(self, db: Optional[AsyncSession] = None):
        self.allowed_roles = set(settings.ALLOWED_ROLES)
        self.default_role_permissions = settings.DEFAULT_ROLE_PERMISSIONS
        self.default_role_teams = settings.DEFAULT_ROLE_TEAMS
        self.default_new_user_role = settings.DEFAULT_NEW_USER_ROLE
        self.db = db
        self.rbac_service = RBACService(db) if db else None
    
    def is_valid_role(self, role: str) -> bool:
        """Check if a role is valid"""
        return role in self.allowed_roles
    
    def validate_roles(self, roles: List[str]) -> List[str]:
        """Validate and return valid roles"""
        if not roles:
            return [self.default_new_user_role]
        
        valid_roles = []
        for role in roles:
            if self.is_valid_role(role):
                valid_roles.append(role)
        
        # If no valid roles found, use default
        if not valid_roles:
            valid_roles = [self.default_new_user_role]
        
        return valid_roles
    
    def get_permissions_for_roles(self, roles: List[str]) -> List[str]:
        """Get all permissions for the given roles"""
        # If we have a database connection, use the RBACService
        if self.rbac_service:
            # This method is synchronous but RBACService is async
            # For backward compatibility, we'll use the default config
            # In production, consider making this async or using a different pattern
            pass
        
        # Fallback to config-based permissions
        permissions = set()
        
        for role in roles:
            if role in self.default_role_permissions:
                permissions.update(self.default_role_permissions[role])
        
        return list(permissions)
    
    def get_teams_for_roles(self, roles: List[str]) -> List[str]:
        """Get all teams for the given roles"""
        teams = set()
        
        for role in roles:
            if role in self.default_role_teams:
                teams.update(self.default_role_teams[role])
        
        return list(teams)
    
    def get_default_user_config(self) -> Dict[str, List[str]]:
        """Get default configuration for new users"""
        default_roles = [self.default_new_user_role]
        
        return {
            "roles": default_roles,
            "permissions": self.get_permissions_for_roles(default_roles),
            "teams": self.get_teams_for_roles(default_roles)
        }
    
    def get_user_config_for_roles(self, roles: List[str]) -> Dict[str, List[str]]:
        """Get configuration for a user with specific roles"""
        validated_roles = self.validate_roles(roles)
        
        return {
            "roles": validated_roles,
            "permissions": self.get_permissions_for_roles(validated_roles),
            "teams": self.get_teams_for_roles(validated_roles)
        }
    
    def add_role_to_user_config(self, current_config: Dict[str, List[str]], new_role: str) -> Dict[str, List[str]]:
        """Add a new role to existing user configuration"""
        if not self.is_valid_role(new_role):
            raise ValueError(f"Invalid role: {new_role}")
        
        current_roles = current_config.get("roles", [])
        if new_role not in current_roles:
            current_roles.append(new_role)
        
        return self.get_user_config_for_roles(current_roles)
    
    def remove_role_from_user_config(self, current_config: Dict[str, List[str]], role_to_remove: str) -> Dict[str, List[str]]:
        """Remove a role from existing user configuration"""
        current_roles = current_config.get("roles", [])
        if role_to_remove in current_roles:
            current_roles.remove(role_to_remove)
        
        # Ensure at least one role remains
        if not current_roles:
            current_roles = [self.default_new_user_role]
        
        return self.get_user_config_for_roles(current_roles)
    
    def get_all_available_roles(self) -> List[str]:
        """Get all available roles"""
        return list(self.allowed_roles)
    
    def get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a specific role"""
        if not self.is_valid_role(role):
            raise ValueError(f"Invalid role: {role}")
        
        return self.default_role_permissions.get(role, [])
    
    def get_role_teams(self, role: str) -> List[str]:
        """Get teams for a specific role"""
        if not self.is_valid_role(role):
            raise ValueError(f"Invalid role: {role}")
        
        return self.default_role_teams.get(role, [])
    
    def merge_permissions(self, *permission_lists: List[str]) -> List[str]:
        """Merge multiple permission lists, removing duplicates"""
        merged = set()
        for perm_list in permission_lists:
            merged.update(perm_list)
        return list(merged)
    
    def merge_teams(self, *team_lists: List[str]) -> List[str]:
        """Merge multiple team lists, removing duplicates"""
        merged = set()
        for team_list in team_lists:
            merged.update(team_list)
        return list(merged)
    
    # Async methods for database operations
    async def get_user_roles_async(self, user_id: str) -> List[str]:
        """Get user roles from database"""
        if not self.rbac_service:
            raise RuntimeError("Database connection required for async operations")
        
        roles = await self.rbac_service.get_user_roles(user_id)
        return [role.name for role in roles]
    
    async def get_user_permissions_async(self, user_id: str) -> List[str]:
        """Get all user permissions from database"""
        if not self.rbac_service:
            raise RuntimeError("Database connection required for async operations")
        
        permissions = await self.rbac_service.get_user_permissions(user_id)
        return list(permissions)
    
    async def assign_role_async(self, user_id: str, role_name: str, assigned_by: str = None) -> bool:
        """Assign role to user in database"""
        if not self.rbac_service:
            raise RuntimeError("Database connection required for async operations")
        
        if not self.is_valid_role(role_name):
            raise ValueError(f"Invalid role: {role_name}")
        
        return await self.rbac_service.assign_role_to_user(user_id, role_name, assigned_by)
    
    async def remove_role_async(self, user_id: str, role_name: str) -> bool:
        """Remove role from user in database"""
        if not self.rbac_service:
            raise RuntimeError("Database connection required for async operations")
        
        return await self.rbac_service.remove_role_from_user(user_id, role_name)
    
    async def sync_user_roles_with_config(self, user_id: str, config_roles: List[str]) -> None:
        """Sync user roles from config to database"""
        if not self.rbac_service:
            logger.warning("No database connection, cannot sync roles")
            return
        
        try:
            # Get current roles from database
            current_roles = await self.get_user_roles_async(user_id)
            
            # Validate config roles
            validated_roles = self.validate_roles(config_roles)
            
            # Add new roles
            for role in validated_roles:
                if role not in current_roles:
                    await self.assign_role_async(user_id, role, "system")
            
            # Remove roles not in config (optional, based on business logic)
            # for role in current_roles:
            #     if role not in validated_roles:
            #         await self.remove_role_async(user_id, role)
            
            logger.info(f"Synced roles for user {user_id}: {validated_roles}")
        except Exception as e:
            logger.error(f"Failed to sync roles for user {user_id}: {str(e)}")
    
    def validate_configuration(self) -> Dict[str, bool]:
        """Validate the role configuration for completeness and consistency"""
        validation_results = {
            "has_default_role": self.default_new_user_role in self.allowed_roles,
            "all_roles_have_permissions": True,
            "all_roles_have_teams": True,
            "no_empty_permissions": True,
            "no_empty_teams": True,
            "has_database_connection": self.rbac_service is not None
        }
        
        for role in self.allowed_roles:
            if role not in self.default_role_permissions:
                validation_results["all_roles_have_permissions"] = False
            elif not self.default_role_permissions[role]:
                validation_results["no_empty_permissions"] = False
                
            if role not in self.default_role_teams:
                validation_results["all_roles_have_teams"] = False
            elif not self.default_role_teams[role]:
                validation_results["no_empty_teams"] = False
        
        return validation_results
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of the current role configuration"""
        validation = self.validate_configuration()
        
        return {
            "default_new_user_role": self.default_new_user_role,
            "total_roles": len(self.allowed_roles),
            "available_roles": list(self.allowed_roles),
            "validation_status": validation,
            "is_valid": all(validation.values()),
            "mode": "database" if self.rbac_service else "config"
        }
    
    @classmethod
    def create_with_db(cls, db: AsyncSession) -> 'RoleService':
        """Factory method to create RoleService with database connection"""
        return cls(db=db)
    
    @classmethod
    def create_config_only(cls) -> 'RoleService':
        """Factory method to create RoleService without database (config only)"""
        return cls(db=None)