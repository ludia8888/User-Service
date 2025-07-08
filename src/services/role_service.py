"""
Role-based Access Control (RBAC) Service
Handles role management and permission assignment
"""
from typing import List, Dict, Set, Optional
from core.config import settings


class RoleService:
    """Service for managing roles and permissions"""
    
    def __init__(self):
        self.allowed_roles = set(settings.ALLOWED_ROLES)
        self.default_role_permissions = settings.DEFAULT_ROLE_PERMISSIONS
        self.default_role_teams = settings.DEFAULT_ROLE_TEAMS
        self.default_new_user_role = settings.DEFAULT_NEW_USER_ROLE
    
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
    
    def validate_configuration(self) -> Dict[str, bool]:
        """Validate the role configuration for completeness and consistency"""
        validation_results = {
            "has_default_role": self.default_new_user_role in self.allowed_roles,
            "all_roles_have_permissions": True,
            "all_roles_have_teams": True,
            "no_empty_permissions": True,
            "no_empty_teams": True
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
    
    def get_configuration_summary(self) -> Dict[str, any]:
        """Get a summary of the current role configuration"""
        validation = self.validate_configuration()
        
        return {
            "default_new_user_role": self.default_new_user_role,
            "total_roles": len(self.allowed_roles),
            "available_roles": list(self.allowed_roles),
            "validation_status": validation,
            "is_valid": all(validation.values())
        }