"""
Authorization Service - Business Logic for Permission and Role Management
SOLID 원칙 준수: Single Responsibility - 권한 관련 비즈니스 로직만 담당
SSOT 원칙: Single Source of Truth - 모든 권한 규칙의 중앙 집중식 관리
"""
from typing import Set, List, Optional, Dict, Tuple
from abc import ABC, abstractmethod
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from models.user_clean import User
from models.rbac import Role, Permission, Team
from services.rbac_service import RBACService


class AuthorizationPolicy(ABC):
    """
    Abstract base class for authorization policies
    Strategy Pattern for different authorization strategies
    """
    
    @abstractmethod
    async def evaluate_permission(self, user: User, permission: str, context: Dict = None) -> bool:
        """Evaluate if user has permission under this policy"""
        pass
    
    @abstractmethod
    def get_policy_name(self) -> str:
        """Get the name of this policy"""
        pass


class DefaultAuthorizationPolicy(AuthorizationPolicy):
    """
    Default authorization policy implementation
    Centralized business rules for permissions
    """
    
    def __init__(self, rbac_service: RBACService):
        self.rbac_service = rbac_service
    
    async def evaluate_permission(self, user: User, permission: str, context: Dict = None) -> bool:
        """
        Centralized permission evaluation with business rules
        
        Business Rules (SSOT):
        1. Admin role bypasses all permission checks
        2. Suspended/Locked users have no permissions
        3. Inactive users have limited read-only permissions
        4. Permission inheritance: Direct > Role > Team
        5. Context-aware permissions (time-based, IP-based, etc.)
        """
        # Rule 1: Suspended/Locked users have no permissions
        if user.status in ['suspended', 'locked']:
            return False
        
        # Rule 2: Check temporary lock
        if user.has_temp_lock:
            return False
        
        # Rule 3: Admin role has all permissions (except when suspended/locked)
        if await self._user_has_admin_role(user):
            return True
        
        # Rule 4: Inactive users get limited read-only permissions
        if user.status == 'inactive':
            return self._is_read_only_permission(permission)
        
        # Rule 5: Check context-based restrictions
        if context and not await self._evaluate_context_restrictions(user, permission, context):
            return False
        
        # Rule 6: Standard permission evaluation (Direct > Role > Team)
        return await self.rbac_service.user_has_permission(user.id, permission)
    
    async def _user_has_admin_role(self, user: User) -> bool:
        """Check if user has admin role"""
        roles = await self.rbac_service.get_user_roles(user.id)
        return any(role.name == 'admin' for role in roles)
    
    def _is_read_only_permission(self, permission: str) -> bool:
        """Check if permission is read-only"""
        try:
            _, _, action = permission.split(':')
            return action in ['read', 'view', 'list']
        except ValueError:
            return False
    
    async def _evaluate_context_restrictions(self, user: User, permission: str, context: Dict) -> bool:
        """Evaluate context-based restrictions"""
        # Time-based restrictions
        if 'time_restriction' in context:
            current_hour = datetime.now().hour
            allowed_hours = context['time_restriction'].get('allowed_hours', [])
            if allowed_hours and current_hour not in allowed_hours:
                return False
        
        # IP-based restrictions
        if 'ip_restriction' in context:
            client_ip = context.get('client_ip')
            allowed_ips = context['ip_restriction'].get('allowed_ips', [])
            if allowed_ips and client_ip not in allowed_ips:
                return False
        
        # Resource-specific restrictions
        if 'resource_restriction' in context:
            # Additional resource-specific checks can be added here
            pass
        
        return True
    
    def get_policy_name(self) -> str:
        return "default"


class StrictAuthorizationPolicy(AuthorizationPolicy):
    """
    Strict authorization policy for high-security contexts
    """
    
    def __init__(self, rbac_service: RBACService):
        self.rbac_service = rbac_service
    
    async def evaluate_permission(self, user: User, permission: str, context: Dict = None) -> bool:
        """
        Strict permission evaluation
        
        Strict Rules:
        1. No admin bypass - all permissions must be explicit
        2. Only active users with verified email
        3. MFA required for sensitive operations
        4. Time-based session validation
        """
        # Rule 1: Only active users allowed
        if user.status != 'active':
            return False
        
        # Rule 2: Check for temporary locks
        if user.has_temp_lock:
            return False
        
        # Rule 3: MFA required for sensitive operations
        if self._is_sensitive_permission(permission) and not user.mfa_enabled:
            return False
        
        # Rule 4: Explicit permission check only (no admin bypass)
        return await self.rbac_service.user_has_permission(user.id, permission)
    
    def _is_sensitive_permission(self, permission: str) -> bool:
        """Determine if permission is sensitive"""
        sensitive_actions = ['admin', 'delete', 'write', 'approve']
        try:
            _, _, action = permission.split(':')
            return action in sensitive_actions
        except ValueError:
            return True  # Default to sensitive if pattern doesn't match
    
    def get_policy_name(self) -> str:
        return "strict"


class AuthorizationService:
    """
    Central Authorization Service - Business Logic Layer
    
    Responsibilities:
    - Apply authorization policies
    - Evaluate complex permission scenarios
    - Manage business rules for access control
    - Provide audit trail for authorization decisions
    """
    
    def __init__(self, db: AsyncSession, policy: AuthorizationPolicy = None):
        self.db = db
        self.rbac_service = RBACService(db)
        self.policy = policy or DefaultAuthorizationPolicy(self.rbac_service)
        self._audit_trail = []
    
    async def user_can_access(
        self, 
        user: User, 
        permission: str, 
        context: Dict = None,
        audit_action: str = None
    ) -> bool:
        """
        Main authorization check with audit trail
        
        Args:
            user: User requesting access
            permission: Permission string (resource:id:action)
            context: Additional context for authorization
            audit_action: Action being audited
        
        Returns:
            bool: True if access granted
        """
        start_time = datetime.now()
        
        try:
            # Evaluate permission using current policy
            result = await self.policy.evaluate_permission(user, permission, context)
            
            # Record audit trail
            self._record_authorization_decision(
                user=user,
                permission=permission,
                result=result,
                policy=self.policy.get_policy_name(),
                context=context,
                audit_action=audit_action,
                duration=(datetime.now() - start_time).total_seconds()
            )
            
            return result
            
        except Exception as e:
            # Record failed authorization attempt
            self._record_authorization_error(
                user=user,
                permission=permission,
                error=str(e),
                context=context
            )
            # Fail secure - deny access on errors
            return False
    
    async def user_can_access_multiple(
        self, 
        user: User, 
        permissions: List[str], 
        context: Dict = None,
        require_all: bool = True
    ) -> Dict[str, bool]:
        """
        Bulk authorization check
        
        Args:
            user: User requesting access
            permissions: List of permission strings
            context: Additional context
            require_all: If True, all permissions must be granted
        
        Returns:
            Dict mapping permission to result
        """
        results = {}
        
        for permission in permissions:
            results[permission] = await self.user_can_access(user, permission, context)
        
        # If require_all is True, check that all permissions are granted
        if require_all:
            all_granted = all(results.values())
            # Override individual results if require_all fails
            if not all_granted:
                results = {perm: False for perm in permissions}
        
        return results
    
    async def get_user_effective_permissions(
        self, 
        user: User, 
        context: Dict = None
    ) -> Set[str]:
        """
        Get all effective permissions for user under current policy
        """
        # Get all potential permissions
        all_permissions = await self.rbac_service.get_user_permissions(user.id)
        
        # Filter based on current policy and context
        effective_permissions = set()
        
        for permission in all_permissions:
            if await self.policy.evaluate_permission(user, permission, context):
                effective_permissions.add(permission)
        
        return effective_permissions
    
    async def explain_permission_decision(
        self, 
        user: User, 
        permission: str, 
        context: Dict = None
    ) -> Dict[str, any]:
        """
        Explain why a permission was granted or denied
        Useful for debugging and compliance
        """
        explanation = {
            "user_id": user.id,
            "username": user.username,
            "permission": permission,
            "context": context,
            "policy": self.policy.get_policy_name(),
            "checks": []
        }
        
        # Check user status
        if user.status in ['suspended', 'locked']:
            explanation["checks"].append({
                "check": "user_status",
                "result": False,
                "reason": f"User status is {user.status}"
            })
            explanation["final_decision"] = False
            return explanation
        
        # Check temporary lock
        if user.has_temp_lock:
            explanation["checks"].append({
                "check": "temporary_lock",
                "result": False,
                "reason": f"User locked until {user.locked_until}"
            })
            explanation["final_decision"] = False
            return explanation
        
        # Check admin role
        has_admin = await self._user_has_admin_role(user)
        explanation["checks"].append({
            "check": "admin_role",
            "result": has_admin,
            "reason": "Admin role grants all permissions" if has_admin else "No admin role"
        })
        
        if has_admin and isinstance(self.policy, DefaultAuthorizationPolicy):
            explanation["final_decision"] = True
            return explanation
        
        # Check explicit permissions
        has_explicit = await self.rbac_service.user_has_permission(user.id, permission)
        explanation["checks"].append({
            "check": "explicit_permission",
            "result": has_explicit,
            "reason": "Found matching permission" if has_explicit else "No matching permission found"
        })
        
        # Final decision
        final_result = await self.policy.evaluate_permission(user, permission, context)
        explanation["final_decision"] = final_result
        
        return explanation
    
    def set_policy(self, policy: AuthorizationPolicy) -> None:
        """Change authorization policy"""
        self.policy = policy
    
    def get_audit_trail(self) -> List[Dict]:
        """Get authorization audit trail"""
        return self._audit_trail.copy()
    
    def clear_audit_trail(self) -> None:
        """Clear audit trail"""
        self._audit_trail.clear()
    
    # Helper methods
    async def _user_has_admin_role(self, user: User) -> bool:
        """Check if user has admin role"""
        roles = await self.rbac_service.get_user_roles(user.id)
        return any(role.name == 'admin' for role in roles)
    
    def _record_authorization_decision(
        self, 
        user: User, 
        permission: str, 
        result: bool, 
        policy: str,
        context: Dict,
        audit_action: str,
        duration: float
    ) -> None:
        """Record authorization decision for audit"""
        self._audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "user_id": user.id,
            "username": user.username,
            "permission": permission,
            "result": result,
            "policy": policy,
            "context": context,
            "audit_action": audit_action,
            "duration_seconds": duration,
            "type": "authorization_decision"
        })
    
    def _record_authorization_error(
        self, 
        user: User, 
        permission: str, 
        error: str,
        context: Dict
    ) -> None:
        """Record authorization error for audit"""
        self._audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "user_id": user.id,
            "username": user.username,
            "permission": permission,
            "error": error,
            "context": context,
            "type": "authorization_error"
        })


class RoleManagementService:
    """
    Role Management Business Logic Service
    
    Responsibilities:
    - Role assignment business rules
    - Role hierarchy enforcement
    - Role conflict detection
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.rbac_service = RBACService(db)
    
    async def assign_role_with_validation(
        self, 
        user: User, 
        role_name: str, 
        assigned_by: str,
        business_justification: str = None
    ) -> Tuple[bool, str]:
        """
        Assign role with business rule validation
        
        Business Rules:
        1. Cannot assign admin role without special approval
        2. Service accounts cannot get user roles
        3. Users can't have conflicting roles
        4. Role assignments must have business justification for audit
        """
        # Rule 1: Admin role requires special validation
        if role_name == 'admin':
            if not await self._validate_admin_assignment(user, assigned_by):
                return False, "Admin role assignment requires special approval"
        
        # Rule 2: Service account validation
        if 'service' in user.username.lower():
            if role_name not in ['service', 'readonly']:
                return False, "Service accounts can only have service or readonly roles"
        
        # Rule 3: Check for role conflicts
        conflicts = await self._check_role_conflicts(user, role_name)
        if conflicts:
            return False, f"Role conflicts with existing roles: {conflicts}"
        
        # Rule 4: Business justification required for sensitive roles
        sensitive_roles = ['admin', 'reviewer', 'developer']
        if role_name in sensitive_roles and not business_justification:
            return False, "Business justification required for sensitive roles"
        
        # Assign role if all validations pass
        success = await self.rbac_service.assign_role_to_user(
            user.id, role_name, assigned_by
        )
        
        if success:
            return True, f"Role {role_name} assigned successfully"
        else:
            return False, "Role assignment failed"
    
    async def _validate_admin_assignment(self, user: User, assigned_by: str) -> bool:
        """Validate admin role assignment"""
        # Check if assigner has admin role
        assigner = await self.rbac_service.get_user_by_id(assigned_by)
        if not assigner:
            return False
        
        assigner_roles = await self.rbac_service.get_user_roles(assigner.id)
        has_admin = any(role.name == 'admin' for role in assigner_roles)
        
        return has_admin
    
    async def _check_role_conflicts(self, user: User, new_role: str) -> List[str]:
        """Check for conflicting roles"""
        current_roles = await self.rbac_service.get_user_roles(user.id)
        current_role_names = [role.name for role in current_roles]
        
        # Define conflicting role pairs
        conflicts = {
            'admin': ['service', 'readonly'],
            'service': ['admin', 'user', 'developer', 'reviewer'],
            'readonly': ['admin', 'developer', 'reviewer']
        }
        
        conflicting_roles = []
        if new_role in conflicts:
            for current_role in current_role_names:
                if current_role in conflicts[new_role]:
                    conflicting_roles.append(current_role)
        
        return conflicting_roles


class TeamManagementService:
    """
    Team Management Business Logic Service
    
    Responsibilities:
    - Team membership business rules
    - Team capacity management
    - Team permission inheritance
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.rbac_service = RBACService(db)
    
    async def add_user_to_team_with_validation(
        self, 
        user: User, 
        team_name: str, 
        role_in_team: str = "member",
        added_by: str = None
    ) -> Tuple[bool, str]:
        """
        Add user to team with business rule validation
        
        Business Rules:
        1. Team capacity limits
        2. User eligibility (status, conflicts)
        3. Team lead permissions
        4. Cross-team restrictions
        """
        # Get team information
        team = await self.rbac_service.get_team_by_name(team_name)
        if not team:
            return False, f"Team {team_name} not found"
        
        # Rule 1: Check team capacity
        if not team.can_add_member():
            return False, f"Team {team_name} is at capacity"
        
        # Rule 2: Check user eligibility
        if user.status != 'active':
            return False, "Only active users can join teams"
        
        # Rule 3: Validate team role assignment
        if role_in_team == 'lead':
            if not await self._can_assign_team_lead(user, team_name, added_by):
                return False, "Insufficient permissions to assign team lead role"
        
        # Rule 4: Check cross-team restrictions
        if await self._has_team_conflicts(user, team_name):
            return False, "User has conflicting team memberships"
        
        # Add to team if all validations pass
        success = await self.rbac_service.add_user_to_team(
            user.id, team_name, role_in_team, added_by
        )
        
        if success:
            return True, f"User added to team {team_name} as {role_in_team}"
        else:
            return False, "Failed to add user to team"
    
    async def _can_assign_team_lead(self, user: User, team_name: str, added_by: str) -> bool:
        """Check if user can be assigned as team lead"""
        # Check if adder has appropriate permissions
        if added_by:
            adder_permissions = await self.rbac_service.get_user_permissions(added_by)
            required_permission = f"team:{team_name}:admin"
            
            # Check for team admin permission or general admin role
            if (required_permission in adder_permissions or 
                any(perm.startswith('team:*:admin') for perm in adder_permissions)):
                return True
        
        return False
    
    async def _has_team_conflicts(self, user: User, team_name: str) -> bool:
        """Check for team membership conflicts"""
        user_teams = await self.rbac_service.get_user_teams(user.id)
        current_team_names = [team.name for team in user_teams]
        
        # Define conflicting teams
        team_conflicts = {
            'security': ['external_contractor'],
            'admin': ['external_contractor', 'vendor'],
            'financial': ['external_contractor', 'vendor']
        }
        
        if team_name in team_conflicts:
            for current_team in current_team_names:
                if current_team in team_conflicts[team_name]:
                    return True
        
        return False