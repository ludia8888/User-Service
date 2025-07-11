"""
RBAC Service - Optimized relational queries for roles, permissions, and teams
"""
from datetime import datetime, timezone
from typing import List, Optional, Set, Dict, Tuple
from sqlalchemy import select, and_, or_, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from models.rbac import Role, Permission, Team, user_roles, user_permissions, user_teams, role_permissions, team_permissions
from models.user import User


class RBACService:
    """Optimized RBAC service with proper relational queries"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self._auth_service = None
    
    @property
    def auth_service(self):
        """Lazy load auth service to avoid circular imports"""
        if self._auth_service is None:
            from services.auth_service import AuthService
            self._auth_service = AuthService(self.db)
        return self._auth_service
    
    async def _invalidate_user_cache(self, user_id: str):
        """Invalidate user permissions cache"""
        try:
            await self.auth_service.invalidate_user_permissions_cache(user_id)
        except Exception:
            # Cache invalidation failure shouldn't break the operation
            pass
    
    # Role Management
    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get role by name with optimized query"""
        result = await self.db.execute(
            select(Role)
            .where(Role.name == name)
        )
        return result.scalar_one_or_none()
    
    async def get_roles_by_names(self, names: List[str]) -> List[Role]:
        """Get multiple roles by names in single query"""
        result = await self.db.execute(
            select(Role)
            .where(Role.name.in_(names))
        )
        return result.scalars().all()
    
    async def get_user_roles(self, user_id: str) -> List[Role]:
        """Get all roles for a user with single query"""
        result = await self.db.execute(
            select(Role)
            .join(user_roles)
            .where(user_roles.c.user_id == user_id)
            .order_by(Role.priority.desc())
        )
        return result.scalars().all()
    
    async def assign_role_to_user(self, user_id: str, role_name: str, assigned_by: str = None, expires_at: datetime = None) -> bool:
        """Assign role to user with audit trail"""
        role = await self.get_role_by_name(role_name)
        if not role:
            return False
        
        # Check if already assigned
        existing = await self.db.execute(
            select(user_roles)
            .where(
                and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role.id
                )
            )
        )
        
        if existing.first():
            return False  # Already assigned
        
        # Insert new assignment (only include columns that exist in schema)
        await self.db.execute(
            user_roles.insert().values(
                user_id=user_id,
                role_id=role.id,
                expires_at=expires_at,
                assigned_at=datetime.now(timezone.utc)
            )
        )
        
        # Invalidate cache after successful assignment
        await self._invalidate_user_cache(user_id)
        
        return True
    
    async def remove_role_from_user(self, user_id: str, role_name: str) -> bool:
        """Remove role from user"""
        role = await self.get_role_by_name(role_name)
        if not role:
            return False
        
        result = await self.db.execute(
            user_roles.delete().where(
                and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role.id
                )
            )
        )
        
        if result.rowcount > 0:
            # Invalidate cache after successful removal
            await self._invalidate_user_cache(user_id)
            return True
        
        return False
    
    async def get_users_with_role(self, role_name: str) -> List[User]:
        """Get all users with specific role - optimized query"""
        result = await self.db.execute(
            select(User)
            .join(user_roles)
            .join(Role)
            .where(Role.name == role_name)
            .options(selectinload(User.roles))
        )
        return result.scalars().all()
    
    # Permission Management
    async def get_permission_by_name(self, name: str) -> Optional[Permission]:
        """Get permission by name"""
        result = await self.db.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()
    
    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for user (direct + role + team) with optimized query"""
        # Single query to get all permissions from all sources
        query = text("""
            SELECT DISTINCT p.name
            FROM permissions p
            WHERE p.id IN (
                -- Direct user permissions
                SELECT up.permission_id 
                FROM user_permissions up 
                WHERE up.user_id = :user_id
                  AND (up.expires_at IS NULL OR up.expires_at > CURRENT_TIMESTAMP)
                
                UNION
                
                -- Permissions from roles
                SELECT rp.permission_id 
                FROM role_permissions rp
                JOIN user_roles ur ON ur.role_id = rp.role_id
                WHERE ur.user_id = :user_id
                  AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                
                UNION
                
                -- Permissions from teams
                SELECT tp.permission_id
                FROM team_permissions tp
                JOIN user_teams ut ON ut.team_id = tp.team_id
                WHERE ut.user_id = :user_id
            )
        """)
        
        result = await self.db.execute(query, {"user_id": user_id})
        return {row[0] for row in result}
    
    async def user_has_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has specific permission - optimized single query"""
        # First check for admin role (admin has all permissions)
        admin_check = await self.db.execute(
            select(func.count())
            .select_from(user_roles.join(Role))
            .where(
                and_(
                    user_roles.c.user_id == user_id,
                    Role.name == 'admin',
                    or_(
                        user_roles.c.expires_at.is_(None),
                        user_roles.c.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
        )
        
        if admin_check.scalar() > 0:
            return True
        
        # Parse permission pattern
        try:
            resource_type, resource_id, permission_type = permission.split(":")
        except ValueError:
            return False
        
        # Check for permission with pattern matching
        query = text("""
            SELECT COUNT(*) > 0
            FROM permissions p
            WHERE p.id IN (
                -- Direct user permissions
                SELECT up.permission_id 
                FROM user_permissions up 
                WHERE up.user_id = :user_id
                  AND (up.expires_at IS NULL OR up.expires_at > CURRENT_TIMESTAMP)
                
                UNION
                
                -- Permissions from roles
                SELECT rp.permission_id 
                FROM role_permissions rp
                JOIN user_roles ur ON ur.role_id = rp.role_id
                WHERE ur.user_id = :user_id
                  AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                
                UNION
                
                -- Permissions from teams
                SELECT tp.permission_id
                FROM team_permissions tp
                JOIN user_teams ut ON ut.team_id = tp.team_id
                WHERE ut.user_id = :user_id
            )
            AND (
                -- Exact match
                p.name = :permission
                OR
                -- Pattern matching for wildcards
                (p.resource_type = :resource_type OR p.resource_type = '*')
                AND (p.resource_id = :resource_id OR p.resource_id = '*')
                AND (p.permission_type = :permission_type OR p.permission_type = '*')
            )
        """)
        
        result = await self.db.execute(query, {
            "user_id": user_id,
            "permission": permission,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "permission_type": permission_type
        })
        
        return result.scalar()
    
    async def assign_permission_to_user(self, user_id: str, permission_name: str, granted_by: str = None, expires_at: datetime = None) -> bool:
        """Assign direct permission to user"""
        permission = await self.get_permission_by_name(permission_name)
        if not permission:
            return False
        
        # Check if already assigned
        existing = await self.db.execute(
            select(user_permissions)
            .where(
                and_(
                    user_permissions.c.user_id == user_id,
                    user_permissions.c.permission_id == permission.id
                )
            )
        )
        
        if existing.first():
            return False
        
        # Insert new assignment
        await self.db.execute(
            user_permissions.insert().values(
                user_id=user_id,
                permission_id=permission.id,
                granted_by=granted_by,
                expires_at=expires_at,
                granted_at=datetime.now(timezone.utc)
            )
        )
        
        # Invalidate cache after successful assignment
        await self._invalidate_user_cache(user_id)
        
        return True
    
    async def remove_permission_from_user(self, user_id: str, permission_name: str) -> bool:
        """Remove direct permission from user"""
        permission = await self.get_permission_by_name(permission_name)
        if not permission:
            return False
        
        result = await self.db.execute(
            user_permissions.delete().where(
                and_(
                    user_permissions.c.user_id == user_id,
                    user_permissions.c.permission_id == permission.id
                )
            )
        )
        
        if result.rowcount > 0:
            # Invalidate cache after successful removal
            await self._invalidate_user_cache(user_id)
            return True
        
        return False
    
    # Team Management
    async def get_team_by_name(self, name: str) -> Optional[Team]:
        """Get team by name with members"""
        result = await self.db.execute(
            select(Team)
            .options(selectinload(Team.members))
            .where(Team.name == name)
        )
        return result.scalar_one_or_none()
    
    async def get_user_teams(self, user_id: str) -> List[Team]:
        """Get all teams for a user"""
        result = await self.db.execute(
            select(Team)
            .join(user_teams)
            .where(user_teams.c.user_id == user_id)
            .options(selectinload(Team.permissions))
        )
        return result.scalars().all()
    
    async def add_user_to_team(self, user_id: str, team_name: str, role_in_team: str = "member", added_by: str = None) -> bool:
        """Add user to team"""
        team = await self.get_team_by_name(team_name)
        if not team:
            return False
        
        # Check if team can accept new members
        if not team.can_add_member():
            return False
        
        # Check if already a member
        existing = await self.db.execute(
            select(user_teams)
            .where(
                and_(
                    user_teams.c.user_id == user_id,
                    user_teams.c.team_id == team.id
                )
            )
        )
        
        if existing.first():
            return False
        
        # Add to team
        await self.db.execute(
            user_teams.insert().values(
                user_id=user_id,
                team_id=team.id,
                role_in_team=role_in_team,
                added_by=added_by,
                joined_at=datetime.now(timezone.utc)
            )
        )
        
        # Invalidate cache after successful team assignment
        await self._invalidate_user_cache(user_id)
        
        return True
    
    async def remove_user_from_team(self, user_id: str, team_name: str) -> bool:
        """Remove user from team"""
        team = await self.get_team_by_name(team_name)
        if not team:
            return False
        
        result = await self.db.execute(
            user_teams.delete().where(
                and_(
                    user_teams.c.user_id == user_id,
                    user_teams.c.team_id == team.id
                )
            )
        )
        
        if result.rowcount > 0:
            # Invalidate cache after successful removal
            await self._invalidate_user_cache(user_id)
            return True
        
        return False
    
    async def get_team_members(self, team_name: str) -> List[Tuple[User, str]]:
        """Get team members with their roles in team"""
        result = await self.db.execute(
            select(User, user_teams.c.role_in_team)
            .join(user_teams)
            .join(Team)
            .where(Team.name == team_name)
        )
        return [(user, role) for user, role in result]
    
    # Bulk Operations for Performance
    async def get_users_with_permissions(self, permission_patterns: List[str]) -> Dict[str, List[User]]:
        """Get users who have any of the specified permissions - bulk operation"""
        results = {}
        
        for pattern in permission_patterns:
            try:
                resource_type, resource_id, permission_type = pattern.split(":")
            except ValueError:
                continue
            
            query = text("""
                SELECT DISTINCT u.*
                FROM users u
                WHERE u.id IN (
                    -- Users with admin role
                    SELECT ur.user_id 
                    FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE r.name = 'admin'
                      AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                    
                    UNION
                    
                    -- Users with direct permission
                    SELECT up.user_id
                    FROM user_permissions up
                    JOIN permissions p ON p.id = up.permission_id
                    WHERE (p.name = :pattern OR
                           ((p.resource_type = :resource_type OR p.resource_type = '*') AND
                            (p.resource_id = :resource_id OR p.resource_id = '*') AND
                            (p.permission_type = :permission_type OR p.permission_type = '*')))
                      AND (up.expires_at IS NULL OR up.expires_at > CURRENT_TIMESTAMP)
                    
                    UNION
                    
                    -- Users with permission from roles
                    SELECT ur.user_id
                    FROM user_roles ur
                    JOIN role_permissions rp ON rp.role_id = ur.role_id
                    JOIN permissions p ON p.id = rp.permission_id
                    WHERE (p.name = :pattern OR
                           ((p.resource_type = :resource_type OR p.resource_type = '*') AND
                            (p.resource_id = :resource_id OR p.resource_id = '*') AND
                            (p.permission_type = :permission_type OR p.permission_type = '*')))
                      AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                    
                    UNION
                    
                    -- Users with permission from teams
                    SELECT ut.user_id
                    FROM user_teams ut
                    JOIN team_permissions tp ON tp.team_id = ut.team_id
                    JOIN permissions p ON p.id = tp.permission_id
                    WHERE (p.name = :pattern OR
                           ((p.resource_type = :resource_type OR p.resource_type = '*') AND
                            (p.resource_id = :resource_id OR p.resource_id = '*') AND
                            (p.permission_type = :permission_type OR p.permission_type = '*')))
                )
            """)
            
            result = await self.db.execute(query, {
                "pattern": pattern,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "permission_type": permission_type
            })
            
            users = []
            for row in result:
                user = User(**row._asdict())
                users.append(user)
            
            results[pattern] = users
        
        return results
    
    async def bulk_assign_roles(self, assignments: List[Dict]) -> Dict[str, bool]:
        """Bulk assign roles to multiple users"""
        results = {}
        
        for assignment in assignments:
            user_id = assignment.get("user_id")
            role_name = assignment.get("role_name")
            assigned_by = assignment.get("assigned_by")
            expires_at = assignment.get("expires_at")
            
            success = await self.assign_role_to_user(user_id, role_name, assigned_by, expires_at)
            results[f"{user_id}:{role_name}"] = success
        
        return results
    
    # Analytics and Reporting
    async def get_permission_usage_stats(self) -> Dict[str, int]:
        """Get statistics on permission usage"""
        query = text("""
            SELECT 
                p.name,
                (
                    (SELECT COUNT(*) FROM user_permissions up WHERE up.permission_id = p.id) +
                    (SELECT COUNT(*) FROM role_permissions rp 
                     JOIN user_roles ur ON ur.role_id = rp.role_id 
                     WHERE rp.permission_id = p.id) +
                    (SELECT COUNT(*) FROM team_permissions tp 
                     JOIN user_teams ut ON ut.team_id = tp.team_id 
                     WHERE tp.permission_id = p.id)
                ) as usage_count
            FROM permissions p
            ORDER BY usage_count DESC
        """)
        
        result = await self.db.execute(query)
        return {row[0]: row[1] for row in result}
    
    async def get_role_distribution(self) -> Dict[str, int]:
        """Get distribution of roles among users"""
        result = await self.db.execute(
            select(Role.name, func.count(user_roles.c.user_id))
            .select_from(Role.join(user_roles, isouter=True))
            .group_by(Role.name)
            .order_by(func.count(user_roles.c.user_id).desc())
        )
        
        return {name: count for name, count in result}
    
    async def get_team_size_distribution(self) -> Dict[str, int]:
        """Get team size distribution"""
        result = await self.db.execute(
            select(Team.name, func.count(user_teams.c.user_id))
            .select_from(Team.join(user_teams, isouter=True))
            .where(Team.is_active == True)
            .group_by(Team.name)
            .order_by(func.count(user_teams.c.user_id).desc())
        )
        
        return {name: count for name, count in result}
    
    # Permission Cleanup
    async def cleanup_expired_permissions(self) -> int:
        """Remove expired permission assignments"""
        now = datetime.now(timezone.utc)
        
        # Remove expired user permissions
        user_perm_result = await self.db.execute(
            user_permissions.delete().where(
                and_(
                    user_permissions.c.expires_at.is_not(None),
                    user_permissions.c.expires_at < now
                )
            )
        )
        
        # Remove expired role assignments
        role_result = await self.db.execute(
            user_roles.delete().where(
                and_(
                    user_roles.c.expires_at.is_not(None),
                    user_roles.c.expires_at < now
                )
            )
        )
        
        total_cleaned = user_perm_result.rowcount + role_result.rowcount
        return total_cleaned