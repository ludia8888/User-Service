"""
Normalized User Service
User management with proper relational design
"""
from datetime import datetime, timezone
from typing import Optional, List, Set, Dict
from uuid import uuid4

from sqlalchemy import select, or_, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from passlib.context import CryptContext

from models.user_normalized import User, UserStatus, PasswordHistory, MFABackupCode, UserPreference
from models.rbac import Role, Permission, Team
from core.config import settings
from core.validators import validate_password
from services.rbac_service import RBACService
from services.audit_service import AuditService

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    default="bcrypt",
    deprecated="auto"
)


class UserServiceNormalized:
    """Normalized user management service with optimized relational queries"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.rbac_service = RBACService(db)
        self.audit_service = AuditService(db)
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role_names: List[str] = None,
        team_names: List[str] = None,
        created_by: str = "system"
    ) -> User:
        """
        Create new user with proper relational structure
        """
        # Pre-check if user exists
        existing = await self.db.execute(
            select(User).where(
                or_(User.username == username, User.email == email)
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("User already exists")
        
        # Validate password
        try:
            validate_password(password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Hash password
        password_hash = pwd_context.hash(password)
        
        # Create user
        try:
            user = User(
                id=str(uuid4()),
                username=username,
                email=email,
                full_name=full_name,
                password_hash=password_hash,
                status=UserStatus.ACTIVE,
                password_changed_at=datetime.now(timezone.utc),
                created_by=created_by,
                created_at=datetime.now(timezone.utc)
            )
            
            self.db.add(user)
            await self.db.flush()
            
            # Add initial password to history
            password_entry = PasswordHistory(
                user_id=user.id,
                password_hash=password_hash
            )
            self.db.add(password_entry)
            
            # Assign default roles
            if not role_names:
                role_names = ["user"]  # Default role
            
            for role_name in role_names:
                await self.rbac_service.assign_role_to_user(
                    user.id, role_name, created_by
                )
            
            # Add to teams if specified
            if team_names:
                for team_name in team_names:
                    await self.rbac_service.add_user_to_team(
                        user.id, team_name, "member", created_by
                    )
            
            # Log user creation
            try:
                await self.audit_service.log_user_created(
                    user_id=user.id,
                    username=user.username,
                    email=user.email,
                    created_by=created_by,
                    roles=role_names
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Audit logging failed for user creation {user.username}: {e}")
            
            return user
            
        except IntegrityError as e:
            error_msg = str(e).lower()
            orig_msg = str(e.orig).lower() if e.orig else ""
            
            if any(keyword in error_msg or keyword in orig_msg for keyword in [
                'unique', 'username', 'email', 'duplicate'
            ]):
                raise ValueError("User already exists")
            else:
                raise ValueError(f"Database integrity error: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to create user: {str(e)}")
    
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID with optimized loading"""
        result = await self.db.execute(
            select(User)
            .options(
                selectinload(User.roles),
                selectinload(User.teams),
                selectinload(User.direct_permissions)
            )
            .where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username with optimized loading"""
        result = await self.db.execute(
            select(User)
            .options(
                selectinload(User.roles),
                selectinload(User.teams),
                selectinload(User.direct_permissions)
            )
            .where(User.username == username)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email with optimized loading"""
        result = await self.db.execute(
            select(User)
            .options(
                selectinload(User.roles),
                selectinload(User.teams),
                selectinload(User.direct_permissions)
            )
            .where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def update_user(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        status: Optional[UserStatus] = None,
        updated_by: str = "system"
    ) -> User:
        """Update user information"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Track changes for audit
        changes = {}
        
        if full_name is not None and user.full_name != full_name:
            changes["full_name"] = {"old": user.full_name, "new": full_name}
            user.full_name = full_name
        
        if email is not None and user.email != email:
            # Check email uniqueness
            existing = await self.db.execute(
                select(User).where(and_(User.email == email, User.id != user_id))
            )
            if existing.scalar_one_or_none():
                raise ValueError("Email already exists")
            
            changes["email"] = {"old": user.email, "new": email}
            user.email = email
        
        if status is not None and user.status != status:
            changes["status"] = {"old": user.status, "new": status}
            user.status = status
        
        if changes:
            user.updated_by = updated_by
            user.updated_at = datetime.now(timezone.utc)
            
            # Log user update
            try:
                await self.audit_service.log_user_updated(
                    user_id=user.id,
                    username=user.username,
                    changes=changes,
                    updated_by=updated_by
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Audit logging failed for user update {user.username}: {e}")
        
        return user
    
    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        changed_by: str
    ) -> User:
        """Change user password with history tracking"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Verify old password
        if not pwd_context.verify(old_password, user.password_hash):
            try:
                await self.audit_service.log_password_change_failed(
                    user_id=user.id,
                    username=user.username,
                    reason="Invalid old password"
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Audit logging failed for password change failure {user.username}: {e}")
            
            raise ValueError("Invalid old password")
        
        # Validate new password
        try:
            validate_password(new_password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Check password history
        new_hash = pwd_context.hash(new_password)
        
        # Get recent password history
        recent_passwords = await self.db.execute(
            select(PasswordHistory.password_hash)
            .where(PasswordHistory.user_id == user_id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(settings.PASSWORD_HISTORY_COUNT)
        )
        
        for (old_hash,) in recent_passwords:
            if pwd_context.verify(new_password, old_hash):
                raise ValueError("Password was used recently")
        
        # Update password
        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        
        # Add to password history
        password_entry = PasswordHistory(
            user_id=user.id,
            password_hash=new_hash
        )
        self.db.add(password_entry)
        
        # Clean up old password history
        await self._cleanup_password_history(user_id)
        
        # Log successful password change
        try:
            await self.audit_service.log_password_changed(
                user_id=user.id,
                username=user.username,
                changed_by=changed_by
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Audit logging failed for password change {user.username}: {e}")
        
        return user
    
    async def _cleanup_password_history(self, user_id: str):
        """Remove old password history entries beyond the limit"""
        # Get IDs of entries to keep
        keep_entries = await self.db.execute(
            select(PasswordHistory.id)
            .where(PasswordHistory.user_id == user_id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(settings.PASSWORD_HISTORY_COUNT)
        )
        
        keep_ids = [row[0] for row in keep_entries]
        
        if keep_ids:
            # Delete old entries
            await self.db.execute(
                select(PasswordHistory)
                .where(
                    and_(
                        PasswordHistory.user_id == user_id,
                        PasswordHistory.id.not_in(keep_ids)
                    )
                ).delete()
            )
    
    async def assign_roles(self, user_id: str, role_names: List[str], assigned_by: str) -> User:
        """Assign multiple roles to user"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        current_roles = {role.name for role in user.roles}
        new_roles = set(role_names) - current_roles
        
        for role_name in new_roles:
            await self.rbac_service.assign_role_to_user(user_id, role_name, assigned_by)
        
        if new_roles:
            # Refresh user with new roles
            user = await self.get_user_by_id(user_id)
        
        return user
    
    async def remove_roles(self, user_id: str, role_names: List[str]) -> User:
        """Remove multiple roles from user"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        for role_name in role_names:
            await self.rbac_service.remove_role_from_user(user_id, role_name)
        
        # Refresh user
        user = await self.get_user_by_id(user_id)
        return user
    
    async def assign_teams(self, user_id: str, team_names: List[str], added_by: str) -> User:
        """Assign user to multiple teams"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        current_teams = {team.name for team in user.teams}
        new_teams = set(team_names) - current_teams
        
        for team_name in new_teams:
            await self.rbac_service.add_user_to_team(user_id, team_name, "member", added_by)
        
        if new_teams:
            user = await self.get_user_by_id(user_id)
        
        return user
    
    async def remove_teams(self, user_id: str, team_names: List[str]) -> User:
        """Remove user from multiple teams"""
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        for team_name in team_names:
            await self.rbac_service.remove_user_from_team(user_id, team_name)
        
        user = await self.get_user_by_id(user_id)
        return user
    
    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all effective permissions for user"""
        return await self.rbac_service.get_user_permissions(user_id)
    
    async def user_has_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has specific permission"""
        return await self.rbac_service.user_has_permission(user_id, permission)
    
    async def update_last_login(self, user_id: str, ip_address: str = "unknown", user_agent: str = "unknown"):
        """Update user's last login time with audit"""
        user = await self.get_user_by_id(user_id)
        if user:
            user.last_login = datetime.now(timezone.utc)
            user.last_activity = datetime.now(timezone.utc)
            
            try:
                await self.audit_service.log_login_success(
                    user_id=user.id,
                    username=user.username,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Audit logging failed for last login update {user.username}: {e}")
    
    async def get_users_with_role(self, role_name: str) -> List[User]:
        """Get all users with specific role"""
        return await self.rbac_service.get_users_with_role(role_name)
    
    async def get_users_in_team(self, team_name: str) -> List[User]:
        """Get all users in specific team"""
        result = await self.db.execute(
            select(User)
            .join(User.teams)
            .where(Team.name == team_name)
            .options(selectinload(User.roles))
        )
        return result.scalars().all()
    
    async def search_users(
        self,
        query: str = None,
        role_names: List[str] = None,
        team_names: List[str] = None,
        status: UserStatus = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[User]:
        """Advanced user search with filters"""
        stmt = select(User).options(
            selectinload(User.roles),
            selectinload(User.teams)
        )
        
        conditions = []
        
        # Text search in username, email, full_name
        if query:
            query_pattern = f"%{query}%"
            conditions.append(
                or_(
                    User.username.ilike(query_pattern),
                    User.email.ilike(query_pattern),
                    User.full_name.ilike(query_pattern)
                )
            )
        
        # Status filter
        if status:
            conditions.append(User.status == status)
        
        # Role filter
        if role_names:
            stmt = stmt.join(User.roles).where(Role.name.in_(role_names))
        
        # Team filter
        if team_names:
            stmt = stmt.join(User.teams).where(Team.name.in_(team_names))
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        stmt = stmt.distinct().offset(offset).limit(limit)
        
        result = await self.db.execute(stmt)
        return result.scalars().all()
    
    async def get_user_stats(self) -> Dict[str, int]:
        """Get user statistics"""
        stats = {}
        
        # Total users
        total = await self.db.scalar(select(func.count(User.id)))
        stats["total_users"] = total
        
        # Users by status
        status_counts = await self.db.execute(
            select(User.status, func.count(User.id))
            .group_by(User.status)
        )
        
        for status, count in status_counts:
            stats[f"users_{status}"] = count
        
        # Users with MFA enabled
        mfa_enabled = await self.db.scalar(
            select(func.count(User.id)).where(User.mfa_enabled == True)
        )
        stats["users_mfa_enabled"] = mfa_enabled
        
        # Recent registrations (last 30 days)
        thirty_days_ago = datetime.now(timezone.utc).replace(day=1)  # Simple approximation
        recent = await self.db.scalar(
            select(func.count(User.id)).where(User.created_at >= thirty_days_ago)
        )
        stats["users_recent"] = recent
        
        return stats
    
    async def cleanup_inactive_users(self, days_inactive: int = 365) -> int:
        """Cleanup users who haven't been active for specified days"""
        cutoff_date = datetime.now(timezone.utc).replace(
            year=datetime.now().year - (days_inactive // 365)
        )
        
        inactive_users = await self.db.execute(
            select(User)
            .where(
                and_(
                    User.last_activity < cutoff_date,
                    User.status != UserStatus.ACTIVE
                )
            )
        )
        
        count = 0
        for user in inactive_users.scalars():
            user.status = UserStatus.INACTIVE
            count += 1
        
        return count