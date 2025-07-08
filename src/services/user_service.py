"""
User Service
User management business logic
"""
from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4
import logging

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

from models.user import User, UserStatus
from core.config import settings
from core.validators import validate_password
from services.rbac_service import RBACService
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

# Password hashing - Use bcrypt as default for compatibility
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    default="bcrypt",
    deprecated="auto"
)


class UserService:
    """User management service"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_service = AuditService(db)
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role_names: List[str] = None,
        created_by: str = "system"
    ) -> User:
        """
        Create new user with race condition protection
        
        Handles concurrent requests by catching IntegrityError from UNIQUE constraints.
        Pre-checks are kept for user-friendly error messages.
        
        Note: Audit logging is handled by publishing events to Audit Service
        """
        # Pre-check if user exists (for user-friendly error messages)
        existing = await self.db.execute(
            select(User).where(
                or_(User.username == username, User.email == email)
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("User already exists")
        
        # Validate password using the comprehensive validator
        try:
            validate_password(password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Hash password
        password_hash = pwd_context.hash(password)
        
        # Atomic user creation with race condition protection
        try:
            # Create user with normalized model
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
            
            # Assign roles using RBAC service
            if role_names:
                rbac_service = RBACService(self.db)
                for role_name in role_names:
                    try:
                        await rbac_service.assign_role_to_user(
                            user_id=user.id,
                            role_name=role_name,
                            assigned_by=created_by
                        )
                        logger.info(f"Assigned role {role_name} to user {username}")
                    except Exception as e:
                        logger.warning(f"Failed to assign role {role_name} to user {username}: {e}")
            else:
                logger.info(f"User {username} created without explicit roles")
            
            # Force flush to trigger UNIQUE constraint check
            # This will raise IntegrityError if concurrent creation occurred
            await self.db.flush()
            
            # Log user creation audit event
            try:
                # TODO: Get actual roles when database roles are implemented
                role_names_for_audit = role_names or []
                await self.audit_service.log_user_created(
                    user_id=user.id,
                    username=user.username,
                    email=user.email,
                    created_by=created_by,
                    roles=role_names_for_audit
                )
            except Exception as e:
                # Audit logging failure should not break user creation
                # The audit service has retry mechanisms via Redis queue
                logger.error(f"Audit logging failed for user creation {user.username}: {e}")
            
            return user
            
        except IntegrityError as e:
            # Handle race condition: another thread created the user
            # Check if it's a username or email conflict
            error_msg = str(e).lower()
            orig_msg = str(e.orig).lower() if e.orig else ""
            
            # Check for UNIQUE constraint violations on username or email
            if any(keyword in error_msg or keyword in orig_msg for keyword in [
                'unique', 'username', 'email', 'duplicate'
            ]):
                # UNIQUE constraint violation - user was created by concurrent request
                raise ValueError("User already exists")
            else:
                # Other integrity error, re-raise with details
                raise ValueError(f"Database integrity error: {str(e)}")
        except Exception as e:
            # Handle other database errors
            raise ValueError(f"Failed to create user: {str(e)}")
    
    async def update_user(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        team_names: Optional[List[str]] = None,
        updated_by: str = "system"
    ) -> User:
        """Update user information"""
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Track changes for audit
        changes = {}
        
        # Update fields
        if full_name is not None:
            changes["full_name"] = {"old": user.full_name, "new": full_name}
            user.full_name = full_name
        
        if role_names is not None:
            # Update roles using RBAC service
            rbac_service = RBACService(self.db)
            current_roles = await rbac_service.get_user_roles(user_id)
            current_role_names = [role.name for role in current_roles]
            
            # Remove old roles
            for role_name in current_role_names:
                if role_name not in role_names:
                    await rbac_service.remove_role_from_user(user_id, role_name)
            
            # Add new roles
            for role_name in role_names:
                if role_name not in current_role_names:
                    await rbac_service.assign_role_to_user(
                        user_id=user_id,
                        role_name=role_name,
                        assigned_by=updated_by
                    )
            
            changes["roles"] = {"old": current_role_names, "new": role_names}
            logger.info(f"User {user.username} roles updated from {current_role_names} to {role_names}")
        
        if team_names is not None:
            from services.team_service import TeamService
            old_teams = [team.name for team in user.teams]
            changes["teams"] = {"old": old_teams, "new": team_names}
            
            # Clear existing teams
            user.teams.clear()
            
            # Add new teams using TeamService
            team_service = TeamService(self.db)
            for team_name in team_names:
                team = await team_service.get_team_by_name(team_name)
                if team:
                    user.teams.append(team)
                else:
                    # Create team if not exists
                    team = await team_service.create_team(
                        name=team_name,
                        description=f"Auto-created team: {team_name}",
                        created_by=updated_by
                    )
                    user.teams.append(team)
        
        user.updated_by = updated_by
        user.updated_at = datetime.now(timezone.utc)
        
        # Log user update audit event if changes were made
        if changes:
            try:
                await self.audit_service.log_user_updated(
                    user_id=user.id,
                    username=user.username,
                    changes=changes,
                    updated_by=updated_by
                )
            except Exception as e:
                # Audit logging failure should not break user update
                logger.error(f"Audit logging failed for user update {user.username}: {e}")
            
            # Invalidate cache if roles or teams changed
            if "roles" in changes or "teams" in changes:
                await self._invalidate_user_cache(user_id)
        
        return user
    
    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        changed_by: str
    ) -> User:
        """Change user password"""
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Verify old password
        if not pwd_context.verify(old_password, user.password_hash):
            # Log failed password change attempt
            try:
                await self.audit_service.log_password_change_failed(
                    user_id=user.id,
                    username=user.username,
                    reason="Invalid old password"
                )
            except Exception as e:
                logger.error(f"Audit logging failed for password change failure {user.username}: {e}")
            
            raise ValueError("Invalid old password")
        
        # Validate new password using the comprehensive validator
        try:
            validate_password(new_password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Check password history
        new_hash = pwd_context.hash(new_password)
        password_history = user.password_history or []
        for old_hash in password_history[-settings.PASSWORD_HISTORY_COUNT:]:
            if pwd_context.verify(new_password, old_hash):
                raise ValueError("Password was used recently")
        
        # Update password
        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        user.password_history = password_history + [new_hash]
        user.password_history = user.password_history[-settings.PASSWORD_HISTORY_COUNT:]
        
        # Log successful password change
        try:
            await self.audit_service.log_password_changed(
                user_id=user.id,
                username=user.username,
                changed_by=changed_by
            )
        except Exception as e:
            # Audit logging failure should not break password change
            logger.error(f"Audit logging failed for password change {user.username}: {e}")
        
        return user
    
    async def update_last_login(self, user_id: str):
        """Update user's last login time"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if user:
            user.last_login = datetime.now(timezone.utc)
            user.last_activity = datetime.now(timezone.utc)
            
            # Log last login update
            try:
                await self.audit_service.log_login_success(
                    user_id=user.id,
                    username=user.username,
                    ip_address="unknown",  # IP should be passed from caller
                    user_agent="unknown"   # User agent should be passed from caller
                )
            except Exception as e:
                logger.error(f"Audit logging failed for last login update {user.username}: {e}")
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def update_user_permissions(
        self, 
        user_id: str, 
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        teams: Optional[List[str]] = None
    ) -> User:
        """
        Update user permissions and invalidate cache
        This ensures real-time permission changes take effect immediately
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # TODO: Update fields when database relationships are ready
        if roles is not None:
            logger.info(f"Would update user {user_id} roles to: {roles}")
        if permissions is not None:
            logger.info(f"Would update user {user_id} permissions to: {permissions}")
        if teams is not None:
            logger.info(f"Would update user {user_id} teams to: {teams}")
        
        # Invalidate permissions cache to ensure real-time updates
        await self._invalidate_user_cache(user_id)
        
        return user
    
    async def _invalidate_user_cache(self, user_id: str):
        """Invalidate user permissions cache when data changes"""
        try:
            from core.redis import get_redis_client
            from core.config import settings
            
            redis_client = get_redis_client()
            cache_key = f"{settings.REDIS_PREFIX}:user_permissions:{user_id}"
            await redis_client.delete(cache_key)
        except Exception:
            # Cache invalidation failure shouldn't break the operation
            pass
    
    async def create_default_user(self):
        """Create default test user if it doesn't exist with race condition protection"""
        # Create admin user first
        existing_admin = await self.get_user_by_username("admin")
        if not existing_admin:
            try:
                admin_user = await self.create_user(
                    username="admin",
                    email="admin@example.com",
                    password=settings.DEFAULT_ADMIN_PASSWORD,
                    full_name="Admin User",
                    role_names=["admin"],
                    created_by="system"
                )
                logger.info(f"Created admin user: {admin_user.username}")
            except ValueError as e:
                if "User already exists" not in str(e):
                    logger.error(f"Failed to create admin user: {e}")
        
        existing_user = await self.get_user_by_username("testuser")
        if not existing_user:
            try:
                # Create admin user with admin role
                user = await self.create_user(
                    username="testuser",
                    email="test@example.com",
                    password="Test123!",
                    full_name="Test User",
                    role_names=["admin"],  # Just pass role name for validation
                    created_by="system"
                )
                
                logger.info(f"Created default test user: {user.username}")
                return user
                
            except ValueError as e:
                # If user creation fails due to race condition, try to get the user again
                if "User already exists" in str(e):
                    existing_user = await self.get_user_by_username("testuser")
                    if existing_user:
                        return existing_user
                # Re-raise other ValueError types
                raise
        return existing_user
    
    def _validate_password(self, password: str) -> bool:
        """Validate password against policy"""
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not has_upper:
            return False
        if settings.PASSWORD_REQUIRE_LOWERCASE and not has_lower:
            return False
        if settings.PASSWORD_REQUIRE_DIGITS and not has_digit:
            return False
        if settings.PASSWORD_REQUIRE_SPECIAL and not has_special:
            return False
        
        return True