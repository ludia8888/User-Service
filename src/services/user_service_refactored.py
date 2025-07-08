"""
Refactored User Service - SOLID Principles Implementation
완전히 분리된 책임과 의존성 주입을 사용한 깔끔한 서비스 레이어
"""
from datetime import datetime, timezone
from typing import Optional, List, Set, Dict
from uuid import uuid4

from sqlalchemy import select, or_, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from passlib.context import CryptContext

from models.user_clean import User, UserStatus, PasswordHistory, MFABackupCode, UserPreference
from models.rbac import Role, Permission, Team
from core.config import settings
from core.validators import validate_password
from services.rbac_service import RBACService
from services.authorization_service import AuthorizationService, DefaultAuthorizationPolicy
from services.audit_service import AuditService
from business.rules import business_rules, BusinessRuleCategory, RiskLevel

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt", "argon2"],
    default="bcrypt",
    deprecated="auto"
)


class UserService:
    """
    Refactored User Service - SOLID Principles
    
    Single Responsibility: User lifecycle management only
    Open/Closed: Extensible through dependency injection
    Liskov Substitution: Uses abstractions for authorization
    Interface Segregation: Focused interface for user operations
    Dependency Inversion: Depends on abstractions, not concretions
    """
    
    def __init__(
        self, 
        db: AsyncSession,
        authorization_service: Optional[AuthorizationService] = None,
        audit_service: Optional[AuditService] = None,
        rbac_service: Optional[RBACService] = None
    ):
        # Dependency Inversion: Inject dependencies
        self.db = db
        self.rbac_service = rbac_service or RBACService(db)
        self.audit_service = audit_service or AuditService(db)
        
        # Authorization service with proper policy
        if authorization_service:
            self.authorization_service = authorization_service
        else:
            policy = DefaultAuthorizationPolicy(self.rbac_service)
            self.authorization_service = AuthorizationService(db, policy)
    
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
        Create new user with business rule validation
        
        Uses business rules engine for validation
        No business logic in this method - only orchestration
        """
        # Pre-existence check
        existing = await self._check_user_exists(username, email)
        if existing:
            raise ValueError("User already exists")
        
        # Password validation (delegated to validator)
        try:
            validate_password(password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Business rule validation
        await self._validate_user_creation_rules(username, role_names, created_by)
        
        # Create user entity
        user = await self._create_user_entity(
            username, email, password, full_name, created_by
        )
        
        # Setup initial password history
        await self._initialize_password_history(user.id, user.password_hash)
        
        # Assign roles and teams
        if role_names:
            await self._assign_initial_roles(user.id, role_names, created_by)
        
        if team_names:
            await self._assign_initial_teams(user.id, team_names, created_by)
        
        # Audit logging (delegated to audit service)
        await self._audit_user_creation(user, role_names, created_by)
        
        return user
    
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
    
    async def update_user(
        self,
        user_id: str,
        updates: Dict[str, any],
        updated_by: str = "system"
    ) -> User:
        """
        Update user with business rule validation
        
        Business logic delegated to business rules engine
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Validate updates using business rules
        await self._validate_user_updates(user, updates, updated_by)
        
        # Track changes for audit
        changes = await self._apply_user_updates(user, updates)
        
        if changes:
            user.updated_by = updated_by
            user.updated_at = datetime.now(timezone.utc)
            
            # Audit logging
            await self._audit_user_update(user, changes, updated_by)
        
        return user
    
    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        changed_by: str
    ) -> User:
        """
        Change password with business rule validation
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Verify old password
        if not pwd_context.verify(old_password, user.password_hash):
            await self._audit_password_failure(user, "Invalid old password")
            raise ValueError("Invalid old password")
        
        # Validate new password
        try:
            validate_password(new_password)
        except ValueError as e:
            raise ValueError(f"Password validation failed: {str(e)}")
        
        # Check password history using business rules
        await self._validate_password_history(user_id, new_password)
        
        # Update password
        new_hash = pwd_context.hash(new_password)
        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        
        # Add to password history
        await self._add_to_password_history(user_id, new_hash)
        
        # Clean up old history using business rules
        await self._cleanup_password_history(user_id)
        
        # Audit logging
        await self._audit_password_change(user, changed_by)
        
        return user
    
    async def check_user_permission(
        self, 
        user_id: str, 
        permission: str,
        context: Dict = None
    ) -> bool:
        """
        Check user permission using authorization service
        
        Business logic completely delegated to authorization service
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False
        
        return await self.authorization_service.user_can_access(
            user, permission, context
        )
    
    async def get_user_effective_permissions(
        self, 
        user_id: str,
        context: Dict = None
    ) -> Set[str]:
        """
        Get user's effective permissions
        
        Delegated to authorization service
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return set()
        
        return await self.authorization_service.get_user_effective_permissions(
            user, context
        )
    
    async def update_last_login(
        self, 
        user_id: str, 
        ip_address: str = "unknown", 
        user_agent: str = "unknown"
    ):
        """Update user's last login with audit trail"""
        user = await self.get_user_by_id(user_id)
        if user:
            # Pure data update - no business logic
            user.update_last_login()
            
            # Audit logging
            await self._audit_login_success(user, ip_address, user_agent)
    
    # ========================================
    # PRIVATE HELPER METHODS
    # ========================================
    
    async def _check_user_exists(self, username: str, email: str) -> bool:
        """Check if user already exists"""
        existing = await self.db.execute(
            select(User).where(
                or_(User.username == username, User.email == email)
            )
        )
        return existing.scalar_one_or_none() is not None
    
    async def _validate_user_creation_rules(
        self, 
        username: str, 
        role_names: List[str], 
        created_by: str
    ):
        """Validate user creation against business rules"""
        # Check if it's a service account
        is_service_account = 'service' in username.lower()
        
        if role_names:
            # Get creator's roles for validation
            creator_roles = set()
            if created_by != "system":
                creator_user = await self.get_user_by_id(created_by)
                if creator_user:
                    creator_roles = set(creator_user.get_role_names())
            
            # Validate each role assignment
            for role_name in role_names:
                validation = business_rules.evaluate_role_assignment_validity(
                    target_user_type='service_account' if is_service_account else 'user',
                    role_name=role_name,
                    assigner_roles=creator_roles,
                    business_justification=None  # Could be passed as parameter
                )
                
                if not validation['is_valid']:
                    raise ValueError(f"Role assignment invalid: {validation['violations']}")
    
    async def _create_user_entity(
        self, 
        username: str, 
        email: str, 
        password: str, 
        full_name: Optional[str],
        created_by: str
    ) -> User:
        """Create user entity with race condition protection"""
        password_hash = pwd_context.hash(password)
        
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
            
            return user
            
        except IntegrityError as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ['unique', 'username', 'email']):
                raise ValueError("User already exists")
            else:
                raise ValueError(f"Database integrity error: {str(e)}")
    
    async def _initialize_password_history(self, user_id: str, password_hash: str):
        """Initialize password history"""
        password_entry = PasswordHistory(
            user_id=user_id,
            password_hash=password_hash
        )
        self.db.add(password_entry)
    
    async def _assign_initial_roles(self, user_id: str, role_names: List[str], created_by: str):
        """Assign initial roles"""
        for role_name in role_names:
            await self.rbac_service.assign_role_to_user(user_id, role_name, created_by)
    
    async def _assign_initial_teams(self, user_id: str, team_names: List[str], created_by: str):
        """Assign initial teams"""
        for team_name in team_names:
            await self.rbac_service.add_user_to_team(user_id, team_name, "member", created_by)
    
    async def _validate_user_updates(self, user: User, updates: Dict, updated_by: str):
        """Validate user updates using business rules"""
        # Check email uniqueness if email is being updated
        if 'email' in updates:
            new_email = updates['email']
            if new_email != user.email:
                existing = await self.db.execute(
                    select(User).where(and_(User.email == new_email, User.id != user.id))
                )
                if existing.scalar_one_or_none():
                    raise ValueError("Email already exists")
        
        # Validate status changes using business rules
        if 'status' in updates:
            new_status = updates['status']
            current_status = user.status
            
            # Business rule: Only admins can suspend users
            if new_status == 'suspended' and current_status != 'suspended':
                updater_user = await self.get_user_by_id(updated_by)
                if updater_user:
                    updater_roles = set(updater_user.get_role_names())
                    if not business_rules.evaluate_admin_bypass_rule(updater_roles, updater_user.status):
                        raise ValueError("Only administrators can suspend users")
    
    async def _apply_user_updates(self, user: User, updates: Dict) -> Dict:
        """Apply updates to user and track changes"""
        changes = {}
        
        for field, new_value in updates.items():
            if hasattr(user, field):
                old_value = getattr(user, field)
                if old_value != new_value:
                    changes[field] = {"old": old_value, "new": new_value}
                    setattr(user, field, new_value)
        
        return changes
    
    async def _validate_password_history(self, user_id: str, new_password: str):
        """Validate against password history using business rules"""
        limit = business_rules.PASSWORD_HISTORY_LIMIT
        
        recent_passwords = await self.db.execute(
            select(PasswordHistory.password_hash)
            .where(PasswordHistory.user_id == user_id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(limit)
        )
        
        for (old_hash,) in recent_passwords:
            if pwd_context.verify(new_password, old_hash):
                raise ValueError("Password was used recently")
    
    async def _add_to_password_history(self, user_id: str, password_hash: str):
        """Add password to history"""
        password_entry = PasswordHistory(
            user_id=user_id,
            password_hash=password_hash
        )
        self.db.add(password_entry)
    
    async def _cleanup_password_history(self, user_id: str):
        """Clean up old password history using business rules"""
        limit = business_rules.PASSWORD_HISTORY_LIMIT
        
        # Get IDs of entries to keep
        keep_entries = await self.db.execute(
            select(PasswordHistory.id)
            .where(PasswordHistory.user_id == user_id)
            .order_by(PasswordHistory.created_at.desc())
            .limit(limit)
        )
        
        keep_ids = [row[0] for row in keep_entries]
        
        if keep_ids:
            # Delete old entries
            from sqlalchemy import delete
            await self.db.execute(
                delete(PasswordHistory).where(
                    and_(
                        PasswordHistory.user_id == user_id,
                        PasswordHistory.id.not_in(keep_ids)
                    )
                )
            )
    
    # ========================================
    # AUDIT METHODS (DELEGATED TO AUDIT SERVICE)
    # ========================================
    
    async def _audit_user_creation(self, user: User, role_names: List[str], created_by: str):
        """Audit user creation"""
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
    
    async def _audit_user_update(self, user: User, changes: Dict, updated_by: str):
        """Audit user update"""
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
    
    async def _audit_password_change(self, user: User, changed_by: str):
        """Audit password change"""
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
    
    async def _audit_password_failure(self, user: User, reason: str):
        """Audit password change failure"""
        try:
            await self.audit_service.log_password_change_failed(
                user_id=user.id,
                username=user.username,
                reason=reason
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Audit logging failed for password failure {user.username}: {e}")
    
    async def _audit_login_success(self, user: User, ip_address: str, user_agent: str):
        """Audit login success"""
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
            logger.error(f"Audit logging failed for login success {user.username}: {e}")


class UserManagementFacade:
    """
    Facade pattern for complex user management operations
    
    Provides simple interface for complex operations involving multiple services
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_service = UserService(db)
        self.rbac_service = RBACService(db)
        self.authorization_service = self.user_service.authorization_service
    
    async def create_user_with_full_setup(
        self,
        user_data: Dict,
        role_assignments: List[Dict],
        team_assignments: List[Dict],
        created_by: str
    ) -> Dict[str, any]:
        """
        Create user with complete setup in single transaction
        
        Combines multiple operations with proper error handling
        """
        try:
            # Create base user
            user = await self.user_service.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],
                full_name=user_data.get('full_name'),
                created_by=created_by
            )
            
            results = {
                'user': user,
                'role_assignments': [],
                'team_assignments': [],
                'errors': []
            }
            
            # Assign roles with validation
            for role_assignment in role_assignments:
                try:
                    success = await self.rbac_service.assign_role_to_user(
                        user.id,
                        role_assignment['role_name'],
                        created_by,
                        role_assignment.get('expires_at')
                    )
                    results['role_assignments'].append({
                        'role': role_assignment['role_name'],
                        'success': success
                    })
                except Exception as e:
                    results['errors'].append(f"Role assignment failed: {e}")
            
            # Assign teams with validation
            for team_assignment in team_assignments:
                try:
                    success = await self.rbac_service.add_user_to_team(
                        user.id,
                        team_assignment['team_name'],
                        team_assignment.get('role_in_team', 'member'),
                        created_by
                    )
                    results['team_assignments'].append({
                        'team': team_assignment['team_name'],
                        'success': success
                    })
                except Exception as e:
                    results['errors'].append(f"Team assignment failed: {e}")
            
            # Commit transaction
            await self.db.commit()
            
            return results
            
        except Exception as e:
            await self.db.rollback()
            raise ValueError(f"User creation failed: {e}")
    
    async def get_user_complete_profile(self, user_id: str) -> Optional[Dict]:
        """Get user with complete profile including permissions"""
        user = await self.user_service.get_user_by_id(user_id)
        if not user:
            return None
        
        # Get effective permissions
        effective_permissions = await self.user_service.get_user_effective_permissions(user_id)
        
        # Get role details
        roles = await self.rbac_service.get_user_roles(user_id)
        
        # Get team details
        teams = await self.rbac_service.get_user_teams(user_id)
        
        return {
            'user': user.to_dict(),
            'roles': [role.to_dict() for role in roles],
            'teams': [team.to_dict() for team in teams],
            'effective_permissions': list(effective_permissions),
            'authorization_summary': await self._get_authorization_summary(user)
        }
    
    async def _get_authorization_summary(self, user: User) -> Dict:
        """Get authorization summary for user"""
        return {
            'is_admin': business_rules.evaluate_admin_bypass_rule(
                set(user.get_role_names()), 
                user.status
            ),
            'status_restrictions': business_rules.evaluate_user_status_restriction(user.status),
            'mfa_enabled': user.is_mfa_enabled,
            'account_locked': user.is_status_locked or user.has_temp_lock
        }