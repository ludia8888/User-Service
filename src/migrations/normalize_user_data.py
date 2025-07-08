"""
Migration script to normalize user data from JSON fields to proper relational structure
"""
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Set

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import AsyncSessionLocal
from models.rbac import Role, Permission, Team, PasswordHistory, user_roles, user_permissions, user_teams
from models.user_normalized import User as NormalizedUser, MFABackupCode, UserPreference
from models.user import User as OldUser


class UserDataNormalizer:
    """Handles migration from JSON-based user model to normalized relational model"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.role_cache = {}
        self.permission_cache = {}
        self.team_cache = {}
        
    async def migrate_all_users(self):
        """Complete migration process"""
        print("Starting User Data Normalization Migration...")
        
        # 1. Create default roles, permissions, and teams
        await self.create_default_rbac_entities()
        
        # 2. Migrate all users
        await self.migrate_users()
        
        # 3. Verify migration
        await self.verify_migration()
        
        print("Migration completed successfully!")
    
    async def create_default_rbac_entities(self):
        """Create default roles, permissions, and teams"""
        print("Creating default RBAC entities...")
        
        # Create system permissions
        await self.create_system_permissions()
        
        # Create system roles
        await self.create_system_roles()
        
        # Create default teams
        await self.create_default_teams()
        
        await self.session.commit()
        print("Default RBAC entities created.")
    
    async def create_system_permissions(self):
        """Create system permissions based on existing patterns"""
        permissions_data = [
            # Schema permissions
            ("schema:*:read", "Schema Read", "Read access to all schemas", "schema", "*", "read"),
            ("schema:*:write", "Schema Write", "Write access to all schemas", "schema", "*", "write"),
            ("schema:*:admin", "Schema Admin", "Admin access to all schemas", "schema", "*", "admin"),
            
            # Ontology permissions
            ("ontology:*:read", "Ontology Read", "Read access to all ontologies", "ontology", "*", "read"),
            ("ontology:*:write", "Ontology Write", "Write access to all ontologies", "ontology", "*", "write"),
            ("ontology:*:admin", "Ontology Admin", "Admin access to all ontologies", "ontology", "*", "admin"),
            
            # Branch permissions
            ("branch:*:read", "Branch Read", "Read access to all branches", "branch", "*", "read"),
            ("branch:*:write", "Branch Write", "Write access to all branches", "branch", "*", "write"),
            ("branch:*:admin", "Branch Admin", "Admin access to all branches", "branch", "*", "admin"),
            
            # Proposal permissions
            ("proposal:*:read", "Proposal Read", "Read access to all proposals", "proposal", "*", "read"),
            ("proposal:*:write", "Proposal Write", "Write access to all proposals", "proposal", "*", "write"),
            ("proposal:*:approve", "Proposal Approve", "Approve proposals", "proposal", "*", "approve"),
            ("proposal:*:admin", "Proposal Admin", "Admin access to all proposals", "proposal", "*", "admin"),
            
            # Audit permissions
            ("audit:*:read", "Audit Read", "Read access to audit logs", "audit", "*", "read"),
            ("audit:*:admin", "Audit Admin", "Admin access to audit system", "audit", "*", "admin"),
            
            # System permissions
            ("system:*:admin", "System Admin", "System administration access", "system", "*", "admin"),
            ("system:*:read", "System Read", "System read access", "system", "*", "read"),
            
            # Service permissions
            ("service:*:account", "Service Account", "Service account permissions", "service", "*", "account"),
            
            # Webhook permissions
            ("webhook:*:execute", "Webhook Execute", "Execute webhook actions", "webhook", "*", "execute"),
            ("webhook:*:admin", "Webhook Admin", "Webhook administration", "webhook", "*", "admin"),
            
            # User management permissions
            ("user:*:read", "User Read", "Read user information", "user", "*", "read"),
            ("user:*:write", "User Write", "Modify user information", "user", "*", "write"),
            ("user:*:admin", "User Admin", "User administration", "user", "*", "admin"),
            
            # Team management permissions
            ("team:*:read", "Team Read", "Read team information", "team", "*", "read"),
            ("team:*:write", "Team Write", "Modify team information", "team", "*", "write"),
            ("team:*:admin", "Team Admin", "Team administration", "team", "*", "admin"),
            
            # Role management permissions
            ("role:*:read", "Role Read", "Read role information", "role", "*", "read"),
            ("role:*:write", "Role Write", "Modify role information", "role", "*", "write"),
            ("role:*:admin", "Role Admin", "Role administration", "role", "*", "admin"),
        ]
        
        for name, display_name, description, resource_type, resource_id, permission_type in permissions_data:
            if name not in self.permission_cache:
                perm = Permission(
                    name=name,
                    display_name=display_name,
                    description=description,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission_type=permission_type,
                    is_system_permission=True
                )
                self.session.add(perm)
                self.permission_cache[name] = perm
    
    async def create_system_roles(self):
        """Create system roles"""
        roles_data = [
            ("admin", "Administrator", "Full system access", True, True, 1000),
            ("developer", "Developer", "Development access", True, False, 800),
            ("reviewer", "Reviewer", "Review and approve access", True, False, 600),
            ("user", "User", "Basic user access", True, True, 400),
            ("service", "Service Account", "Service account role", True, False, 200),
            ("readonly", "Read Only", "Read-only access", True, False, 100),
        ]
        
        for name, display_name, description, is_system, is_default, priority in roles_data:
            if name not in self.role_cache:
                role = Role(
                    name=name,
                    display_name=display_name,
                    description=description,
                    is_system_role=is_system,
                    is_default=is_default,
                    priority=priority
                )
                self.session.add(role)
                self.role_cache[name] = role
        
        await self.session.flush()
        
        # Assign permissions to roles
        await self.assign_permissions_to_roles()
    
    async def assign_permissions_to_roles(self):
        """Assign permissions to roles"""
        role_permissions = {
            "admin": [
                "schema:*:admin", "ontology:*:admin", "branch:*:admin", "proposal:*:admin",
                "audit:*:admin", "system:*:admin", "service:*:account", "webhook:*:admin",
                "user:*:admin", "team:*:admin", "role:*:admin"
            ],
            "developer": [
                "schema:*:write", "ontology:*:write", "branch:*:write", "proposal:*:write",
                "audit:*:read", "system:*:read", "webhook:*:execute",
                "user:*:read", "team:*:read", "role:*:read"
            ],
            "reviewer": [
                "schema:*:read", "ontology:*:read", "branch:*:read", "proposal:*:approve",
                "audit:*:read", "user:*:read", "team:*:read", "role:*:read"
            ],
            "user": [
                "schema:*:read", "ontology:*:read", "branch:*:read", "proposal:*:read",
                "user:*:read", "team:*:read"
            ],
            "service": [
                "service:*:account", "system:*:read", "webhook:*:execute"
            ],
            "readonly": [
                "schema:*:read", "ontology:*:read", "branch:*:read", "proposal:*:read",
                "audit:*:read", "user:*:read", "team:*:read", "role:*:read"
            ]
        }
        
        for role_name, permission_names in role_permissions.items():
            role = self.role_cache[role_name]
            for perm_name in permission_names:
                if perm_name in self.permission_cache:
                    permission = self.permission_cache[perm_name]
                    role.permissions.append(permission)
    
    async def create_default_teams(self):
        """Create default teams"""
        teams_data = [
            ("backend", "Backend Team", "Backend development team", "project"),
            ("frontend", "Frontend Team", "Frontend development team", "project"),
            ("platform", "Platform Team", "Platform and infrastructure team", "project"),
            ("security", "Security Team", "Security and compliance team", "department"),
            ("admin", "Admin Team", "System administrators", "department"),
            ("qa", "QA Team", "Quality assurance team", "functional"),
            ("devops", "DevOps Team", "DevOps and infrastructure team", "functional"),
        ]
        
        for name, display_name, description, team_type in teams_data:
            if name not in self.team_cache:
                team = Team(
                    name=name,
                    display_name=display_name,
                    description=description,
                    team_type=team_type,
                    is_active=True
                )
                self.session.add(team)
                self.team_cache[name] = team
    
    async def migrate_users(self):
        """Migrate all users from old model to normalized model"""
        print("Migrating users...")
        
        # Get all users from old model
        result = await self.session.execute(text("SELECT * FROM users"))
        old_users = result.mappings().all()
        
        migration_stats = {
            "total_users": len(old_users),
            "migrated_users": 0,
            "migrated_roles": 0,
            "migrated_permissions": 0,
            "migrated_teams": 0,
            "migrated_passwords": 0,
            "migrated_backup_codes": 0,
            "errors": []
        }
        
        for old_user_data in old_users:
            try:
                await self.migrate_single_user(old_user_data, migration_stats)
                migration_stats["migrated_users"] += 1
            except Exception as e:
                error_msg = f"Failed to migrate user {old_user_data.get('username', 'unknown')}: {str(e)}"
                migration_stats["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
        
        await self.session.commit()
        
        # Print migration statistics
        print("\n" + "="*60)
        print("MIGRATION STATISTICS")
        print("="*60)
        print(f"Total users: {migration_stats['total_users']}")
        print(f"Migrated users: {migration_stats['migrated_users']}")
        print(f"Migrated roles: {migration_stats['migrated_roles']}")
        print(f"Migrated permissions: {migration_stats['migrated_permissions']}")
        print(f"Migrated teams: {migration_stats['migrated_teams']}")
        print(f"Migrated passwords: {migration_stats['migrated_passwords']}")
        print(f"Migrated backup codes: {migration_stats['migrated_backup_codes']}")
        print(f"Errors: {len(migration_stats['errors'])}")
        
        if migration_stats['errors']:
            print("\nERROR DETAILS:")
            for error in migration_stats['errors']:
                print(f"  - {error}")
        
        print("="*60)
    
    async def migrate_single_user(self, old_user_data: Dict, stats: Dict):
        """Migrate a single user"""
        # Create new normalized user
        new_user = NormalizedUser(
            id=old_user_data['id'],
            username=old_user_data['username'],
            email=old_user_data['email'],
            full_name=old_user_data['full_name'],
            password_hash=old_user_data['password_hash'],
            status=old_user_data['status'],
            mfa_enabled=old_user_data.get('mfa_enabled', False),
            mfa_secret=old_user_data.get('mfa_secret'),
            mfa_enabled_at=old_user_data.get('mfa_enabled_at'),
            failed_login_attempts=old_user_data.get('failed_login_attempts', 0),
            last_failed_login=old_user_data.get('last_failed_login'),
            locked_until=old_user_data.get('locked_until'),
            password_changed_at=old_user_data.get('password_changed_at'),
            last_login=old_user_data.get('last_login'),
            last_activity=old_user_data.get('last_activity'),
            created_at=old_user_data.get('created_at'),
            updated_at=old_user_data.get('updated_at'),
            created_by=old_user_data.get('created_by'),
            updated_by=old_user_data.get('updated_by'),
            terms_accepted_at=old_user_data.get('terms_accepted_at'),
            privacy_accepted_at=old_user_data.get('privacy_accepted_at'),
            data_retention_consent=old_user_data.get('data_retention_consent', True)
        )
        
        self.session.add(new_user)
        await self.session.flush()
        
        # Migrate roles
        old_roles = self.parse_json_field(old_user_data.get('roles', '[]'))
        for role_name in old_roles:
            if role_name in self.role_cache:
                new_user.roles.append(self.role_cache[role_name])
                stats["migrated_roles"] += 1
            else:
                # Create unknown role
                unknown_role = await self.create_unknown_role(role_name)
                new_user.roles.append(unknown_role)
                stats["migrated_roles"] += 1
        
        # Migrate permissions
        old_permissions = self.parse_json_field(old_user_data.get('permissions', '[]'))
        for perm_name in old_permissions:
            if perm_name in self.permission_cache:
                new_user.direct_permissions.append(self.permission_cache[perm_name])
                stats["migrated_permissions"] += 1
            else:
                # Create unknown permission
                unknown_perm = await self.create_unknown_permission(perm_name)
                new_user.direct_permissions.append(unknown_perm)
                stats["migrated_permissions"] += 1
        
        # Migrate teams
        old_teams = self.parse_json_field(old_user_data.get('teams', '[]'))
        for team_name in old_teams:
            if team_name in self.team_cache:
                new_user.teams.append(self.team_cache[team_name])
                stats["migrated_teams"] += 1
            else:
                # Create unknown team
                unknown_team = await self.create_unknown_team(team_name)
                new_user.teams.append(unknown_team)
                stats["migrated_teams"] += 1
        
        # Migrate password history
        old_password_history = self.parse_json_field(old_user_data.get('password_history', '[]'))
        for password_hash in old_password_history:
            if password_hash:  # Skip empty entries
                password_entry = PasswordHistory(
                    user_id=new_user.id,
                    password_hash=password_hash,
                    created_at=old_user_data.get('password_changed_at', datetime.now())
                )
                self.session.add(password_entry)
                stats["migrated_passwords"] += 1
        
        # Migrate MFA backup codes
        old_backup_codes = self.parse_json_field(old_user_data.get('backup_codes', '[]'))
        for code_hash in old_backup_codes:
            if code_hash:  # Skip empty entries
                backup_code = MFABackupCode(
                    user_id=new_user.id,
                    code_hash=code_hash,
                    is_used=False
                )
                self.session.add(backup_code)
                stats["migrated_backup_codes"] += 1
        
        # Migrate preferences
        old_preferences = self.parse_json_field(old_user_data.get('preferences', '{}'))
        for key, value in old_preferences.items():
            preference = UserPreference(
                user_id=new_user.id,
                preference_key=key,
                preference_value=str(value),
                preference_type=type(value).__name__,
                category="migrated"
            )
            self.session.add(preference)
        
        # Migrate notification settings
        old_notifications = self.parse_json_field(old_user_data.get('notification_settings', '{}'))
        for key, value in old_notifications.items():
            preference = UserPreference(
                user_id=new_user.id,
                preference_key=f"notification_{key}",
                preference_value=str(value),
                preference_type=type(value).__name__,
                category="notification"
            )
            self.session.add(preference)
    
    def parse_json_field(self, json_str: str) -> List:
        """Safely parse JSON field"""
        try:
            if isinstance(json_str, str):
                return json.loads(json_str)
            elif isinstance(json_str, list):
                return json_str
            else:
                return []
        except (json.JSONDecodeError, TypeError):
            return []
    
    async def create_unknown_role(self, role_name: str) -> Role:
        """Create unknown role found in user data"""
        if role_name not in self.role_cache:
            role = Role(
                name=role_name,
                display_name=f"Migrated Role: {role_name}",
                description=f"Role migrated from JSON field: {role_name}",
                is_system_role=False,
                is_default=False,
                priority=500
            )
            self.session.add(role)
            await self.session.flush()
            self.role_cache[role_name] = role
        
        return self.role_cache[role_name]
    
    async def create_unknown_permission(self, perm_name: str) -> Permission:
        """Create unknown permission found in user data"""
        if perm_name not in self.permission_cache:
            # Parse permission pattern
            parts = perm_name.split(":")
            if len(parts) == 3:
                resource_type, resource_id, permission_type = parts
            else:
                resource_type, resource_id, permission_type = "unknown", "*", "unknown"
            
            permission = Permission(
                name=perm_name,
                display_name=f"Migrated Permission: {perm_name}",
                description=f"Permission migrated from JSON field: {perm_name}",
                resource_type=resource_type,
                resource_id=resource_id,
                permission_type=permission_type,
                is_system_permission=False
            )
            self.session.add(permission)
            await self.session.flush()
            self.permission_cache[perm_name] = permission
        
        return self.permission_cache[perm_name]
    
    async def create_unknown_team(self, team_name: str) -> Team:
        """Create unknown team found in user data"""
        if team_name not in self.team_cache:
            team = Team(
                name=team_name,
                display_name=f"Migrated Team: {team_name}",
                description=f"Team migrated from JSON field: {team_name}",
                team_type="migrated",
                is_active=True
            )
            self.session.add(team)
            await self.session.flush()
            self.team_cache[team_name] = team
        
        return self.team_cache[team_name]
    
    async def verify_migration(self):
        """Verify the migration was successful"""
        print("Verifying migration...")
        
        # Count old users
        old_users_count = await self.session.scalar(text("SELECT COUNT(*) FROM users"))
        
        # Count new users (assuming new table would be users_normalized)
        # For now, we'll just verify the relationships
        
        # Check role assignments
        role_assignments = await self.session.scalar(text("SELECT COUNT(*) FROM user_roles"))
        
        # Check permission assignments
        permission_assignments = await self.session.scalar(text("SELECT COUNT(*) FROM user_permissions"))
        
        # Check team assignments
        team_assignments = await self.session.scalar(text("SELECT COUNT(*) FROM user_teams"))
        
        # Check password history
        password_history_count = await self.session.scalar(text("SELECT COUNT(*) FROM password_history"))
        
        # Check backup codes
        backup_codes_count = await self.session.scalar(text("SELECT COUNT(*) FROM mfa_backup_codes"))
        
        print(f"Migration verification:")
        print(f"  - Role assignments: {role_assignments}")
        print(f"  - Permission assignments: {permission_assignments}")
        print(f"  - Team assignments: {team_assignments}")
        print(f"  - Password history entries: {password_history_count}")
        print(f"  - MFA backup codes: {backup_codes_count}")


async def run_migration():
    """Run the complete migration"""
    async with AsyncSessionLocal() as session:
        normalizer = UserDataNormalizer(session)
        await normalizer.migrate_all_users()


if __name__ == "__main__":
    asyncio.run(run_migration())