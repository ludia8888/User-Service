"""optimize_database_indexes

Revision ID: c7f4161771a3
Revises: 001_remove_audit_events_table
Create Date: 2025-07-06 10:52:22.102769

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7f4161771a3'
down_revision: Union[str, None] = '001_remove_audit_events_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Index optimization: Remove inefficient single-column indexes and create composite indexes"""
    
    # Remove inefficient single-column indexes
    op.execute("DROP INDEX IF EXISTS idx_user_status")
    op.execute("DROP INDEX IF EXISTS idx_user_mfa_enabled")
    
    # Create optimized composite indexes for users table - only if table exists
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
                -- Critical Priority
                CREATE INDEX IF NOT EXISTS idx_users_status_last_login 
                ON users (status, last_login DESC NULLS LAST);
                
                -- High Priority
                CREATE INDEX IF NOT EXISTS idx_users_status_mfa_last_activity
                ON users (status, mfa_enabled, last_activity DESC NULLS LAST);
                
                CREATE INDEX IF NOT EXISTS idx_users_status_created_at
                ON users (status, created_at DESC);
                
                CREATE INDEX IF NOT EXISTS idx_users_email_status
                ON users (email, status);
                
                CREATE INDEX IF NOT EXISTS idx_users_username_status
                ON users (username, status);
                
                -- Medium Priority
                CREATE INDEX IF NOT EXISTS idx_users_status_password_changed
                ON users (status, password_changed_at);
                
                -- Specialized indexes with partial conditions
                CREATE INDEX IF NOT EXISTS idx_users_locked_until
                ON users (status, locked_until) WHERE locked_until IS NOT NULL;
                
                CREATE INDEX IF NOT EXISTS idx_users_failed_login_tracking
                ON users (failed_login_attempts, last_failed_login) WHERE failed_login_attempts > 0;
            END IF;
        END $$;
    """)
    
    # Only create indexes for existing tables
    # Check if tables exist before creating indexes
    
    # Session indexes - only if table exists
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_sessions') THEN
                CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active
                ON user_sessions (user_id, is_active);
                
                CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at
                ON user_sessions (expires_at);
            END IF;
        END $$;
    """)
    
    # Password history indexes - only if table exists
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'password_history') THEN
                CREATE INDEX IF NOT EXISTS idx_password_history_user_created
                ON password_history (user_id, created_at DESC);
            END IF;
        END $$;
    """)
    
    # MFA backup code indexes - only if table exists
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mfa_backup_codes') THEN
                CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user_unused
                ON mfa_backup_codes (user_id, is_used);
            END IF;
        END $$;
    """)
    
    # User preferences indexes - only if table exists
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_preferences') THEN
                CREATE UNIQUE INDEX IF NOT EXISTS idx_user_preferences_user_key
                ON user_preferences (user_id, preference_key);
            END IF;
        END $$;
    """)


def downgrade() -> None:
    """Rollback index optimization"""
    
    # Remove optimized indexes
    op.execute("DROP INDEX IF EXISTS idx_users_status_last_login")
    op.execute("DROP INDEX IF EXISTS idx_users_status_mfa_last_activity")
    op.execute("DROP INDEX IF EXISTS idx_users_status_created_at")
    op.execute("DROP INDEX IF EXISTS idx_users_email_status")
    op.execute("DROP INDEX IF EXISTS idx_users_username_status")
    op.execute("DROP INDEX IF EXISTS idx_users_status_password_changed")
    op.execute("DROP INDEX IF EXISTS idx_users_locked_until")
    op.execute("DROP INDEX IF EXISTS idx_users_failed_login_tracking")
    op.execute("DROP INDEX IF EXISTS idx_user_sessions_user_active")
    op.execute("DROP INDEX IF EXISTS idx_user_sessions_expires_at")
    op.execute("DROP INDEX IF EXISTS idx_password_history_user_created")
    op.execute("DROP INDEX IF EXISTS idx_mfa_backup_codes_user_unused")
    op.execute("DROP INDEX IF EXISTS idx_user_preferences_user_key")
    
    # Restore original inefficient indexes
    op.execute("CREATE INDEX IF NOT EXISTS idx_user_status ON users (status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_user_mfa_enabled ON users (mfa_enabled)")
