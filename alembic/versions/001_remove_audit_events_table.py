"""Remove audit_events table - migrated to Audit Service

Revision ID: 001_remove_audit_events_table
Revises: 
Create Date: 2025-07-05 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_remove_audit_events_table'
down_revision = '000_initial_tables'
branch_labels = None
depends_on = None


def upgrade():
    """Remove audit_events table as we're using centralized Audit Service"""
    # Check if audit_events table exists before backing up
    op.execute("""
        DO $$ 
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_events') THEN
                CREATE TABLE IF NOT EXISTS audit_events_backup AS 
                SELECT * FROM audit_events;
                DROP TABLE audit_events;
            END IF;
        END $$;
    """)


def downgrade():
    """Recreate audit_events table from backup if needed"""
    # Recreate the table structure
    op.create_table('audit_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('ix_audit_events_event_type', 'audit_events', ['event_type'])
    op.create_index('ix_audit_events_user_id', 'audit_events', ['user_id'])
    op.create_index('ix_audit_events_username', 'audit_events', ['username'])
    op.create_index('ix_audit_events_timestamp', 'audit_events', ['timestamp'])
    
    # Restore data from backup if it exists
    op.execute("""
        INSERT INTO audit_events 
        SELECT * FROM audit_events_backup
        WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_events_backup');
    """)