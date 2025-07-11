"""Add service_clients table

Revision ID: 002_add_service_clients
Revises: 001_initial_schema
Create Date: 2025-07-09 18:35:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '002_add_service_clients'
down_revision = '001_initial_schema'
branch_labels = None
depends_on = None


def upgrade():
    """Create service_clients table for service-to-service authentication"""
    op.create_table(
        'service_clients',
        sa.Column('client_id', sa.String(), nullable=False),
        sa.Column('client_secret_hash', sa.String(), nullable=False),
        sa.Column('service_name', sa.String(), nullable=False),
        sa.Column('allowed_grant_types', postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('allowed_scopes', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('client_id')
    )
    
    # Create indexes
    op.create_index('ix_service_clients_client_id', 'service_clients', ['client_id'])
    op.create_index('ix_service_clients_service_name', 'service_clients', ['service_name'], unique=True)
    
    # Insert default service clients
    op.execute("""
        INSERT INTO service_clients (client_id, client_secret_hash, service_name, allowed_grant_types, allowed_scopes, description)
        VALUES 
        ('oms-monolith-client', '$2b$12$placeholder_hash_replace_in_production', 'oms-monolith', 
         ARRAY['token_exchange'], ARRAY['audit:write', 'audit:read', 'user:read'], 
         'OMS Monolith Service Client'),
        ('audit-service-client', '$2b$12$placeholder_hash_replace_in_production', 'audit-service',
         ARRAY['token_exchange'], ARRAY['user:read', 'user:validate'],
         'Audit Service Client')
    """)


def downgrade():
    """Drop service_clients table"""
    op.drop_index('ix_service_clients_service_name', table_name='service_clients')
    op.drop_index('ix_service_clients_client_id', table_name='service_clients')
    op.drop_table('service_clients')