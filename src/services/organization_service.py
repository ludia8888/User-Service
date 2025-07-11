"""
Organization service for managing organizations
"""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import re

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models.organization import Organization, OrganizationStatus, OrganizationType, user_organizations
from models.user import User
from core.exceptions import (
    NotFoundException,
    ConflictException,
    ValidationException,
    ForbiddenException
)


logger = logging.getLogger(__name__)


class OrganizationService:
    """Service for managing organizations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_organization(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        type: OrganizationType = OrganizationType.TEAM,
        **kwargs
    ) -> Organization:
        """Create a new organization"""
        try:
            # Generate slug if not provided
            if not slug:
                slug = self._generate_slug(name)
            
            # Validate slug
            if not self._is_valid_slug(slug):
                raise ValidationException("Invalid slug format. Use only lowercase letters, numbers, and hyphens.")
            
            # Check if slug already exists
            existing = await self.db.execute(
                select(Organization).where(Organization.slug == slug)
            )
            if existing.scalar_one_or_none():
                raise ConflictException(f"Organization with slug '{slug}' already exists")
            
            # Create organization
            organization = Organization(
                name=name,
                slug=slug,
                description=description,
                type=type,
                created_by=created_by,
                updated_by=created_by,
                **kwargs
            )
            
            self.db.add(organization)
            
            # Add creator as owner
            await self.db.execute(
                user_organizations.insert().values(
                    user_id=created_by,
                    organization_id=organization.id,
                    role='owner',
                    is_primary=True
                )
            )
            
            await self.db.commit()
            await self.db.refresh(organization)
            
            logger.info(f"Created organization: {organization.id}")
            return organization
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to create organization: {str(e)}")
            raise
    
    async def get_organization(self, organization_id: str) -> Organization:
        """Get organization by ID"""
        result = await self.db.execute(
            select(Organization)
            .where(Organization.id == organization_id)
            .options(
                selectinload(Organization.users),
                selectinload(Organization.teams)
            )
        )
        organization = result.scalar_one_or_none()
        
        if not organization:
            raise NotFoundException(f"Organization {organization_id} not found")
        
        return organization
    
    async def get_organization_by_slug(self, slug: str) -> Organization:
        """Get organization by slug"""
        result = await self.db.execute(
            select(Organization)
            .where(Organization.slug == slug)
            .options(
                selectinload(Organization.users),
                selectinload(Organization.teams)
            )
        )
        organization = result.scalar_one_or_none()
        
        if not organization:
            raise NotFoundException(f"Organization with slug '{slug}' not found")
        
        return organization
    
    async def list_organizations(
        self,
        user_id: Optional[str] = None,
        status: Optional[OrganizationStatus] = None,
        type: Optional[OrganizationType] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Organization]:
        """List organizations with filters"""
        query = select(Organization)
        
        # Filter by user membership
        if user_id:
            query = query.join(
                user_organizations,
                Organization.id == user_organizations.c.organization_id
            ).where(user_organizations.c.user_id == user_id)
        
        # Filter by status
        if status:
            query = query.where(Organization.status == status)
        
        # Filter by type
        if type:
            query = query.where(Organization.type == type)
        
        # Search by name or slug
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                or_(
                    Organization.name.ilike(search_pattern),
                    Organization.slug.ilike(search_pattern)
                )
            )
        
        # Apply pagination
        query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def update_organization(
        self,
        organization_id: str,
        updated_by: str,
        **updates
    ) -> Organization:
        """Update organization"""
        organization = await self.get_organization(organization_id)
        
        # Check if user can update (simplified - in real app, check permissions)
        if not await self._can_user_manage_organization(updated_by, organization_id):
            raise ForbiddenException("You don't have permission to update this organization")
        
        # Validate slug if being updated
        if 'slug' in updates and updates['slug'] != organization.slug:
            if not self._is_valid_slug(updates['slug']):
                raise ValidationException("Invalid slug format")
            
            # Check if new slug already exists
            existing = await self.db.execute(
                select(Organization).where(
                    and_(
                        Organization.slug == updates['slug'],
                        Organization.id != organization_id
                    )
                )
            )
            if existing.scalar_one_or_none():
                raise ConflictException(f"Organization with slug '{updates['slug']}' already exists")
        
        # Update fields
        for key, value in updates.items():
            if hasattr(organization, key) and key not in ['id', 'created_at', 'created_by']:
                setattr(organization, key, value)
        
        organization.updated_by = updated_by
        organization.updated_at = datetime.utcnow()
        
        await self.db.commit()
        await self.db.refresh(organization)
        
        logger.info(f"Updated organization: {organization_id}")
        return organization
    
    async def delete_organization(self, organization_id: str, deleted_by: str) -> bool:
        """Delete organization (soft delete by setting status to inactive)"""
        organization = await self.get_organization(organization_id)
        
        # Check if user can delete
        if not await self._can_user_manage_organization(deleted_by, organization_id):
            raise ForbiddenException("You don't have permission to delete this organization")
        
        # Don't allow deletion if there are active teams
        if organization.teams and any(team.is_active for team in organization.teams):
            raise ValidationException("Cannot delete organization with active teams")
        
        # Soft delete
        organization.status = OrganizationStatus.INACTIVE
        organization.updated_by = deleted_by
        organization.updated_at = datetime.utcnow()
        
        await self.db.commit()
        
        logger.info(f"Deleted organization: {organization_id}")
        return True
    
    async def add_user_to_organization(
        self,
        organization_id: str,
        user_id: str,
        role: str = 'member',
        added_by: str = None
    ) -> bool:
        """Add user to organization"""
        # Verify organization exists
        organization = await self.get_organization(organization_id)
        
        # Check if organization can add more users
        if not organization.can_add_user():
            raise ValidationException(f"Organization has reached its user limit ({organization.max_users})")
        
        # Check if user already in organization
        existing = await self.db.execute(
            select(user_organizations).where(
                and_(
                    user_organizations.c.user_id == user_id,
                    user_organizations.c.organization_id == organization_id
                )
            )
        )
        if existing.first():
            raise ConflictException("User is already a member of this organization")
        
        # Add user to organization
        await self.db.execute(
            user_organizations.insert().values(
                user_id=user_id,
                organization_id=organization_id,
                role=role,
                is_primary=False
            )
        )
        
        await self.db.commit()
        
        logger.info(f"Added user {user_id} to organization {organization_id}")
        return True
    
    async def remove_user_from_organization(
        self,
        organization_id: str,
        user_id: str,
        removed_by: str = None
    ) -> bool:
        """Remove user from organization"""
        # Check if user is in organization
        result = await self.db.execute(
            select(user_organizations).where(
                and_(
                    user_organizations.c.user_id == user_id,
                    user_organizations.c.organization_id == organization_id
                )
            )
        )
        membership = result.first()
        
        if not membership:
            raise NotFoundException("User is not a member of this organization")
        
        # Don't allow removing the last owner
        if membership.role == 'owner':
            owner_count = await self.db.execute(
                select(func.count()).select_from(user_organizations).where(
                    and_(
                        user_organizations.c.organization_id == organization_id,
                        user_organizations.c.role == 'owner'
                    )
                )
            )
            if owner_count.scalar() <= 1:
                raise ValidationException("Cannot remove the last owner from organization")
        
        # Remove user from organization
        await self.db.execute(
            user_organizations.delete().where(
                and_(
                    user_organizations.c.user_id == user_id,
                    user_organizations.c.organization_id == organization_id
                )
            )
        )
        
        await self.db.commit()
        
        logger.info(f"Removed user {user_id} from organization {organization_id}")
        return True
    
    async def get_user_organizations(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all organizations for a user"""
        result = await self.db.execute(
            select(Organization, user_organizations.c.role, user_organizations.c.is_primary)
            .join(
                user_organizations,
                Organization.id == user_organizations.c.organization_id
            )
            .where(user_organizations.c.user_id == user_id)
            .order_by(user_organizations.c.is_primary.desc(), Organization.name)
        )
        
        organizations = []
        for org, role, is_primary in result:
            org_dict = {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "type": org.type,
                "status": org.status,
                "role": role,
                "is_primary": is_primary
            }
            organizations.append(org_dict)
        
        return organizations
    
    async def _can_user_manage_organization(self, user_id: str, organization_id: str) -> bool:
        """Check if user can manage organization (owner or admin)"""
        result = await self.db.execute(
            select(user_organizations.c.role).where(
                and_(
                    user_organizations.c.user_id == user_id,
                    user_organizations.c.organization_id == organization_id,
                    user_organizations.c.role.in_(['owner', 'admin'])
                )
            )
        )
        return result.first() is not None
    
    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from name"""
        # Convert to lowercase and replace spaces with hyphens
        slug = name.lower().strip()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[-\s]+', '-', slug)
        return slug
    
    def _is_valid_slug(self, slug: str) -> bool:
        """Validate slug format"""
        return bool(re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', slug))