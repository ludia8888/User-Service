"""
Organization management routes
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from middleware.auth_dependencies import get_current_user
from models.user import User
from models.organization import OrganizationStatus, OrganizationType
from services.organization_service import OrganizationService
from schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    OrganizationMemberResponse
)


router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    organization_data: OrganizationCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new organization"""
    service = OrganizationService(db)
    
    organization = await service.create_organization(
        name=organization_data.name,
        created_by=current_user.id,
        slug=organization_data.slug,
        description=organization_data.description,
        type=organization_data.type,
        email=organization_data.email,
        phone=organization_data.phone,
        website=organization_data.website,
        address_line1=organization_data.address_line1,
        address_line2=organization_data.address_line2,
        city=organization_data.city,
        state=organization_data.state,
        postal_code=organization_data.postal_code,
        country=organization_data.country
    )
    
    return OrganizationResponse.from_orm(organization)


@router.get("/", response_model=List[OrganizationListResponse])
async def list_organizations(
    status: Optional[OrganizationStatus] = Query(None, description="Filter by status"),
    type: Optional[OrganizationType] = Query(None, description="Filter by type"),
    search: Optional[str] = Query(None, description="Search by name or slug"),
    my_organizations: bool = Query(False, description="Show only user's organizations"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List organizations"""
    service = OrganizationService(db)
    
    user_id = current_user.id if my_organizations else None
    
    organizations = await service.list_organizations(
        user_id=user_id,
        status=status,
        type=type,
        search=search,
        skip=skip,
        limit=limit
    )
    
    return [OrganizationListResponse.from_orm(org) for org in organizations]


@router.get("/my", response_model=List[OrganizationMemberResponse])
async def get_my_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's organizations with membership details"""
    service = OrganizationService(db)
    organizations = await service.get_user_organizations(current_user.id)
    return organizations


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get organization by ID"""
    service = OrganizationService(db)
    organization = await service.get_organization(organization_id)
    return OrganizationResponse.from_orm(organization)


@router.get("/slug/{slug}", response_model=OrganizationResponse)
async def get_organization_by_slug(
    slug: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get organization by slug"""
    service = OrganizationService(db)
    organization = await service.get_organization_by_slug(slug)
    return OrganizationResponse.from_orm(organization)


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: str,
    organization_data: OrganizationUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update organization"""
    service = OrganizationService(db)
    
    updates = organization_data.dict(exclude_unset=True)
    
    organization = await service.update_organization(
        organization_id=organization_id,
        updated_by=current_user.id,
        **updates
    )
    
    return OrganizationResponse.from_orm(organization)


@router.delete("/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    organization_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete organization (soft delete)"""
    service = OrganizationService(db)
    await service.delete_organization(organization_id, current_user.id)
    return None


@router.post("/{organization_id}/members/{user_id}", status_code=status.HTTP_201_CREATED)
async def add_member(
    organization_id: str,
    user_id: str,
    role: str = Query("member", regex="^(owner|admin|member)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Add user to organization"""
    service = OrganizationService(db)
    
    await service.add_user_to_organization(
        organization_id=organization_id,
        user_id=user_id,
        role=role,
        added_by=current_user.id
    )
    
    return {"message": "User added to organization successfully"}


@router.delete("/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    organization_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Remove user from organization"""
    service = OrganizationService(db)
    
    await service.remove_user_from_organization(
        organization_id=organization_id,
        user_id=user_id,
        removed_by=current_user.id
    )
    
    return None