"""
Main Authentication Router
Combines all authentication-related routers with proper organization
"""
from fastapi import APIRouter

from api.auth_router import router as auth_router
from api.registration_router import router as registration_router
from api.mfa_router import router as mfa_router
from api.account_router import router as account_router
from api.profile_router import router as profile_router

# Create main auth router
router = APIRouter(prefix="/auth", tags=["authentication"])

# Include sub-routers with clear organization
router.include_router(
    auth_router,
    tags=["core-auth"],
    responses={
        401: {"description": "Authentication failed"},
        429: {"description": "Rate limit exceeded"}
    }
)

router.include_router(
    registration_router,
    tags=["registration"],
    responses={
        400: {"description": "Invalid registration data"},
        429: {"description": "Rate limit exceeded"}
    }
)

router.include_router(
    mfa_router,
    prefix="/mfa",
    tags=["multi-factor-auth"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Invalid MFA request"}
    }
)

router.include_router(
    account_router,
    prefix="/account",
    tags=["account-management"],
    responses={
        401: {"description": "Unauthorized"},
        400: {"description": "Invalid account request"}
    }
)

router.include_router(
    profile_router,
    prefix="/profile",
    tags=["user-profile"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"}
    }
)