"""
User Service - Main Application
FastAPI application for user authentication and management
"""
import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi

from core.config import settings
from core.database import init_db
from core.logging import setup_logging
from core.security_headers import SecurityHeadersMiddleware
from core.rate_limit import RateLimitMiddleware
from middleware.api_key_auth import ServiceAuthMiddleware
from api import auth, iam_adapter, internal

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler
    """
    logger.info("Starting User Service...")
    
    # Validate critical security settings
    if settings.JWT_SECRET.startswith("your-super-secret") and not settings.DEBUG:
        logger.error("CRITICAL: JWT_SECRET is using default value in production!")
        raise RuntimeError(
            "JWT_SECRET must be changed from default value in production! "
            "Set JWT_SECRET environment variable with a secure value."
        )
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Create default test user
    try:
        from core.database import AsyncSessionLocal
        from services.user_service import UserService
        
        async with AsyncSessionLocal() as db:
            user_service = UserService(db)
            await user_service.create_default_user()
            logger.info("Default test user created/verified")
    except Exception as e:
        logger.warning(f"Failed to create default user: {e}")
    
    yield
    
    logger.info("Shutting down User Service...")


# Create FastAPI application
app = FastAPI(
    title="User Service",
    description="Authentication and User Management Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Add security middleware
# Configure allowed hosts based on environment
allowed_hosts = ["*"] if settings.DEBUG else ["localhost", "127.0.0.1", ".yourdomain.com"]
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)

# Add CORS middleware with proper configuration
cors_origins = ["*"] if settings.CORS_ALLOW_ALL_ORIGINS else settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count", "X-Page", "X-Per-Page"],
    max_age=3600  # Cache preflight requests for 1 hour
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware, strict=not settings.DEBUG)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Add service authentication middleware
app.add_middleware(ServiceAuthMiddleware, protected_paths=["/internal/"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler - prevents sensitive information leakage
    """
    # Log detailed error internally
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    
    # Return generic error message to client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Please contact support if this persists."}
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "service": "user-service",
        "version": "1.0.0"
    }


# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(iam_adapter.router, tags=["IAM Adapter"])
app.include_router(internal.router, tags=["Internal API"])


# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="User Service API",
        version="1.0.0",
        description="User Authentication and Management Service with OMS IAM Compatibility",
        routes=app.routes,
    )
    
    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_config=None  # Use our custom logging
    )