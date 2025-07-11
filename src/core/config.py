"""
Configuration settings
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import field_validator
import secrets
import warnings


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "User Service"
    DEBUG: bool = False
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_PREFIX: str = "user-service"
    
    # JWT
    JWT_SECRET: str = "your_super_secret_key_for_user_service_with_32_chars"
    JWT_ALGORITHM: str = "RS256"
    JWT_ISSUER: str = "user-service"
    JWT_AUDIENCE: str = "oms"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    @field_validator('JWT_SECRET')
    @classmethod
    def validate_jwt_secret(cls, v: str, values) -> str:
        """Validate JWT secret is secure"""
        # Check if DEBUG mode is enabled
        is_debug = values.data.get('DEBUG', False) if hasattr(values, 'data') else os.getenv('DEBUG', 'false').lower() == 'true'
        
        if v.startswith("your-super-secret") or v.startswith("your-development-secret") or v.startswith("your_super_secret"):
            if not is_debug:
                raise ValueError(
                    "JWT_SECRET must be changed from default value in production! "
                    "Generate a secure secret with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
            else:
                warnings.warn(
                    "Using default JWT_SECRET in DEBUG mode. "
                    "This must be changed before deploying to production!",
                    RuntimeWarning
                )
        elif len(v) < 32:
            if not is_debug:
                raise ValueError("JWT_SECRET must be at least 32 characters long")
        return v
    
    # Security
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_COUNT: int = 12
    PASSWORD_EXPIRE_DAYS: int = 90
    PASSWORD_COMMON_PATTERNS: List[str] = ["password", "123456", "qwerty", "abc123"]
    
    # Account Security
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 30
    MAX_CONCURRENT_SESSIONS: int = 5
    SESSION_TIMEOUT_MINUTES: int = 30
    
    # MFA
    MFA_ISSUER: str = "Your Company"
    MFA_BACKUP_CODES_COUNT: int = 10
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8007"]
    CORS_ALLOW_ALL_ORIGINS: bool = False  # Set to True only for development
    
    @field_validator('CORS_ORIGINS')
    @classmethod
    def validate_cors_origins(cls, v: List[str]) -> List[str]:
        """Validate CORS origins"""
        if not v and not cls.model_fields.get('CORS_ALLOW_ALL_ORIGINS'):
            raise ValueError("CORS_ORIGINS must be configured or CORS_ALLOW_ALL_ORIGINS must be True")
        return v
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Audit Service
    AUDIT_SERVICE_URL: str = "http://audit-service:8001"
    AUDIT_LOG_RETENTION_DAYS: int = 90
    
    # Role-Based Access Control (RBAC)
    DEFAULT_USER_ROLES: List[str] = ["user"]
    ALLOWED_ROLES: List[str] = ["user", "admin", "operator", "viewer", "service"]
    
    # Default permissions for roles
    DEFAULT_ROLE_PERMISSIONS: dict = {
        "user": [
            "ontology:read:*",
            "schema:read:*",
            "branch:read:*"
        ],
        "admin": [
            "ontology:*:*",
            "schema:*:*",
            "branch:*:*",
            "proposal:*:*",
            "audit:*:read",
            "system:*:admin"
        ],
        "operator": [
            "ontology:read:*",
            "ontology:write:*",
            "schema:read:*",
            "schema:write:*",
            "branch:read:*",
            "branch:write:*",
            "proposal:read:*",
            "proposal:write:*"
        ],
        "viewer": [
            "ontology:read:*",
            "schema:read:*",
            "branch:read:*",
            "proposal:read:*"
        ],
        "service": [
            "ontology:*:*",
            "schema:*:*",
            "branch:*:*",
            "proposal:*:*",
            "audit:*:read",
            "system:*:admin",
            "service:*:account",
            "webhook:*:execute"
        ]
    }
    
    # Default teams for roles
    DEFAULT_ROLE_TEAMS: dict = {
        "user": ["users"],
        "admin": ["users", "admins"],
        "operator": ["users", "operators"],
        "viewer": ["users", "viewers"],
        "service": ["system", "services"]
    }
    
    # Default user role (for self-registration)
    DEFAULT_NEW_USER_ROLE: str = "user"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Create settings instance
settings = Settings()