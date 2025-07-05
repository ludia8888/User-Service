"""
Configuration settings
"""
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
    DATABASE_URL: str = "postgresql+asyncpg://user_service:password@user-db:5432/user_service"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_PREFIX: str = "user-service"
    
    # JWT
    JWT_SECRET: str = "your-super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    @field_validator('JWT_SECRET')
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Validate JWT secret is secure"""
        if v.startswith("your-super-secret"):
            if not cls.model_fields.get('DEBUG') or not cls.model_fields['DEBUG'].default:
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
    
    # Audit
    AUDIT_LOG_RETENTION_DAYS: int = 90
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Create settings instance
settings = Settings()