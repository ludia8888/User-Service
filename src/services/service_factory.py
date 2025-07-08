"""
Service Factory for Dependency Injection
Provides centralized service creation with proper dependency wiring
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from services.auth_service import AuthService
from services.mfa_service import MFAService
from services.user_service import UserService
from services.audit_service import AuditService


class ServiceFactory:
    """Factory for creating service instances with proper dependency injection"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self._mfa_service: Optional[MFAService] = None
        self._auth_service: Optional[AuthService] = None
        self._user_service: Optional[UserService] = None
        self._audit_service: Optional[AuditService] = None
    
    def get_mfa_service(self) -> MFAService:
        """Get MFA service instance (singleton per factory)"""
        if self._mfa_service is None:
            self._mfa_service = MFAService(self.db)
        return self._mfa_service
    
    def get_auth_service(self) -> AuthService:
        """Get Auth service instance with MFA service injected"""
        if self._auth_service is None:
            mfa_service = self.get_mfa_service()
            self._auth_service = AuthService(self.db, mfa_service)
        return self._auth_service
    
    def get_user_service(self) -> UserService:
        """Get User service instance"""
        if self._user_service is None:
            self._user_service = UserService(self.db)
        return self._user_service
    
    def get_audit_service(self) -> AuditService:
        """Get Audit service instance"""
        if self._audit_service is None:
            self._audit_service = AuditService(self.db)
        return self._audit_service


# Convenience function for creating service factory
def create_service_factory(db: AsyncSession) -> ServiceFactory:
    """Create a service factory with database session"""
    return ServiceFactory(db)


# Helper functions for backward compatibility and convenience
def create_auth_service_with_mfa(db: AsyncSession) -> AuthService:
    """Create AuthService with MFA service properly injected"""
    factory = ServiceFactory(db)
    return factory.get_auth_service()


def create_auth_service_legacy(db: AsyncSession) -> AuthService:
    """Create AuthService without dependency injection (legacy mode)"""
    return AuthService(db, mfa_service=None)