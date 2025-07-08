"""
Service Interfaces
Defines clear contracts for service responsibilities
"""
from abc import ABC, abstractmethod
from typing import Optional, Tuple, List, Dict, Any

from models.user import User


class IUserService(ABC):
    """
    User Service Interface
    Responsible for user CRUD operations and state management
    """
    
    @abstractmethod
    async def create_user(
        self, 
        username: str, 
        email: str, 
        password: str,
        full_name: Optional[str] = None,
        roles: Optional[List[str]] = None,
        created_by: str = "system"
    ) -> User:
        """Create a new user account"""
        pass
    
    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve user by ID"""
        pass
    
    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieve user by username"""
        pass
    
    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve user by email"""
        pass
    
    @abstractmethod
    async def update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp"""
        pass
    
    @abstractmethod
    async def change_password(
        self, 
        user_id: str, 
        old_password: str, 
        new_password: str,
        changed_by: str
    ) -> User:
        """Change user password with validation"""
        pass
    
    @abstractmethod
    async def update_user_status(self, user_id: str, status: str) -> User:
        """Update user account status"""
        pass


class IAuthService(ABC):
    """
    Authentication Service Interface
    Responsible for authentication operations and token management
    """
    
    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password"""
        pass
    
    @abstractmethod
    def get_password_hash(self, password: str) -> str:
        """Generate a secure hash for a password"""
        pass
    
    @abstractmethod
    async def authenticate(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> User:
        """Authenticate user with credentials and optional MFA"""
        pass
    
    @abstractmethod
    def create_access_token(self, user: User) -> str:
        """Create a JWT access token for user"""
        pass
    
    @abstractmethod
    def create_refresh_token(self, user: User) -> str:
        """Create a JWT refresh token for user"""
        pass
    
    @abstractmethod
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and check revocation status"""
        pass
    
    @abstractmethod
    async def revoke_session(self, session_id: str, user_id: str) -> None:
        """Revoke a user session"""
        pass
    
    @abstractmethod
    async def is_session_revoked(self, session_id: str) -> bool:
        """Check if a session is revoked"""
        pass


class IMFAService(ABC):
    """
    Multi-Factor Authentication Service Interface
    Responsible for MFA operations
    """
    
    @abstractmethod
    async def generate_mfa_secret(self, user: User) -> Tuple[str, str]:
        """Generate MFA secret and provisioning URI for user"""
        pass
    
    @abstractmethod
    def generate_qr_code(self, provisioning_uri: str) -> bytes:
        """Generate QR code for MFA setup"""
        pass
    
    @abstractmethod
    async def enable_mfa(self, user: User, verification_code: str) -> List[str]:
        """Enable MFA for user and return backup codes"""
        pass
    
    @abstractmethod
    async def disable_mfa(self, user: User, password: str) -> None:
        """Disable MFA for user"""
        pass
    
    @abstractmethod
    async def verify_mfa(self, user: User, code: str) -> bool:
        """Verify MFA code (TOTP or backup code)"""
        pass
    
    @abstractmethod
    async def verify_totp(self, user: User, code: str) -> bool:
        """Verify TOTP code specifically"""
        pass
    
    @abstractmethod
    async def regenerate_backup_codes(self, user: User) -> List[str]:
        """Regenerate backup codes for user"""
        pass


class IAuditService(ABC):
    """
    Audit Service Interface
    Responsible for security event logging
    """
    
    @abstractmethod
    async def log_login_success(
        self,
        user_id: str,
        username: str,
        ip_address: str,
        user_agent: str
    ) -> None:
        """Log successful login attempt"""
        pass
    
    @abstractmethod
    async def log_login_failed(
        self,
        username: str,
        ip_address: str,
        user_agent: str,
        reason: str
    ) -> None:
        """Log failed login attempt"""
        pass
    
    @abstractmethod
    async def log_logout(
        self,
        user_id: str,
        username: str,
        session_id: str
    ) -> None:
        """Log user logout"""
        pass
    
    @abstractmethod
    async def log_password_changed(
        self,
        user_id: str,
        username: str,
        changed_by: str,
        ip_address: str
    ) -> None:
        """Log password change event"""
        pass
    
    @abstractmethod
    async def log_mfa_enabled(self, user_id: str, username: str) -> None:
        """Log MFA enablement"""
        pass
    
    @abstractmethod
    async def log_mfa_disabled(self, user_id: str, username: str) -> None:
        """Log MFA disablement"""
        pass
    
    @abstractmethod
    async def log_user_created(
        self,
        user_id: str,
        username: str,
        email: str,
        created_by: str,
        roles: List[str]
    ) -> None:
        """Log user creation"""
        pass
    
    @abstractmethod
    async def log_suspicious_activity(
        self,
        user_id: Optional[str],
        ip_address: str,
        activity: str,
        details: Dict[str, Any]
    ) -> None:
        """Log suspicious security activity"""
        pass