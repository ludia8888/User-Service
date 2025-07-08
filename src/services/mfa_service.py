"""
Multi-Factor Authentication Service
Handles TOTP generation, validation, and backup codes
"""
import base64
from common_security import encrypt_text, decrypt_text, hash_data
import secrets
import qrcode
import io
from typing import Optional, List, Tuple
from datetime import datetime, timezone

import pyotp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from models.user import User
from core.config import settings


class MFAService:
    """Service for managing multi-factor authentication"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        # Import audit service here to avoid circular imports
        from services.audit_service import AuditService
        self.audit_service = AuditService(db)
    
    async def generate_mfa_secret(self, user: User) -> Tuple[str, str]:
        """
        Generate MFA secret for user
        
        Returns:
            Tuple of (secret, provisioning_uri)
        """
        # Generate random secret
        secret = pyotp.random_base32()
        
        # Create TOTP instance
        totp = pyotp.TOTP(secret)
        
        # Generate provisioning URI for QR code
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.MFA_ISSUER
        )
        
        # Store encrypted secret in database
        user.mfa_secret = self._encrypt_secret(secret)
        
        return secret, provisioning_uri
    
    async def enable_mfa(self, user: User, verification_code: str) -> List[str]:
        """
        Enable MFA for user after verifying initial code
        
        Returns:
            List of backup codes
        """
        if not user.mfa_secret:
            raise ValueError("MFA secret not generated")
        
        # Verify the code
        if not await self.verify_totp(user, verification_code):
            raise ValueError("Invalid verification code")
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        
        # Update user
        user.mfa_enabled = True
        user.mfa_enabled_at = datetime.now(timezone.utc)
        user.backup_codes = self._hash_backup_codes(backup_codes)
        
        # Log MFA enablement
        try:
            await self.audit_service.log_mfa_enabled(
                user_id=user.id,
                username=user.username
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Audit logging failed for MFA enablement {user.username}: {e}")
        
        return backup_codes
    
    async def disable_mfa(self, user: User, password: str) -> None:
        """Disable MFA for user"""
        # Password verification should be done by caller
        
        user.mfa_enabled = False
        user.mfa_secret = None
        user.backup_codes = None
        user.mfa_enabled_at = None
        
        # Log MFA disablement
        try:
            await self.audit_service.log_mfa_disabled(
                user_id=user.id,
                username=user.username
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Audit logging failed for MFA disablement {user.username}: {e}")
    
    async def verify_totp(self, user: User, code: str) -> bool:
        """Verify TOTP code"""
        if not user.mfa_secret:
            return False
        
        # Decrypt secret
        secret = self._decrypt_secret(user.mfa_secret)
        
        # Create TOTP instance
        totp = pyotp.TOTP(secret)
        
        # Verify with window of 1 (allows previous/next code)
        return totp.verify(code, valid_window=1)
    
    async def verify_backup_code(self, user: User, code: str) -> bool:
        """Verify and consume backup code"""
        if not user.backup_codes:
            return False
        
        # Normalize code
        code = code.upper().replace(" ", "")
        
        # Check each backup code
        backup_codes = user.backup_codes or []
        for i, stored_hash in enumerate(backup_codes):
            if self._verify_backup_code(code, stored_hash):
                # Remove used code
                backup_codes.pop(i)
                user.backup_codes = backup_codes
                return True
        
        return False
    
    async def verify_mfa(self, user: User, code: Optional[str]) -> bool:
        """
        Verify MFA code (TOTP or backup code)
        
        Returns:
            True if verification successful
        """
        if not user.mfa_enabled or not code:
            return not user.mfa_enabled
        
        # Try TOTP first
        if len(code) == 6 and code.isdigit():
            return await self.verify_totp(user, code)
        
        # Try backup code
        if len(code) == 8:
            return await self.verify_backup_code(user, code)
        
        return False
    
    async def regenerate_backup_codes(self, user: User) -> List[str]:
        """Regenerate backup codes for user"""
        if not user.mfa_enabled:
            raise ValueError("MFA not enabled")
        
        # Generate new codes
        backup_codes = self._generate_backup_codes()
        
        # Store hashed codes
        user.backup_codes = self._hash_backup_codes(backup_codes)
        
        return backup_codes
    
    def generate_qr_code(self, provisioning_uri: str) -> bytes:
        """Generate QR code image for provisioning URI"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    def _generate_backup_codes(self, count: int = None) -> List[str]:
        """Generate backup codes"""
        count = count or settings.MFA_BACKUP_CODES_COUNT
        codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            codes.append(code)
        
        return codes
    
    def _hash_backup_codes(self, codes: List[str]) -> List[str]:
        """Hash backup codes for storage using common_security"""
        return [hash_data(code, algorithm="sha256") for code in codes]
    
    def _verify_backup_code(self, code: str, hashed: str) -> bool:
        """Verify backup code against hash"""
        return hash_data(code, algorithm="sha256") == hashed
    
    def _encrypt_secret(self, secret: str) -> str:
        """Encrypt MFA secret for storage using common_security"""
        return encrypt_text(secret, key_id="mfa_secret")
    
    def _decrypt_secret(self, encrypted: str) -> str:
        """Decrypt MFA secret using common_security"""
        return decrypt_text(encrypted, key_id="mfa_secret")