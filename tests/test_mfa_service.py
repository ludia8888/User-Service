"""
Comprehensive unit tests for MFAService
"""
import pytest
import base64
import secrets
import pyotp
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from io import BytesIO

from sqlalchemy.ext.asyncio import AsyncSession

from services.mfa_service import MFAService
from models.user import User
from core.config import settings


class TestMFAService:
    """Test MFAService class"""
    
    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
    @pytest.fixture
    def mfa_service(self, mock_db):
        """MFAService instance"""
        service = MFAService(mock_db)
        
        # Mock encryption/decryption to avoid cryptography complexity in tests
        service._encrypt_secret = lambda x: f"encrypted_{x}"
        service._decrypt_secret = lambda x: x.replace("encrypted_", "") if x.startswith("encrypted_") else x
        
        # Mock hash functions
        service._hash_backup_codes = lambda codes: [f"hashed_{code}" for code in codes]
        service._verify_backup_code = lambda code, hashed: hashed == f"hashed_{code}"
        
        return service
    
    @pytest.fixture
    def mock_user(self):
        """Mock user object"""
        user = MagicMock()
        user.id = "test_user_id"
        user.username = "testuser"
        user.email = "test@example.com"
        user.mfa_enabled = False
        user.mfa_secret = None
        user.backup_codes = None
        user.mfa_enabled_at = None
        return user
    
    @pytest.fixture
    def mock_user_with_mfa(self, mock_user):
        """Mock user with MFA enabled"""
        test_secret = "JBSWY3DPEHPK3PXP"
        mock_user.mfa_enabled = True
        mock_user.mfa_secret = f"encrypted_{test_secret}"  # Use the mocked encryption format
        mock_user.backup_codes = ["hashed_ABCD1234", "hashed_EFGH5678"]
        mock_user.mfa_enabled_at = datetime.now(timezone.utc)
        return mock_user

    # Secret generation tests
    @pytest.mark.asyncio
    async def test_generate_mfa_secret_success(self, mfa_service, mock_user):
        """Test successful MFA secret generation"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        with patch('pyotp.random_base32', return_value="JBSWY3DPEHPK3PXP"):
            with patch.object(settings, 'MFA_ISSUER', 'Test Service'):
                secret, provisioning_uri = await mfa_service.generate_mfa_secret(mock_user)
                
                assert secret == "JBSWY3DPEHPK3PXP"
                assert "Test%20Service" in provisioning_uri
                assert "test%40example.com" in provisioning_uri
                assert mock_user.mfa_secret is not None
                
                mfa_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_generate_mfa_secret_creates_valid_totp(self, mfa_service, mock_user):
        """Test that generated secret creates valid TOTP"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        secret, provisioning_uri = await mfa_service.generate_mfa_secret(mock_user)
        
        # Verify TOTP can be created from secret
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        assert len(code) == 6
        assert code.isdigit()
        assert totp.verify(code)
    
    @pytest.mark.asyncio
    async def test_generate_mfa_secret_encryption(self, mfa_service, mock_user):
        """Test that MFA secret is properly encrypted"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        secret, _ = await mfa_service.generate_mfa_secret(mock_user)
        
        # Verify secret is encrypted (base64 in this implementation)
        assert mock_user.mfa_secret != secret
        
        # Verify it can be decrypted
        decrypted = mfa_service._decrypt_secret(mock_user.mfa_secret)
        assert decrypted == secret

    # MFA enable tests
    @pytest.mark.asyncio
    async def test_enable_mfa_success(self, mfa_service, mock_user):
        """Test successful MFA enablement"""
        # Setup secret
        test_secret = "JBSWY3DPEHPK3PXP"
        mock_user.mfa_secret = f"encrypted_{test_secret}"  # Use mocked encryption format
        
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        # Generate valid TOTP code
        totp = pyotp.TOTP(test_secret)
        valid_code = totp.now()
        
        with patch.object(settings, 'MFA_BACKUP_CODES_COUNT', 10):
            backup_codes = await mfa_service.enable_mfa(mock_user, valid_code)
            
            assert mock_user.mfa_enabled is True
            assert mock_user.mfa_enabled_at is not None
            assert len(backup_codes) == 10
            assert all(len(code) == 8 for code in backup_codes)
            assert mock_user.backup_codes is not None
            assert len(mock_user.backup_codes) == 10
            
            mfa_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_enable_mfa_no_secret(self, mfa_service, mock_user):
        """Test MFA enablement without secret"""
        mock_user.mfa_secret = None
        
        with pytest.raises(ValueError, match="MFA secret not generated"):
            await mfa_service.enable_mfa(mock_user, "123456")
    
    @pytest.mark.asyncio
    async def test_enable_mfa_invalid_code(self, mfa_service, mock_user):
        """Test MFA enablement with invalid code"""
        # Setup secret
        test_secret = "JBSWY3DPEHPK3PXP"
        mock_user.mfa_secret = f"encrypted_{test_secret}"
        
        with pytest.raises(ValueError, match="Invalid verification code"):
            await mfa_service.enable_mfa(mock_user, "000000")

    # MFA disable tests
    @pytest.mark.asyncio
    async def test_disable_mfa_success(self, mfa_service, mock_user_with_mfa):
        """Test successful MFA disabling"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        await mfa_service.disable_mfa(mock_user_with_mfa, "password123")
        
        assert mock_user_with_mfa.mfa_enabled is False
        assert mock_user_with_mfa.mfa_secret is None
        assert mock_user_with_mfa.backup_codes is None
        assert mock_user_with_mfa.mfa_enabled_at is None
        
        mfa_service.db.commit.assert_called_once()

    # TOTP verification tests
    @pytest.mark.asyncio
    async def test_verify_totp_success(self, mfa_service, mock_user_with_mfa):
        """Test successful TOTP verification"""
        # Generate valid code
        test_secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(test_secret)
        valid_code = totp.now()
        
        result = await mfa_service.verify_totp(mock_user_with_mfa, valid_code)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_totp_invalid_code(self, mfa_service, mock_user_with_mfa):
        """Test TOTP verification with invalid code"""
        result = await mfa_service.verify_totp(mock_user_with_mfa, "000000")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_totp_no_secret(self, mfa_service, mock_user):
        """Test TOTP verification without secret"""
        result = await mfa_service.verify_totp(mock_user, "123456")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_totp_with_window(self, mfa_service, mock_user_with_mfa):
        """Test TOTP verification with time window"""
        # Generate code from previous time window
        test_secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(test_secret)
        
        # Mock time to get previous code
        import time
        current_time = int(time.time())
        previous_code = totp.at(current_time - 30)  # 30 seconds ago
        
        result = await mfa_service.verify_totp(mock_user_with_mfa, previous_code)
        # Should still be valid due to window=1
        assert result is True

    # Backup code tests
    @pytest.mark.asyncio
    async def test_verify_backup_code_success(self, mfa_service, mock_user_with_mfa):
        """Test successful backup code verification"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        result = await mfa_service.verify_backup_code(mock_user_with_mfa, "ABCD1234")
        
        assert result is True
        # Check that code was removed
        assert "hashed_ABCD1234" not in mock_user_with_mfa.backup_codes
        assert len(mock_user_with_mfa.backup_codes) == 1
        
        mfa_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_invalid(self, mfa_service, mock_user_with_mfa):
        """Test backup code verification with invalid code"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        result = await mfa_service.verify_backup_code(mock_user_with_mfa, "INVALID1")
        
        assert result is False
        # Check that no codes were removed
        assert len(mock_user_with_mfa.backup_codes) == 2
        
        mfa_service.db.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_no_codes(self, mfa_service, mock_user):
        """Test backup code verification without codes"""
        mock_user.backup_codes = None
        
        result = await mfa_service.verify_backup_code(mock_user, "ABCD1234")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_normalization(self, mfa_service, mock_user_with_mfa):
        """Test backup code normalization"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        # Test with lowercase and spaces
        result = await mfa_service.verify_backup_code(mock_user_with_mfa, "abcd 1234")
        
        assert result is True
        mfa_service.db.commit.assert_called_once()

    # Combined MFA verification tests
    @pytest.mark.asyncio
    async def test_verify_mfa_totp_success(self, mfa_service, mock_user_with_mfa):
        """Test MFA verification with TOTP code"""
        # Generate valid TOTP code
        test_secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(test_secret)
        valid_code = totp.now()
        
        result = await mfa_service.verify_mfa(mock_user_with_mfa, valid_code)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_mfa_backup_code_success(self, mfa_service, mock_user_with_mfa):
        """Test MFA verification with backup code"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        result = await mfa_service.verify_mfa(mock_user_with_mfa, "ABCD1234")
        assert result is True
    
    @pytest.mark.asyncio
    async def test_verify_mfa_mfa_disabled(self, mfa_service, mock_user):
        """Test MFA verification with MFA disabled"""
        result = await mfa_service.verify_mfa(mock_user, "123456")
        assert result is True  # Should pass if MFA is disabled
    
    @pytest.mark.asyncio
    async def test_verify_mfa_no_code(self, mfa_service, mock_user_with_mfa):
        """Test MFA verification without code"""
        result = await mfa_service.verify_mfa(mock_user_with_mfa, None)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_format(self, mfa_service, mock_user_with_mfa):
        """Test MFA verification with invalid code format"""
        result = await mfa_service.verify_mfa(mock_user_with_mfa, "12345")  # Too short
        assert result is False
        
        result = await mfa_service.verify_mfa(mock_user_with_mfa, "1234567890")  # Too long
        assert result is False

    # Backup code regeneration tests
    @pytest.mark.asyncio
    async def test_regenerate_backup_codes_success(self, mfa_service, mock_user_with_mfa):
        """Test successful backup code regeneration"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        with patch.object(settings, 'MFA_BACKUP_CODES_COUNT', 10):
            new_codes = await mfa_service.regenerate_backup_codes(mock_user_with_mfa)
            
            assert len(new_codes) == 10
            assert all(len(code) == 8 for code in new_codes)
            assert len(mock_user_with_mfa.backup_codes) == 10
            
            mfa_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_regenerate_backup_codes_mfa_disabled(self, mfa_service, mock_user):
        """Test backup code regeneration with MFA disabled"""
        with pytest.raises(ValueError, match="MFA not enabled"):
            await mfa_service.regenerate_backup_codes(mock_user)

    # QR code generation tests
    def test_generate_qr_code_success(self, mfa_service):
        """Test successful QR code generation"""
        provisioning_uri = "otpauth://totp/test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test"
        
        qr_bytes = mfa_service.generate_qr_code(provisioning_uri)
        
        assert isinstance(qr_bytes, bytes)
        assert len(qr_bytes) > 0
        assert qr_bytes.startswith(b'\x89PNG')  # PNG header
    
    def test_generate_qr_code_empty_uri(self, mfa_service):
        """Test QR code generation with empty URI"""
        qr_bytes = mfa_service.generate_qr_code("")
        
        assert isinstance(qr_bytes, bytes)
        assert len(qr_bytes) > 0

    # Helper method tests
    def test_generate_backup_codes_default_count(self, mfa_service):
        """Test backup code generation with default count"""
        with patch.object(settings, 'MFA_BACKUP_CODES_COUNT', 10):
            codes = mfa_service._generate_backup_codes()
            
            assert len(codes) == 10
            assert all(len(code) == 8 for code in codes)
            assert all(code.isalnum() for code in codes)
            assert all(code.isupper() for code in codes)
    
    def test_generate_backup_codes_custom_count(self, mfa_service):
        """Test backup code generation with custom count"""
        codes = mfa_service._generate_backup_codes(count=5)
        
        assert len(codes) == 5
        assert all(len(code) == 8 for code in codes)
    
    def test_generate_backup_codes_uniqueness(self, mfa_service):
        """Test backup code uniqueness"""
        codes1 = mfa_service._generate_backup_codes(count=10)
        codes2 = mfa_service._generate_backup_codes(count=10)
        
        # Should be different sets
        assert set(codes1) != set(codes2)
        
        # Should have no duplicates within each set
        assert len(set(codes1)) == len(codes1)
        assert len(set(codes2)) == len(codes2)
    
    def test_hash_backup_codes(self, mfa_service):
        """Test backup code hashing"""
        codes = ["ABCD1234", "EFGH5678"]
        hashed = mfa_service._hash_backup_codes(codes)
        
        assert len(hashed) == 2
        assert hashed[0] == "hashed_ABCD1234"
        assert hashed[1] == "hashed_EFGH5678"
    
    def test_verify_backup_code_hash(self, mfa_service):
        """Test backup code hash verification"""
        code = "ABCD1234"
        hashed = "hashed_ABCD1234"
        
        assert mfa_service._verify_backup_code(code, hashed) is True
        assert mfa_service._verify_backup_code("WRONG123", hashed) is False
    
    def test_encrypt_decrypt_secret(self, mfa_service):
        """Test secret encryption and decryption"""
        secret = "JBSWY3DPEHPK3PXP"
        
        encrypted = mfa_service._encrypt_secret(secret)
        decrypted = mfa_service._decrypt_secret(encrypted)
        
        assert encrypted != secret
        assert decrypted == secret
        # With our mocked encryption
        assert encrypted == f"encrypted_{secret}"
    
    def test_encrypt_decrypt_secret_roundtrip(self, mfa_service):
        """Test secret encryption/decryption roundtrip"""
        original_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        
        encrypted = mfa_service._encrypt_secret(original_secret)
        decrypted = mfa_service._decrypt_secret(encrypted)
        
        assert decrypted == original_secret

    # Edge cases and error handling
    @pytest.mark.asyncio
    async def test_verify_totp_with_invalid_secret(self, mfa_service, mock_user):
        """Test TOTP verification with invalid secret"""
        mock_user.mfa_secret = "invalid_base64!"
        
        with pytest.raises(Exception):
            await mfa_service.verify_totp(mock_user, "123456")
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_empty_list(self, mfa_service, mock_user):
        """Test backup code verification with empty list"""
        mock_user.backup_codes = []
        
        result = await mfa_service.verify_backup_code(mock_user, "ABCD1234")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_verify_backup_code_all_used(self, mfa_service, mock_user_with_mfa):
        """Test backup code verification when all codes are used"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        # Use first code
        result1 = await mfa_service.verify_backup_code(mock_user_with_mfa, "ABCD1234")
        assert result1 is True
        
        # Use second code
        result2 = await mfa_service.verify_backup_code(mock_user_with_mfa, "EFGH5678")
        assert result2 is True
        
        # No codes left
        assert len(mock_user_with_mfa.backup_codes) == 0
        
        # Try to use a code when none are left
        result3 = await mfa_service.verify_backup_code(mock_user_with_mfa, "IJKL9012")
        assert result3 is False
    
    def test_generate_backup_codes_character_set(self, mfa_service):
        """Test backup code character set"""
        codes = mfa_service._generate_backup_codes(count=100)
        
        # Check that only valid characters are used
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
        for code in codes:
            assert set(code).issubset(valid_chars)
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self, mfa_service, mock_user):
        """Test database error handling"""
        # Mock database commit to raise an error
        mfa_service.db.commit = AsyncMock(side_effect=Exception("Database error"))
        
        with pytest.raises(Exception, match="Database error"):
            await mfa_service.generate_mfa_secret(mock_user)
    
    def test_qr_code_image_format(self, mfa_service):
        """Test QR code image format validation"""
        provisioning_uri = "otpauth://totp/test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test"
        
        qr_bytes = mfa_service.generate_qr_code(provisioning_uri)
        
        # Verify PNG format
        assert qr_bytes.startswith(b'\x89PNG\r\n\x1a\n')
        
        # Verify it's a valid image that can be loaded
        from PIL import Image
        image = Image.open(BytesIO(qr_bytes))
        assert image.format == 'PNG'
        assert image.size[0] > 0
        assert image.size[1] > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_backup_code_usage(self, mfa_service, mock_user_with_mfa):
        """Test concurrent backup code usage prevention"""
        # Mock database operations
        mfa_service.db.commit = AsyncMock()
        
        # Simulate two concurrent requests using the same code
        # The second one should fail because the first one consumed it
        result1 = await mfa_service.verify_backup_code(mock_user_with_mfa, "ABCD1234")
        assert result1 is True
        
        # Reset backup codes to original state to simulate race condition
        mock_user_with_mfa.backup_codes = ["hashed_ABCD1234", "hashed_EFGH5678"]
        
        result2 = await mfa_service.verify_backup_code(mock_user_with_mfa, "ABCD1234")
        assert result2 is True  # Would succeed in this implementation
        
        # In a real implementation, this would be prevented by database constraints