"""
Password security tests
"""
import pytest
from passlib.context import CryptContext
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Set test environment
os.environ['DEBUG'] = 'true'

from core.config import settings


class TestPasswordSecurity:
    """Test password hashing and verification"""
    
    def setup_method(self):
        """Setup test password context"""
        self.pwd_context = CryptContext(
            schemes=["argon2", "bcrypt"],
            default="argon2",
            deprecated="auto"
        )
    
    def test_password_hash_verification(self):
        """Test password hashing and verification"""
        password = "SecureP@ssw0rd123"
        
        # Hash password
        hashed = self.pwd_context.hash(password)
        assert hashed != password
        assert len(hashed) > 50  # Hashed passwords are long
        
        # Verify correct password
        assert self.pwd_context.verify(password, hashed) is True
        
        # Verify wrong password
        assert self.pwd_context.verify("WrongPassword", hashed) is False
    
    def test_password_hash_uniqueness(self):
        """Test that same password produces different hashes"""
        password = "SecureP@ssw0rd123"
        
        # Hash same password twice
        hash1 = self.pwd_context.hash(password)
        hash2 = self.pwd_context.hash(password)
        
        # Hashes should be different (due to salt)
        assert hash1 != hash2
        
        # But both should verify correctly
        assert self.pwd_context.verify(password, hash1) is True
        assert self.pwd_context.verify(password, hash2) is True
    
    def test_argon2_hash_format(self):
        """Test Argon2 hash format"""
        password = "TestPassword123!"
        
        # Force Argon2 scheme
        argon2_context = CryptContext(schemes=["argon2"], deprecated="auto")
        hashed = argon2_context.hash(password)
        
        # Argon2 hashes start with $argon2
        assert hashed.startswith("$argon2")
        assert argon2_context.verify(password, hashed) is True
    
    def test_bcrypt_fallback(self):
        """Test bcrypt fallback compatibility"""
        password = "TestPassword123!"
        
        # Create bcrypt hash
        bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        bcrypt_hash = bcrypt_context.hash(password)
        
        # Verify with multi-scheme context
        assert self.pwd_context.verify(password, bcrypt_hash) is True
    
    def test_password_needs_rehash(self):
        """Test password rehashing detection"""
        password = "TestPassword123!"
        
        # Create bcrypt hash
        bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        old_hash = bcrypt_context.hash(password)
        
        # Check if needs rehash (bcrypt -> argon2)
        needs_rehash = self.pwd_context.needs_update(old_hash)
        assert needs_rehash is True
        
        # Create new argon2 hash
        new_hash = self.pwd_context.hash(password)
        needs_rehash = self.pwd_context.needs_update(new_hash)
        assert needs_rehash is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])