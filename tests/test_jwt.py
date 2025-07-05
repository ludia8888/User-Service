"""
JWT token tests
"""
import pytest
import jwt
from datetime import datetime, timedelta, timezone
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Set test environment
os.environ['DEBUG'] = 'true'
os.environ['JWT_SECRET'] = 'test-secret-key-for-testing-purposes-only-32chars'

from core.config import settings


class TestJWT:
    """Test JWT functionality"""
    
    def test_jwt_encode_decode(self):
        """Test JWT encoding and decoding"""
        payload = {
            "sub": "user123",
            "username": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        }
        
        # Encode
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        assert isinstance(token, str)
        
        # Decode
        decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        assert decoded["sub"] == "user123"
        assert decoded["username"] == "testuser"
    
    def test_jwt_expired_token(self):
        """Test expired JWT token"""
        payload = {
            "sub": "user123",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1)  # Already expired
        }
        
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    
    def test_jwt_invalid_signature(self):
        """Test JWT with invalid signature"""
        payload = {
            "sub": "user123",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        }
        
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        
        # Try to decode with wrong secret
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(token, "wrong-secret", algorithms=[settings.JWT_ALGORITHM])
    
    def test_jwt_invalid_token_format(self):
        """Test invalid JWT token format"""
        with pytest.raises(jwt.DecodeError):
            jwt.decode("invalid.token.format", settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    
    def test_jwt_missing_required_claims(self):
        """Test JWT validation with required claims"""
        payload = {
            "username": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
            # Missing 'sub' claim
        }
        
        token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        
        # Decode with required claims
        with pytest.raises(jwt.MissingRequiredClaimError):
            jwt.decode(
                token, 
                settings.JWT_SECRET, 
                algorithms=[settings.JWT_ALGORITHM],
                options={"require": ["sub", "exp"]}
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])