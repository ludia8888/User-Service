"""
Unit tests for validators
"""
import pytest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.validators import (
    validate_username, validate_email, validate_password,
    validate_mfa_code, validate_full_name, sanitize_string
)


class TestValidators:
    """Test input validators"""
    
    def test_validate_username_success(self):
        """Test valid usernames"""
        assert validate_username("john_doe") == "john_doe"
        assert validate_username("user123") == "user123"
        assert validate_username("test-user") == "test-user"
    
    def test_validate_username_too_short(self):
        """Test username too short"""
        with pytest.raises(ValueError) as exc:
            validate_username("ab")
        assert "3-32 characters" in str(exc.value)
    
    def test_validate_username_invalid_chars(self):
        """Test username with invalid characters"""
        with pytest.raises(ValueError) as exc:
            validate_username("user@name")
        assert "letters, numbers, underscores, and hyphens" in str(exc.value)
    
    def test_validate_username_starts_with_number(self):
        """Test username starting with number"""
        with pytest.raises(ValueError) as exc:
            validate_username("123user")
        assert "cannot start with a number" in str(exc.value)
    
    def test_validate_username_reserved(self):
        """Test reserved usernames"""
        with pytest.raises(ValueError) as exc:
            validate_username("admin")
        assert "reserved" in str(exc.value)
    
    def test_validate_email_success(self):
        """Test valid emails"""
        assert validate_email("user@example.com") == "user@example.com"
        assert validate_email("USER@EXAMPLE.COM") == "user@example.com"  # Lowercase
        assert validate_email("test.user+tag@example.co.uk") == "test.user+tag@example.co.uk"
    
    def test_validate_email_invalid(self):
        """Test invalid emails"""
        with pytest.raises(ValueError) as exc:
            validate_email("invalid-email")
        assert "Invalid email format" in str(exc.value)
        
        with pytest.raises(ValueError) as exc:
            validate_email("user@.com")
        assert "Invalid email format" in str(exc.value)
    
    def test_validate_email_consecutive_dots(self):
        """Test email with consecutive dots"""
        with pytest.raises(ValueError) as exc:
            validate_email("user..name@example.com")
        assert "consecutive dots" in str(exc.value)
    
    def test_validate_password_success(self):
        """Test valid passwords"""
        assert validate_password("SecureP@ssw0rd") == "SecureP@ssw0rd"
        assert validate_password("Str0ng!Pass") == "Str0ng!Pass"
    
    def test_validate_password_too_short(self):
        """Test password too short"""
        with pytest.raises(ValueError) as exc:
            validate_password("Short1!")
        assert "at least 8 characters" in str(exc.value)
    
    def test_validate_password_no_uppercase(self):
        """Test password without uppercase"""
        with pytest.raises(ValueError) as exc:
            validate_password("password123!")
        assert "uppercase letter" in str(exc.value)
    
    def test_validate_password_no_lowercase(self):
        """Test password without lowercase"""
        with pytest.raises(ValueError) as exc:
            validate_password("PASSWORD123!")
        assert "lowercase letter" in str(exc.value)
    
    def test_validate_password_no_digit(self):
        """Test password without digit"""
        with pytest.raises(ValueError) as exc:
            validate_password("Password!")
        assert "one digit" in str(exc.value)
    
    def test_validate_password_no_special(self):
        """Test password without special character"""
        with pytest.raises(ValueError) as exc:
            validate_password("Password123")
        assert "special character" in str(exc.value)
    
    def test_validate_password_common_pattern(self):
        """Test password with common patterns"""
        with pytest.raises(ValueError) as exc:
            validate_password("Password123!")
        assert "common patterns" in str(exc.value)
    
    def test_validate_mfa_code_totp(self):
        """Test valid TOTP codes"""
        assert validate_mfa_code("123456") == "123456"
        assert validate_mfa_code("000000") == "000000"
    
    def test_validate_mfa_code_backup(self):
        """Test valid backup codes"""
        assert validate_mfa_code("ABC12345") == "ABC12345"
        assert validate_mfa_code("abc12345") == "ABC12345"  # Uppercase
    
    def test_validate_mfa_code_invalid(self):
        """Test invalid MFA codes"""
        with pytest.raises(ValueError):
            validate_mfa_code("12345")  # Too short
        
        with pytest.raises(ValueError):
            validate_mfa_code("1234567")  # Too long for TOTP
        
        with pytest.raises(ValueError):
            validate_mfa_code("ABCD!123")  # Invalid characters
    
    def test_validate_full_name(self):
        """Test full name validation"""
        assert validate_full_name("John Doe") == "John Doe"
        assert validate_full_name("Mary-Jane O'Brien") == "Mary-Jane O'Brien"
        assert validate_full_name(None) is None
    
    def test_validate_full_name_too_short(self):
        """Test name too short"""
        with pytest.raises(ValueError) as exc:
            validate_full_name("J")
        assert "at least 2 characters" in str(exc.value)
    
    def test_validate_full_name_invalid_chars(self):
        """Test name with invalid characters"""
        with pytest.raises(ValueError) as exc:
            validate_full_name("John@Doe")
        assert "invalid characters" in str(exc.value)
    
    def test_sanitize_string(self):
        """Test string sanitization"""
        assert sanitize_string("  test  ") == "test"
        assert sanitize_string("test\x00null") == "testnull"
        assert sanitize_string("a" * 300, max_length=255) == "a" * 255


if __name__ == "__main__":
    pytest.main([__file__, "-v"])