"""
Comprehensive unit tests for validators and input sanitization
"""
import pytest
from unittest.mock import patch

from core.validators import (
    validate_username,
    validate_email,
    validate_password,
    validate_mfa_code,
    validate_full_name,
    sanitize_string,
    USERNAME_REGEX,
    EMAIL_REGEX,
    PASSWORD_SPECIAL_CHARS
)
from core.config import settings


class TestValidators:
    """Test validation functions"""

    # Username validation tests
    def test_validate_username_valid(self):
        """Test valid usernames"""
        valid_usernames = [
            "testuser",
            "test_user",
            "test-user",
            "user123",
            "abc",  # Minimum length
            "a" * 32,  # Maximum length
            "user_name_123",
            "test-user-name"
        ]
        
        for username in valid_usernames:
            result = validate_username(username)
            assert result == username
    
    def test_validate_username_invalid_length(self):
        """Test usernames with invalid length"""
        # Too short
        with pytest.raises(ValueError, match="Username must be 3-32 characters"):
            validate_username("ab")
        
        # Too long
        with pytest.raises(ValueError, match="Username must be 3-32 characters"):
            validate_username("a" * 33)
    
    def test_validate_username_invalid_characters(self):
        """Test usernames with invalid characters"""
        invalid_usernames = [
            "user@name",    # @ symbol
            "user name",    # Space
            "user.name",    # Dot
            "user+name",    # Plus
            "user#name",    # Hash
            "user$name",    # Dollar
            "user%name",    # Percent
            "user!name",    # Exclamation
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValueError, match="Username must be 3-32 characters"):
                validate_username(username)
    
    def test_validate_username_starts_with_number(self):
        """Test usernames starting with numbers"""
        invalid_usernames = [
            "123user",
            "9testuser",
            "0username"
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValueError, match="Username cannot start with a number"):
                validate_username(username)
    
    def test_validate_username_reserved(self):
        """Test reserved usernames"""
        reserved_usernames = [
            "admin", "Admin", "ADMIN",
            "root", "Root", "ROOT",
            "system", "System", "SYSTEM",
            "administrator", "Administrator",
            "operator", "Operator"
        ]
        
        for username in reserved_usernames:
            with pytest.raises(ValueError, match="This username is reserved"):
                validate_username(username)
    
    def test_validate_username_edge_cases(self):
        """Test username edge cases"""
        # Valid edge cases
        assert validate_username("a_b") == "a_b"  # Minimum with underscore
        assert validate_username("a-b") == "a-b"  # Minimum with hyphen
        assert validate_username("_ab") == "_ab"  # Starting with underscore
        assert validate_username("-ab") == "-ab"  # Starting with hyphen
        
        # Numbers in middle/end are OK
        assert validate_username("user1") == "user1"
        assert validate_username("user123") == "user123"
        assert validate_username("u1s2e3r") == "u1s2e3r"

    # Email validation tests
    def test_validate_email_valid(self):
        """Test valid email addresses"""
        valid_emails = [
            "user@example.com",
            "test.user@example.com",
            "user+tag@example.com",
            "user_name@example.com",
            "user123@example123.com",
            "a@b.co",  # Minimum valid email
            "user@sub.example.com",
            "user@example-domain.com"
        ]
        
        for email in valid_emails:
            result = validate_email(email)
            assert result == email.lower()
    
    def test_validate_email_invalid_format(self):
        """Test invalid email formats"""
        invalid_emails = [
            "invalid",
            "invalid@",
            "@invalid.com",
            "invalid.com",
            "user@@example.com",
            "user@example",
            "user@.com",
            "user@example.",
            "",
            "user space@example.com"
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValueError, match="Invalid email format"):
                validate_email(email)
    
    def test_validate_email_consecutive_dots(self):
        """Test emails with consecutive dots"""
        invalid_emails = [
            "user..name@example.com",
            "user@example..com",
            "user.@example.com",
            ".user@example.com"
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValueError):
                validate_email(email)
    
    def test_validate_email_domain_too_long(self):
        """Test emails with domain too long"""
        # Create a domain longer than 253 characters
        long_domain = "a" * 250 + ".com"
        email = f"user@{long_domain}"
        
        with pytest.raises(ValueError, match="Email domain is too long"):
            validate_email(email)
    
    def test_validate_email_case_normalization(self):
        """Test email case normalization"""
        emails = [
            ("User@Example.Com", "user@example.com"),
            ("TEST@EXAMPLE.COM", "test@example.com"),
            ("MixedCase@Domain.ORG", "mixedcase@domain.org")
        ]
        
        for input_email, expected in emails:
            result = validate_email(input_email)
            assert result == expected

    # Password validation tests
    def test_validate_password_valid(self):
        """Test valid passwords"""
        # Mock settings for consistent testing
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', True):
                with patch.object(settings, 'PASSWORD_REQUIRE_LOWERCASE', True):
                    with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', True):
                        with patch.object(settings, 'PASSWORD_REQUIRE_SPECIAL', True):
                            
                            valid_passwords = [
                                "TestPass123!",
                                "MySecure@Pass1",
                                "Complex$Password9",
                                "Valid#123ABC",
                                "StrongP@ssw0rd"
                            ]
                            
                            for password in valid_passwords:
                                result = validate_password(password)
                                assert result == password
    
    def test_validate_password_too_short(self):
        """Test passwords that are too short"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with pytest.raises(ValueError, match="Password must be at least 8 characters"):
                validate_password("Short1!")
    
    def test_validate_password_too_long(self):
        """Test passwords that are too long"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            long_password = "A" * 129 + "1!"
            with pytest.raises(ValueError, match="Password must not exceed 128 characters"):
                validate_password(long_password)
    
    def test_validate_password_missing_uppercase(self):
        """Test passwords missing uppercase letters"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', True):
                with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
                    validate_password("lowercase123!")
    
    def test_validate_password_missing_lowercase(self):
        """Test passwords missing lowercase letters"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_LOWERCASE', True):
                with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
                    validate_password("UPPERCASE123!")
    
    def test_validate_password_missing_digits(self):
        """Test passwords missing digits"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', True):
                with pytest.raises(ValueError, match="Password must contain at least one digit"):
                    validate_password("NoDigitsHere!")
    
    def test_validate_password_missing_special(self):
        """Test passwords missing special characters"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_SPECIAL', True):
                with pytest.raises(ValueError, match="Password must contain at least one special character"):
                    validate_password("NoSpecialChars123")
    
    def test_validate_password_common_patterns(self):
        """Test passwords with common patterns"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.dict('os.environ', {'PASSWORD_COMMON_PATTERNS_LIST': 'password,123456,qwerty,abc123'}):
                # Test with PASSWORD_COMMON_PATTERNS enabled
                common_passwords = [
                    "Password1",     # Starts with "password" (9 chars)
                    "Qwerty1!",      # Starts with "qwerty" (9 chars)
                    "Abc123!",       # Starts with "abc123" (7 chars)  
                    "Password!",     # Starts with "password" (9 chars)
                    "123456A!",      # Starts with "123456" (9 chars)
                ]
                
                for password in common_passwords:
                    with pytest.raises(ValueError, match="Password contains common patterns"):
                        validate_password(password)
    
    def test_validate_password_multiple_errors(self):
        """Test passwords with multiple validation errors"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', True):
                with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', True):
                    
                    with pytest.raises(ValueError) as exc_info:
                        validate_password("short")  # Too short, no uppercase, no digits
                    
                    error_message = str(exc_info.value)
                    assert "at least 8 characters" in error_message
                    assert "uppercase letter" in error_message
                    assert "digit" in error_message
    
    def test_validate_password_requirements_disabled(self):
        """Test password validation with requirements disabled"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 6):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', False):
                with patch.object(settings, 'PASSWORD_REQUIRE_LOWERCASE', False):
                    with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', False):
                        with patch.object(settings, 'PASSWORD_REQUIRE_SPECIAL', False):
                            
                            # Should pass with minimal requirements
                            result = validate_password("simple")
                            assert result == "simple"

    # MFA code validation tests
    def test_validate_mfa_code_totp(self):
        """Test valid TOTP codes"""
        valid_totp_codes = [
            "123456",
            "000000",
            "999999",
            "654321"
        ]
        
        for code in valid_totp_codes:
            result = validate_mfa_code(code)
            assert result == code
    
    def test_validate_mfa_code_backup(self):
        """Test valid backup codes"""
        valid_backup_codes = [
            "ABCD1234",
            "abcd1234",  # Should be converted to uppercase
            "XYZ98765",
            "12345678"
        ]
        
        expected_results = [
            "ABCD1234",
            "ABCD1234",  # Converted to uppercase
            "XYZ98765",
            "12345678"
        ]
        
        for code, expected in zip(valid_backup_codes, expected_results):
            result = validate_mfa_code(code)
            assert result == expected
    
    def test_validate_mfa_code_with_spaces(self):
        """Test MFA codes with spaces"""
        codes_with_spaces = [
            "123 456",    # TOTP with space
            "ABCD 1234",  # Backup code with space
            " 123456 ",   # TOTP with surrounding spaces
            " ABCD1234 "  # Backup code with surrounding spaces
        ]
        
        expected_results = [
            "123456",
            "ABCD1234",
            "123456",
            "ABCD1234"
        ]
        
        for code, expected in zip(codes_with_spaces, expected_results):
            result = validate_mfa_code(code)
            assert result == expected
    
    def test_validate_mfa_code_invalid(self):
        """Test invalid MFA codes"""
        invalid_codes = [
            "12345",      # Too short for TOTP
            "ABCD@234",   # Special character in backup
            "abc",        # Too short
            "12345678901" # Too long (more than 10 characters)
        ]
        
        for code in invalid_codes:
            with pytest.raises(ValueError, match="Invalid MFA code format"):
                validate_mfa_code(code)
    
    def test_validate_mfa_code_none(self):
        """Test MFA code validation with None"""
        result = validate_mfa_code(None)
        assert result is None
    
    def test_validate_mfa_code_empty_string(self):
        """Test MFA code validation with empty string"""
        result = validate_mfa_code("")
        assert result is None

    # Full name validation tests
    def test_validate_full_name_valid(self):
        """Test valid full names"""
        valid_names = [
            "John Doe",
            "Mary Jane Smith",
            "José García",
            "O'Connor",
            "Anne-Marie",
            "Jean-Luc Picard",
            "Dr. Smith",
            "Mary Jo",
            "Al",  # Minimum length
            "A" * 100  # Maximum length
        ]
        
        for name in valid_names:
            result = validate_full_name(name)
            assert result == name
    
    def test_validate_full_name_none_empty(self):
        """Test full name validation with None and empty values"""
        assert validate_full_name(None) is None
        assert validate_full_name("") is None
        assert validate_full_name("   ") is None  # Whitespace only
    
    def test_validate_full_name_too_short(self):
        """Test full names that are too short"""
        with pytest.raises(ValueError, match="Name must be at least 2 characters"):
            validate_full_name("A")
    
    def test_validate_full_name_too_long(self):
        """Test full names that are too long"""
        long_name = "A" * 101
        with pytest.raises(ValueError, match="Name must not exceed 100 characters"):
            validate_full_name(long_name)
    
    def test_validate_full_name_invalid_characters(self):
        """Test full names with invalid characters"""
        invalid_names = [
            "John@Doe",
            "Mary123",
            "User#Name",
            "Name$",
            "Test%User",
            "User&Name",
            "Name*",
            "User+Name",
            "Name=Value",
            "User/Name",
            "Name\\User",
            "User|Name",
            "Name?",
            "User<Name>",
            "Name[Bracket]",
            "User{Name}",
            "Name;Semicolon",
            "User:Colon"
        ]
        
        for name in invalid_names:
            with pytest.raises(ValueError, match="Name contains invalid characters"):
                validate_full_name(name)
    
    def test_validate_full_name_whitespace_handling(self):
        """Test full name whitespace handling"""
        names_with_whitespace = [
            ("  John Doe  ", "John Doe"),
            ("\tMary Smith\t", "Mary Smith"),
            ("\nTest User\n", "Test User"),
            ("   Spaced   Name   ", "Spaced   Name")  # Internal spaces preserved
        ]
        
        for input_name, expected in names_with_whitespace:
            result = validate_full_name(input_name)
            assert result == expected

    # String sanitization tests
    def test_sanitize_string_basic(self):
        """Test basic string sanitization"""
        test_cases = [
            ("normal text", "normal text"),
            ("", ""),
            ("   spaced text   ", "spaced text"),
            ("text with\ttab", "text with\ttab"),  # Tabs preserved
            ("text with\nnewline", "text with\nnewline"),  # Newlines preserved
            ("text with\rcarriage", "text with\rcarriage")  # CR preserved
        ]
        
        for input_str, expected in test_cases:
            result = sanitize_string(input_str)
            assert result == expected
    
    def test_sanitize_string_control_characters(self):
        """Test sanitization of control characters"""
        # Create string with control characters (ASCII 0-31 except \t, \n, \r)
        input_str = "text\x00with\x01control\x02chars"
        result = sanitize_string(input_str)
        assert result == "textwithcontrolchars"
    
    def test_sanitize_string_sql_injection(self):
        """Test SQL injection pattern removal"""
        dangerous_inputs = [
            "SELECT * FROM users --",
            "'; DROP TABLE users; --",
            "UNION SELECT password FROM users",
            "exec master..xp_cmdshell",
            "sp_configure",
            "/* comment */ SELECT",
            "UPDATE users SET",
            "DELETE FROM table",
            "INSERT INTO users"
        ]
        
        for dangerous_input in dangerous_inputs:
            result = sanitize_string(dangerous_input)
            # Should remove dangerous patterns
            result_lower = result.lower()
            assert "--" not in result_lower
            assert "/*" not in result_lower
            assert "*/" not in result_lower
            assert "select" not in result_lower
            assert "union" not in result_lower
            assert "exec" not in result_lower
            assert "sp_" not in result_lower
            assert "xp_" not in result_lower
    
    def test_sanitize_string_xss_patterns(self):
        """Test XSS pattern removal"""
        xss_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "vbscript:msgbox('xss')",
            "onload=alert('xss')",
            "onerror=alert('xss')",
            "<img onload=alert('xss')>"
        ]
        
        for xss_input in xss_inputs:
            result = sanitize_string(xss_input)
            result_lower = result.lower()
            assert "script" not in result_lower
            assert "javascript:" not in result_lower
            assert "vbscript:" not in result_lower
            assert "onload=" not in result_lower
            assert "onerror=" not in result_lower
    
    def test_sanitize_string_length_limit(self):
        """Test string length limiting"""
        long_string = "A" * 300
        
        # Test default max length (255)
        result = sanitize_string(long_string)
        assert len(result) == 255
        
        # Test custom max length
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100
        
        # Test shorter string
        short_string = "short"
        result = sanitize_string(short_string, max_length=100)
        assert result == "short"
    
    def test_sanitize_string_none_empty(self):
        """Test sanitization with None and empty values"""
        assert sanitize_string("") == ""
        assert sanitize_string(None) is None
    
    def test_sanitize_string_case_preservation(self):
        """Test that sanitization preserves case for safe content"""
        input_str = "Mixed Case Content"
        result = sanitize_string(input_str)
        assert result == "Mixed Case Content"
    
    def test_sanitize_string_complex_attack(self):
        """Test complex attack string sanitization"""
        complex_attack = (
            "'; DROP TABLE users; --<script>alert('xss')</script>"
            "UNION SELECT * FROM passwords/*comment*/javascript:alert(1)"
        )
        
        result = sanitize_string(complex_attack)
        
        # Should remove all dangerous patterns
        result_lower = result.lower()
        dangerous_patterns = [
            "--", "/*", "*/", "select", "union", "drop", "script",
            "javascript:", "alert"
        ]
        
        for pattern in dangerous_patterns:
            assert pattern not in result_lower

    # Regex pattern tests
    def test_username_regex_pattern(self):
        """Test USERNAME_REGEX pattern directly"""
        valid_matches = [
            "abc", "user123", "test_user", "test-user", "a" * 32
        ]
        invalid_matches = [
            "ab", "a" * 33, "user@name", "user name", "user.name"
        ]
        
        for username in valid_matches:
            assert USERNAME_REGEX.match(username) is not None
        
        for username in invalid_matches:
            assert USERNAME_REGEX.match(username) is None
    
    def test_email_regex_pattern(self):
        """Test EMAIL_REGEX pattern directly"""
        valid_matches = [
            "user@example.com", "test.user@domain.org", "user+tag@site.net"
        ]
        invalid_matches = [
            "invalid", "user@", "@domain.com", "user@@domain.com"
        ]
        
        for email in valid_matches:
            assert EMAIL_REGEX.match(email) is not None
        
        for email in invalid_matches:
            assert EMAIL_REGEX.match(email) is None
    
    def test_password_special_chars_regex(self):
        """Test PASSWORD_SPECIAL_CHARS regex pattern"""
        strings_with_special = [
            "password!", "test@email", "user#tag", "pass$word",
            "test%value", "pass^word", "test&value", "pass*word",
            "test()", "pass,word", "test.value", "pass?word",
            'test"quote', "test:value", "pass{word}", "test|value",
            "pass<word>", "pass[word]"
        ]
        
        strings_without_special = [
            "password", "test123", "userABC", "NoSpecialChars",
            "OnlyAlphaNumeric123", "UPPERCASE", "lowercase"
        ]
        
        for string in strings_with_special:
            assert PASSWORD_SPECIAL_CHARS.search(string) is not None
        
        for string in strings_without_special:
            assert PASSWORD_SPECIAL_CHARS.search(string) is None

    # Integration and edge cases
    def test_all_validators_with_extreme_inputs(self):
        """Test all validators with extreme inputs"""
        extreme_inputs = [
            "",
            " ",
            "\t",
            "\n",
            "\r",
            "\x00",
            "A" * 1000,
            "🚀🌟💫",  # Unicode emoji
            "Привет",   # Cyrillic
            "こんにちは", # Japanese
            "مرحبا",    # Arabic
        ]
        
        # Most should raise ValueError for username
        for input_str in extreme_inputs:
            if input_str and len(input_str) >= 3:
                try:
                    validate_username(input_str)
                except ValueError:
                    pass  # Expected for most inputs
        
        # Most should raise ValueError for email
        for input_str in extreme_inputs:
            try:
                validate_email(input_str)
            except ValueError:
                pass  # Expected for most inputs
        
        # Test sanitize_string handles all gracefully
        for input_str in extreme_inputs:
            try:
                result = sanitize_string(input_str)
                assert isinstance(result, (str, type(None)))
            except Exception as e:
                pytest.fail(f"sanitize_string failed on input '{input_str}': {e}")
    
    def test_validator_consistency(self):
        """Test validator consistency across similar inputs"""
        # Test that similar valid inputs are handled consistently
        similar_usernames = ["testuser1", "testuser2", "testuser3"]
        for username in similar_usernames:
            result = validate_username(username)
            assert result == username
        
        similar_emails = [
            "user1@example.com",
            "user2@example.com", 
            "user3@example.com"
        ]
        for email in similar_emails:
            result = validate_email(email)
            assert result == email.lower()
        
        # Test that similar invalid inputs fail consistently
        invalid_usernames = ["us", "u$", "u@"]  # All too short or invalid chars
        for username in invalid_usernames:
            with pytest.raises(ValueError):
                validate_username(username)