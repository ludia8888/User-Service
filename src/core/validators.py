"""
Input validation utilities
"""
import re
from typing import Optional
from pydantic import validator, constr, conint

from .config import settings


# Regular expressions for validation
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PASSWORD_SPECIAL_CHARS = re.compile(r"[!@#$%^&*(),.?\":{}|<>\[\]]")


def validate_username(username: str) -> str:
    """
    Validate username format
    
    Rules:
    - 3-32 characters
    - Only alphanumeric, underscore, and hyphen
    - Cannot start with number
    """
    if not USERNAME_REGEX.match(username):
        raise ValueError(
            "Username must be 3-32 characters and contain only letters, "
            "numbers, underscores, and hyphens"
        )
    
    if username[0].isdigit():
        raise ValueError("Username cannot start with a number")
    
    # Check for reserved usernames
    reserved = ["admin", "root", "system", "administrator", "operator"]
    if username.lower() in reserved:
        raise ValueError("This username is reserved")
    
    return username


def validate_email(email: str) -> str:
    """
    Validate email format
    """
    # Check for consecutive dots first
    if ".." in email:
        raise ValueError("Email cannot contain consecutive dots")
    
    # Check for leading/trailing dots in local part
    if email.startswith('.') or '@.' in email or '.@' in email:
        raise ValueError("Invalid email format")
    
    if not EMAIL_REGEX.match(email):
        raise ValueError("Invalid email format")
    
    # Check domain
    domain = email.split("@")[1]
    if len(domain) > 253:
        raise ValueError("Email domain is too long")
    
    return email.lower()


def validate_password(password: str) -> str:
    """
    Validate password strength based on configuration
    """
    errors = []
    
    # Length check
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    
    if len(password) > 128:
        errors.append("Password must not exceed 128 characters")
    
    # Complexity checks
    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if settings.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    
    if settings.PASSWORD_REQUIRE_SPECIAL and not PASSWORD_SPECIAL_CHARS.search(password):
        errors.append("Password must contain at least one special character")
    
    # Common patterns check (configurable for testing)
    # Check for exact matches or complete words, not substrings
    import os
    patterns_env = os.environ.get('PASSWORD_COMMON_PATTERNS_LIST', '')
    if patterns_env:
        common_patterns = [p.strip() for p in patterns_env.split(',') if p.strip()]
    else:
        common_patterns = getattr(settings, 'PASSWORD_COMMON_PATTERNS', ["password", "123456", "qwerty", "abc123"])
    
    if common_patterns:  # Only check if patterns are defined
        password_lower = password.lower()
        for pattern in common_patterns:
            # Only flag if the pattern is a complete word or the entire password
            if password_lower == pattern or (len(pattern) >= 4 and password_lower.startswith(pattern) and len(password_lower) <= len(pattern) + 2):
                errors.append("Password contains common patterns")
                break
    
    if errors:
        raise ValueError("; ".join(errors))
    
    return password


def validate_mfa_code(code: Optional[str]) -> Optional[str]:
    """
    Validate MFA code format
    """
    if not code:
        return None
    
    # Remove spaces
    code = code.replace(" ", "")
    
    # Empty after stripping spaces
    if not code:
        raise ValueError("Invalid MFA code format")
    
    # Check if it's a 6-digit TOTP code
    if len(code) == 6 and code.isdigit():
        return code
    
    # Check if it's a backup code (6-10 alphanumeric characters)
    if 6 <= len(code) <= 10 and code.isalnum():
        return code.upper()
    
    raise ValueError("Invalid MFA code format")


def validate_full_name(name: Optional[str]) -> Optional[str]:
    """
    Validate full name
    """
    if not name:
        return None
    
    name = name.strip()
    
    if not name:  # Empty after stripping
        return None
    
    if len(name) < 2:
        raise ValueError("Name must be at least 2 characters")
    
    if len(name) > 100:
        raise ValueError("Name must not exceed 100 characters")
    
    # Check for valid characters (letters, spaces, hyphens, apostrophes, periods)
    if not re.match(r"^[a-zA-ZÀ-ÿ\u0100-\u017F\u0180-\u024F\s\-'.]+$", name):
        raise ValueError("Name contains invalid characters")
    
    return name


def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Sanitize string input to prevent injection attacks
    """
    if not value:
        return value
    
    # Remove null bytes and control characters
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
    
    # Remove potential SQL injection and XSS patterns
    dangerous_patterns = [
        '--', '/*', '*/', 'xp_', 'sp_', 'exec', 'execute',
        'select', 'insert', 'update', 'delete', 'drop', 'union',
        'script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
        'alert', 'document', 'window', 'eval'
    ]
    
    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            # Remove both lowercase and uppercase versions
            value = value.replace(pattern, '').replace(pattern.upper(), '').replace(pattern.capitalize(), '')
    
    # Trim whitespace
    value = value.strip()
    
    # Limit length
    if len(value) > max_length:
        value = value[:max_length]
    
    return value