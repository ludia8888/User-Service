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
PASSWORD_SPECIAL_CHARS = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")


class UsernameStr(constr):
    """Username string type with validation"""
    min_length = 3
    max_length = 32
    regex = USERNAME_REGEX


class PasswordStr(constr):
    """Password string type"""
    min_length = settings.PASSWORD_MIN_LENGTH
    max_length = 128


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
    if not EMAIL_REGEX.match(email):
        raise ValueError("Invalid email format")
    
    # Additional checks
    if ".." in email:
        raise ValueError("Email cannot contain consecutive dots")
    
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
    
    # Common patterns check
    common_patterns = ["password", "123456", "qwerty", "abc123", "password123"]
    if any(pattern in password.lower() for pattern in common_patterns):
        errors.append("Password contains common patterns")
    
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
    
    # Check if it's a 6-digit TOTP code
    if len(code) == 6 and code.isdigit():
        return code
    
    # Check if it's a backup code (8 alphanumeric)
    if len(code) == 8 and code.isalnum():
        return code.upper()
    
    raise ValueError("Invalid MFA code format")


def validate_full_name(name: Optional[str]) -> Optional[str]:
    """
    Validate full name
    """
    if not name:
        return None
    
    name = name.strip()
    
    if len(name) < 2:
        raise ValueError("Name must be at least 2 characters")
    
    if len(name) > 100:
        raise ValueError("Name must not exceed 100 characters")
    
    # Check for valid characters
    if not re.match(r"^[a-zA-Z\s\-'.]+$", name):
        raise ValueError("Name contains invalid characters")
    
    return name


def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Sanitize string input
    """
    # Remove null bytes
    value = value.replace("\x00", "")
    
    # Trim whitespace
    value = value.strip()
    
    # Limit length
    if len(value) > max_length:
        value = value[:max_length]
    
    return value