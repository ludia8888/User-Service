"""
Comprehensive unit tests for AuthService
"""
import pytest
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from services.auth_service import AuthService
from models.user import User, UserStatus
from core.config import settings


class TestAuthService:
    """Test AuthService class"""
    
    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
    @pytest.fixture
    def auth_service(self, mock_db):
        """AuthService instance"""
        return AuthService(mock_db)
    
    @pytest.fixture
    def mock_user(self):
        """Mock user object"""
        user = MagicMock()
        user.id = "test_user_id"
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = "hashed_password"
        user.status = UserStatus.ACTIVE
        user.mfa_enabled = False
        user.roles = ["user"]
        user.permissions = ["read:profile"]
        user.teams = ["team1"]
        return user
    
    @pytest.fixture
    def mock_mfa_user(self, mock_user):
        """Mock user with MFA enabled"""
        mock_user.mfa_enabled = True
        return mock_user

    # Password verification tests
    def test_verify_password_success(self, auth_service):
        """Test successful password verification"""
        plain_password = "testpassword123"
        hashed_password = auth_service.get_password_hash(plain_password)
        
        result = auth_service.verify_password(plain_password, hashed_password)
        assert result is True
    
    def test_verify_password_failure(self, auth_service):
        """Test failed password verification"""
        plain_password = "testpassword123"
        wrong_password = "wrongpassword456"
        hashed_password = auth_service.get_password_hash(plain_password)
        
        result = auth_service.verify_password(wrong_password, hashed_password)
        assert result is False
    
    def test_get_password_hash_creates_unique_hashes(self, auth_service):
        """Test that password hashing creates unique hashes"""
        password = "testpassword123"
        hash1 = auth_service.get_password_hash(password)
        hash2 = auth_service.get_password_hash(password)
        
        assert hash1 != hash2
        assert auth_service.verify_password(password, hash1)
        assert auth_service.verify_password(password, hash2)

    # Authentication tests
    @pytest.mark.asyncio
    async def test_authenticate_success(self, auth_service, mock_user):
        """Test successful authentication"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            result = await auth_service.authenticate("testuser", "testpassword123")
            
            assert result == mock_user
            auth_service.db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service):
        """Test authentication with non-existent user"""
        # Mock database query returning None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        auth_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="Invalid username or password"):
            await auth_service.authenticate("nonexistent", "password")
    
    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self, auth_service, mock_user):
        """Test authentication with wrong password"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification failure
        with patch.object(auth_service, 'verify_password', return_value=False):
            with pytest.raises(ValueError, match="Invalid username or password"):
                await auth_service.authenticate("testuser", "wrongpassword")
    
    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self, auth_service, mock_user):
        """Test authentication with inactive user"""
        mock_user.status = UserStatus.SUSPENDED
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            with pytest.raises(ValueError, match="Invalid username or password"):
                await auth_service.authenticate("testuser", "testpassword123")
    
    @pytest.mark.asyncio
    async def test_authenticate_mfa_required_but_not_provided(self, auth_service, mock_mfa_user):
        """Test authentication with MFA enabled but no code provided"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_mfa_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            with pytest.raises(ValueError, match="Invalid username or password"):
                await auth_service.authenticate("testuser", "testpassword123")
    
    @pytest.mark.asyncio
    async def test_authenticate_mfa_success(self, auth_service, mock_mfa_user):
        """Test successful authentication with MFA"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_mfa_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            # Mock MFA service
            with patch('services.mfa_service.MFAService') as mock_mfa_service_class:
                mock_mfa_service = AsyncMock()
                mock_mfa_service.verify_mfa.return_value = True
                mock_mfa_service_class.return_value = mock_mfa_service
                
                result = await auth_service.authenticate("testuser", "testpassword123", mfa_code="123456")
                
                assert result == mock_mfa_user
                mock_mfa_service.verify_mfa.assert_called_once_with(mock_mfa_user, "123456")
    
    @pytest.mark.asyncio
    async def test_authenticate_mfa_invalid_code(self, auth_service, mock_mfa_user):
        """Test authentication with invalid MFA code"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_mfa_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            # Mock MFA service
            with patch('services.mfa_service.MFAService') as mock_mfa_service_class:
                mock_mfa_service = AsyncMock()
                mock_mfa_service.verify_mfa.return_value = False
                mock_mfa_service_class.return_value = mock_mfa_service
                
                with pytest.raises(ValueError, match="Invalid username or password"):
                    await auth_service.authenticate("testuser", "testpassword123", mfa_code="000000")

    # Token creation tests
    def test_create_access_token(self, auth_service, mock_user):
        """Test access token creation"""
        token = auth_service.create_access_token(mock_user)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode token to verify contents
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        
        assert payload["sub"] == mock_user.id
        assert payload["username"] == mock_user.username
        assert payload["email"] == mock_user.email
        assert payload["roles"] == mock_user.roles
        assert payload["permissions"] == mock_user.permissions
        assert payload["teams"] == mock_user.teams
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload
        assert "iss" in payload
        assert "sid" in payload
        assert "sid" in payload
    
    def test_create_refresh_token(self, auth_service, mock_user):
        """Test refresh token creation"""
        token = auth_service.create_refresh_token(mock_user)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode token to verify contents
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        
        assert payload["sub"] == mock_user.id
        assert payload["type"] == "refresh"
        assert "exp" in payload
        assert "iat" in payload
        assert "iss" in payload
        assert "sid" in payload
        assert "sid" in payload
    
    def test_create_access_token_expiration(self, auth_service, mock_user):
        """Test access token expiration time"""
        token = auth_service.create_access_token(mock_user)
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        
        exp_time = datetime.fromtimestamp(payload["exp"], timezone.utc)
        iat_time = datetime.fromtimestamp(payload["iat"], timezone.utc)
        
        expected_duration = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        actual_duration = exp_time - iat_time
        
        # Allow for small timing differences
        assert abs(actual_duration.total_seconds() - expected_duration.total_seconds()) < 60
    
    def test_create_refresh_token_expiration(self, auth_service, mock_user):
        """Test refresh token expiration time"""
        token = auth_service.create_refresh_token(mock_user)
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        
        exp_time = datetime.fromtimestamp(payload["exp"], timezone.utc)
        iat_time = datetime.fromtimestamp(payload["iat"], timezone.utc)
        
        expected_duration = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        actual_duration = exp_time - iat_time
        
        # Allow for small timing differences
        assert abs(actual_duration.total_seconds() - expected_duration.total_seconds()) < 60

    # Token decoding tests
    def test_decode_token_success(self, auth_service, mock_user):
        """Test successful token decoding"""
        token = auth_service.create_access_token(mock_user)
        payload = auth_service.decode_token(token)
        
        assert payload["sub"] == mock_user.id
        assert payload["type"] == "access"
        assert "exp" in payload
    
    def test_decode_token_invalid_token(self, auth_service):
        """Test decoding invalid token"""
        with pytest.raises(ValueError, match="Invalid token"):
            auth_service.decode_token("invalid_token")
    
    def test_decode_token_expired_token(self, auth_service, mock_user):
        """Test decoding expired token"""
        # Create token with negative expiration
        payload = {
            "sub": mock_user.id,
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            "iat": datetime.now(timezone.utc) - timedelta(minutes=2)
        }
        
        expired_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
        
        with pytest.raises(ValueError, match="Token has expired"):
            auth_service.decode_token(expired_token)
    
    def test_decode_token_wrong_signature(self, auth_service, mock_user):
        """Test decoding token with wrong signature"""
        # Create token with different secret
        payload = {
            "sub": mock_user.id,
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc)
        }
        
        wrong_token = jwt.encode(payload, "wrong_secret", algorithm=settings.JWT_ALGORITHM)
        
        with pytest.raises(ValueError, match="Invalid token"):
            auth_service.decode_token(wrong_token)

    # User retrieval tests
    @pytest.mark.asyncio
    async def test_get_user_by_id_success(self, auth_service, mock_user):
        """Test successful user retrieval by ID"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        auth_service.db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_id("test_user_id")
        
        assert result == mock_user
        auth_service.db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, auth_service):
        """Test user retrieval with non-existent ID"""
        # Mock database query returning None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        auth_service.db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_id("nonexistent_id")
        
        assert result is None

    # Session revocation tests
    @pytest.mark.asyncio
    async def test_revoke_session(self, auth_service):
        """Test session revocation (currently a no-op)"""
        # Since revoke_session is currently a no-op, just test it doesn't raise
        await auth_service.revoke_session("session_id", "user_id")
        # Test passes if no exception is raised

    # Edge cases and error handling
    def test_token_creation_with_empty_user_data(self, auth_service):
        """Test token creation with minimal user data"""
        minimal_user = MagicMock()
        minimal_user.id = "minimal_user"
        minimal_user.username = "minimal"
        minimal_user.email = "minimal@example.com"
        minimal_user.roles = None
        minimal_user.permissions = None
        minimal_user.teams = None
        
        token = auth_service.create_access_token(minimal_user)
        payload = auth_service.decode_token(token)
        
        assert payload["sub"] == "minimal_user"
        assert payload["roles"] == []
        assert payload["permissions"] == []
        assert payload["teams"] == []
    
    def test_token_creation_with_complex_user_data(self, auth_service):
        """Test token creation with complex user data"""
        complex_user = MagicMock()
        complex_user.id = "complex_user"
        complex_user.username = "complex"
        complex_user.email = "complex@example.com"
        complex_user.roles = ["admin", "user", "moderator"]
        complex_user.permissions = ["read:all", "write:all", "delete:user"]
        complex_user.teams = ["team1", "team2", "team3"]
        
        token = auth_service.create_access_token(complex_user)
        payload = auth_service.decode_token(token)
        
        assert payload["sub"] == "complex_user"
        assert payload["roles"] == ["admin", "user", "moderator"]
        assert payload["permissions"] == ["read:all", "write:all", "delete:user"]
        assert payload["teams"] == ["team1", "team2", "team3"]
    
    @pytest.mark.asyncio
    async def test_authenticate_with_metadata(self, auth_service, mock_user):
        """Test authentication with IP address and user agent"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        auth_service.db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            result = await auth_service.authenticate(
                "testuser", 
                "testpassword123",
                ip_address="192.168.1.1",
                user_agent="TestAgent/1.0"
            )
            
            assert result == mock_user
            # Metadata is currently not used in the implementation,
            # but this test ensures the method accepts the parameters
    
    def test_unique_session_ids(self, auth_service, mock_user):
        """Test that tokens have unique session IDs"""
        token1 = auth_service.create_access_token(mock_user)
        token2 = auth_service.create_access_token(mock_user)
        
        payload1 = auth_service.decode_token(token1)
        payload2 = auth_service.decode_token(token2)
        
        assert payload1["sid"] != payload2["sid"]
        assert uuid.UUID(payload1["sid"])  # Validate UUID format
        assert uuid.UUID(payload2["sid"])  # Validate UUID format