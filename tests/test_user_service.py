"""
Comprehensive unit tests for UserService
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_

from services.user_service import UserService, pwd_context
from models.user import User, UserStatus
from core.config import settings


class TestUserService:
    """Test UserService class"""
    
    @pytest.fixture
    def mock_db(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
    @pytest.fixture
    def user_service(self, mock_db):
        """UserService instance"""
        return UserService(mock_db)
    
    @pytest.fixture
    def mock_user(self):
        """Mock user object"""
        user = MagicMock()
        user.id = "test_user_id"
        user.username = "testuser"
        user.email = "test@example.com"
        user.full_name = "Test User"
        user.password_hash = pwd_context.hash("Test123!")
        user.status = UserStatus.ACTIVE
        user.roles = ["user"]
        user.permissions = []
        user.teams = []
        user.password_history = [user.password_hash]
        user.password_changed_at = datetime.now(timezone.utc)
        user.created_at = datetime.now(timezone.utc)
        user.updated_at = None
        user.last_login = None
        user.last_activity = None
        user.created_by = "system"
        user.updated_by = None
        return user

    # User creation tests
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_service):
        """Test successful user creation"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.add = MagicMock()
            user_service.db.commit = AsyncMock()
            user_service.db.refresh = AsyncMock()
            
            result = await user_service.create_user(
                username="newuser",
                email="new@example.com",
                password="NewPass123!",
                full_name="New User",
                roles=["admin"],
                created_by="admin"
            )
            
            assert result.username == "newuser"
            assert result.email == "new@example.com"
            assert result.full_name == "New User"
            assert result.roles == ["admin"]
            assert result.status == UserStatus.ACTIVE
            assert result.created_by == "admin"
            assert pwd_context.verify("NewPass123!", result.password_hash)
            
            user_service.db.add.assert_called_once()
            user_service.db.commit.assert_called_once()
            user_service.db.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_user_already_exists_username(self, user_service, mock_user):
        """Test user creation with existing username"""
        # Mock existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="User already exists"):
            await user_service.create_user(
                username="testuser",
                email="different@example.com",
                password="NewPass123!"
            )
    
    @pytest.mark.asyncio
    async def test_create_user_already_exists_email(self, user_service, mock_user):
        """Test user creation with existing email"""
        # Mock existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="User already exists"):
            await user_service.create_user(
                username="differentuser",
                email="test@example.com",
                password="NewPass123!"
            )
    
    @pytest.mark.asyncio
    async def test_create_user_invalid_password(self, user_service):
        """Test user creation with invalid password"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation failure
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.side_effect = ValueError("Password too weak")
            
            with pytest.raises(ValueError, match="Password validation failed: Password too weak"):
                await user_service.create_user(
                    username="newuser",
                    email="new@example.com",
                    password="weak"
                )
    
    @pytest.mark.asyncio
    async def test_create_user_default_values(self, user_service):
        """Test user creation with default values"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.add = MagicMock()
            user_service.db.commit = AsyncMock()
            user_service.db.refresh = AsyncMock()
            
            result = await user_service.create_user(
                username="newuser",
                email="new@example.com",
                password="NewPass123!"
            )
            
            assert result.roles == ["user"]  # Default role
            assert result.permissions == []
            assert result.teams == []
            assert result.created_by == "system"  # Default creator
            assert result.full_name is None

    # User update tests
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_service, mock_user):
        """Test successful user update"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock database operations
        user_service.db.commit = AsyncMock()
        user_service.db.refresh = AsyncMock()
        
        result = await user_service.update_user(
            user_id="test_user_id",
            full_name="Updated Name",
            roles=["admin", "user"],
            teams=["team1", "team2"],
            updated_by="admin"
        )
        
        assert result.full_name == "Updated Name"
        assert result.roles == ["admin", "user"]
        assert result.teams == ["team1", "team2"]
        assert result.updated_by == "admin"
        assert result.updated_at is not None
        
        user_service.db.commit.assert_called_once()
        user_service.db.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_user_not_found(self, user_service):
        """Test user update with non-existent user"""
        # Mock user not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="User not found"):
            await user_service.update_user(
                user_id="nonexistent_id",
                full_name="Updated Name"
            )
    
    @pytest.mark.asyncio
    async def test_update_user_partial_update(self, user_service, mock_user):
        """Test partial user update"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock database operations
        user_service.db.commit = AsyncMock()
        user_service.db.refresh = AsyncMock()
        
        original_roles = mock_user.roles
        original_teams = mock_user.teams
        
        result = await user_service.update_user(
            user_id="test_user_id",
            full_name="Updated Name Only"
        )
        
        assert result.full_name == "Updated Name Only"
        assert result.roles == original_roles  # Should remain unchanged
        assert result.teams == original_teams  # Should remain unchanged
    
    @pytest.mark.asyncio
    async def test_update_user_no_changes(self, user_service, mock_user):
        """Test user update with no changes"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock database operations
        user_service.db.commit = AsyncMock()
        user_service.db.refresh = AsyncMock()
        
        result = await user_service.update_user(
            user_id="test_user_id",
            updated_by="admin"
        )
        
        assert result.updated_by == "admin"
        assert result.updated_at is not None
        
        user_service.db.commit.assert_called_once()
        user_service.db.refresh.assert_called_once()

    # Password change tests
    @pytest.mark.asyncio
    async def test_change_password_success(self, user_service, mock_user):
        """Test successful password change"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.commit = AsyncMock()
            
            result = await user_service.change_password(
                user_id="test_user_id",
                old_password="Test123!",
                new_password="NewPass456!",
                changed_by="user"
            )
            
            assert pwd_context.verify("NewPass456!", result.password_hash)
            assert result.password_changed_at is not None
            assert len(result.password_history) == 2
            assert result.password_history[-1] == result.password_hash
            
            user_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self, user_service):
        """Test password change with non-existent user"""
        # Mock user not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="User not found"):
            await user_service.change_password(
                user_id="nonexistent_id",
                old_password="Test123!",
                new_password="NewPass456!",
                changed_by="user"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_invalid_old_password(self, user_service, mock_user):
        """Test password change with invalid old password"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        with pytest.raises(ValueError, match="Invalid old password"):
            await user_service.change_password(
                user_id="test_user_id",
                old_password="WrongPassword!",
                new_password="NewPass456!",
                changed_by="user"
            )
    
    @pytest.mark.asyncio
    async def test_change_password_invalid_new_password(self, user_service, mock_user):
        """Test password change with invalid new password"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation failure
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.side_effect = ValueError("Password too weak")
            
            with pytest.raises(ValueError, match="Password validation failed: Password too weak"):
                await user_service.change_password(
                    user_id="test_user_id",
                    old_password="Test123!",
                    new_password="weak",
                    changed_by="user"
                )
    
    @pytest.mark.asyncio
    async def test_change_password_recent_password_reuse(self, user_service, mock_user):
        """Test password change with recently used password"""
        # Setup password history
        new_password = "RecentPass123!"
        new_hash = pwd_context.hash(new_password)
        mock_user.password_history = [mock_user.password_hash, new_hash]
        
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            with pytest.raises(ValueError, match="Password was used recently"):
                await user_service.change_password(
                    user_id="test_user_id",
                    old_password="Test123!",
                    new_password=new_password,
                    changed_by="user"
                )
    
    @pytest.mark.asyncio
    async def test_change_password_history_limit(self, user_service, mock_user):
        """Test password history limit enforcement"""
        # Setup long password history
        old_hashes = [pwd_context.hash(f"pass{i}") for i in range(10)]
        mock_user.password_history = old_hashes
        
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.commit = AsyncMock()
            
            result = await user_service.change_password(
                user_id="test_user_id",
                old_password="Test123!",
                new_password="NewPass456!",
                changed_by="user"
            )
            
            # Check that history is limited to PASSWORD_HISTORY_COUNT
            assert len(result.password_history) <= settings.PASSWORD_HISTORY_COUNT

    # Last login update tests
    @pytest.mark.asyncio
    async def test_update_last_login_success(self, user_service, mock_user):
        """Test successful last login update"""
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock database operations
        user_service.db.commit = AsyncMock()
        
        await user_service.update_last_login("test_user_id")
        
        assert mock_user.last_login is not None
        assert mock_user.last_activity is not None
        user_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_last_login_user_not_found(self, user_service):
        """Test last login update with non-existent user"""
        # Mock user not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock database operations
        user_service.db.commit = AsyncMock()
        
        # Should not raise exception, just silently fail
        await user_service.update_last_login("nonexistent_id")
        
        # Commit should not be called
        user_service.db.commit.assert_not_called()

    # User retrieval tests
    @pytest.mark.asyncio
    async def test_get_user_by_username_success(self, user_service, mock_user):
        """Test successful user retrieval by username"""
        # Mock user found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        result = await user_service.get_user_by_username("testuser")
        
        assert result == mock_user
        user_service.db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, user_service):
        """Test user retrieval by username with non-existent user"""
        # Mock user not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        result = await user_service.get_user_by_username("nonexistent")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, user_service, mock_user):
        """Test successful user retrieval by email"""
        # Mock user found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        result = await user_service.get_user_by_email("test@example.com")
        
        assert result == mock_user
        user_service.db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, user_service):
        """Test user retrieval by email with non-existent user"""
        # Mock user not found
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        result = await user_service.get_user_by_email("nonexistent@example.com")
        
        assert result is None

    # Default user creation tests
    @pytest.mark.asyncio
    async def test_create_default_user_new(self, user_service):
        """Test default user creation when user doesn't exist"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.add = MagicMock()
            user_service.db.commit = AsyncMock()
            user_service.db.refresh = AsyncMock()
            
            result = await user_service.create_default_user()
            
            assert result.username == "testuser"
            assert result.email == "test@example.com"
            assert result.full_name == "Test User"
            assert result.roles == ["admin"]
            assert "ontology:*:*" in result.permissions
            assert "backend" in result.teams
            
            user_service.db.add.assert_called_once()
            # Commit should be called twice - once for user creation, once for updating permissions
            assert user_service.db.commit.call_count == 2
    
    @pytest.mark.asyncio
    async def test_create_default_user_existing(self, user_service, mock_user):
        """Test default user creation when user already exists"""
        # Mock existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        result = await user_service.create_default_user()
        
        assert result == mock_user
        # No database operations should be called
        user_service.db.add.assert_not_called()

    # Private password validation tests
    def test_validate_password_success(self, user_service):
        """Test successful password validation"""
        # Mock settings
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', True):
                with patch.object(settings, 'PASSWORD_REQUIRE_LOWERCASE', True):
                    with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', True):
                        with patch.object(settings, 'PASSWORD_REQUIRE_SPECIAL', True):
                            
                            result = user_service._validate_password("Test123!")
                            assert result is True
    
    def test_validate_password_too_short(self, user_service):
        """Test password validation with too short password"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            result = user_service._validate_password("Short1!")
            assert result is False
    
    def test_validate_password_no_uppercase(self, user_service):
        """Test password validation without uppercase"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_UPPERCASE', True):
                result = user_service._validate_password("test123!")
                assert result is False
    
    def test_validate_password_no_lowercase(self, user_service):
        """Test password validation without lowercase"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_LOWERCASE', True):
                result = user_service._validate_password("TEST123!")
                assert result is False
    
    def test_validate_password_no_digits(self, user_service):
        """Test password validation without digits"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_DIGITS', True):
                result = user_service._validate_password("TestPass!")
                assert result is False
    
    def test_validate_password_no_special(self, user_service):
        """Test password validation without special characters"""
        with patch.object(settings, 'PASSWORD_MIN_LENGTH', 8):
            with patch.object(settings, 'PASSWORD_REQUIRE_SPECIAL', True):
                result = user_service._validate_password("TestPass123")
                assert result is False

    # Edge cases and error handling
    @pytest.mark.asyncio
    async def test_create_user_database_error(self, user_service):
        """Test user creation with database error"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.add = MagicMock()
            user_service.db.commit = AsyncMock(side_effect=Exception("Database error"))
            
            with pytest.raises(Exception, match="Database error"):
                await user_service.create_user(
                    username="newuser",
                    email="new@example.com",
                    password="NewPass123!"
                )
    
    @pytest.mark.asyncio
    async def test_change_password_empty_history(self, user_service, mock_user):
        """Test password change with empty password history"""
        # Setup empty password history
        mock_user.password_history = None
        
        # Mock user exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.commit = AsyncMock()
            
            result = await user_service.change_password(
                user_id="test_user_id",
                old_password="Test123!",
                new_password="NewPass456!",
                changed_by="user"
            )
            
            assert len(result.password_history) == 1
            assert result.password_history[0] == result.password_hash
    
    def test_password_hashing_context(self, user_service):
        """Test password hashing context configuration"""
        password = "TestPassword123!"
        hashed = pwd_context.hash(password)
        
        assert pwd_context.verify(password, hashed)
        assert not pwd_context.verify("wrongpassword", hashed)
        assert hashed.startswith("$2b$")  # bcrypt prefix
    
    @pytest.mark.asyncio
    async def test_user_creation_with_uuid(self, user_service):
        """Test that user creation generates valid UUID"""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        user_service.db.execute.return_value = mock_result
        
        # Mock password validation
        with patch('services.user_service.validate_password') as mock_validate:
            mock_validate.return_value = True
            
            # Mock database operations
            user_service.db.add = MagicMock()
            user_service.db.commit = AsyncMock()
            user_service.db.refresh = AsyncMock()
            
            result = await user_service.create_user(
                username="newuser",
                email="new@example.com",
                password="NewPass123!"
            )
            
            # Check that ID is a valid UUID format
            import uuid
            assert uuid.UUID(result.id)
            assert len(result.id) == 36  # Standard UUID length with hyphens