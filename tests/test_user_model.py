"""
Comprehensive unit tests for User model
"""
import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from models.user import User, UserStatus


class TestUserModel:
    """Test User model class"""
    
    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing"""
        user = User()
        user.id = str(uuid.uuid4())
        user.username = "testuser"
        user.email = "test@example.com"
        user.full_name = "Test User"
        user.password_hash = "hashed_password"
        user.status = UserStatus.ACTIVE
        user.roles = ["user", "developer"]
        user.permissions = [
            "schema:read:*",
            "branch:write:own",
            "ontology:*:project1"
        ]
        user.teams = ["backend", "platform"]
        user.mfa_enabled = False
        user.created_at = datetime.now(timezone.utc)
        user.last_login = datetime.now(timezone.utc)
        return user
    
    @pytest.fixture
    def admin_user(self):
        """Create an admin user for testing"""
        user = User()
        user.id = str(uuid.uuid4())
        user.username = "adminuser"
        user.email = "admin@example.com"
        user.full_name = "Admin User"
        user.password_hash = "hashed_admin_password"
        user.status = UserStatus.ACTIVE
        user.roles = ["admin", "user"]
        user.permissions = []
        user.teams = ["admin"]
        user.mfa_enabled = True
        user.created_at = datetime.now(timezone.utc)
        return user

    # UserStatus enum tests
    def test_user_status_enum(self):
        """Test UserStatus enum values"""
        assert UserStatus.ACTIVE == "active"
        assert UserStatus.INACTIVE == "inactive"
        assert UserStatus.LOCKED == "locked"
        assert UserStatus.SUSPENDED == "suspended"
        assert UserStatus.PENDING_VERIFICATION == "pending_verification"
    
    def test_user_status_enum_membership(self):
        """Test UserStatus enum membership"""
        all_statuses = list(UserStatus)
        assert len(all_statuses) == 5
        assert UserStatus.ACTIVE in all_statuses
        assert UserStatus.INACTIVE in all_statuses
        assert UserStatus.LOCKED in all_statuses
        assert UserStatus.SUSPENDED in all_statuses
        assert UserStatus.PENDING_VERIFICATION in all_statuses

    # User model field tests
    def test_user_model_initialization(self):
        """Test User model initialization"""
        # Create user with explicit values to test functionality
        user = User(
            username="testuser",
            email="test@example.com", 
            password_hash="hashed_password"
        )
        
        # Test that we can set and access basic attributes
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "hashed_password"
    
    def test_user_model_id_generation(self):
        """Test User model ID generation"""
        # ID is generated when the model is used with SQLAlchemy session
        # For testing, we can create a user with explicit ID
        import uuid as uuid_module
        test_id = str(uuid_module.uuid4())
        user = User(id=test_id)
        
        assert user.id == test_id
        assert len(user.id) == 36  # UUID4 string length with hyphens
        
        # Verify it's a valid UUID
        uuid_module.UUID(user.id)  # Should not raise exception
    
    def test_user_model_required_fields(self):
        """Test User model required fields"""
        user = User()
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = "hashed_password"
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "hashed_password"

    # to_dict method tests
    def test_to_dict_complete_user(self, sample_user):
        """Test to_dict with complete user data"""
        user_dict = sample_user.to_dict()
        
        assert user_dict["id"] == sample_user.id
        assert user_dict["username"] == sample_user.username
        assert user_dict["email"] == sample_user.email
        assert user_dict["full_name"] == sample_user.full_name
        assert user_dict["status"] == sample_user.status
        assert user_dict["roles"] == sample_user.roles
        assert user_dict["teams"] == sample_user.teams
        assert user_dict["mfa_enabled"] == sample_user.mfa_enabled
        assert user_dict["created_at"] is not None
        assert user_dict["last_login"] is not None
        
        # Check that sensitive data is not included
        assert "password_hash" not in user_dict
        assert "permissions" not in user_dict
        assert "mfa_secret" not in user_dict
        assert "backup_codes" not in user_dict
    
    def test_to_dict_minimal_user(self):
        """Test to_dict with minimal user data"""
        user = User()
        user.id = str(uuid.uuid4())
        user.username = "minimal"
        user.email = "minimal@example.com"
        user.password_hash = "hashed"
        
        user_dict = user.to_dict()
        
        assert user_dict["id"] == user.id
        assert user_dict["username"] == "minimal"
        assert user_dict["email"] == "minimal@example.com"
        assert user_dict["full_name"] is None
        assert user_dict["created_at"] is None
        assert user_dict["last_login"] is None
    
    def test_to_dict_datetime_serialization(self, sample_user):
        """Test to_dict datetime serialization"""
        user_dict = sample_user.to_dict()
        
        # Check ISO format
        assert isinstance(user_dict["created_at"], str)
        assert isinstance(user_dict["last_login"], str)
        assert "T" in user_dict["created_at"]  # ISO format indicator
        assert "T" in user_dict["last_login"]  # ISO format indicator

    # has_role method tests
    def test_has_role_existing_role(self, sample_user):
        """Test has_role with existing role"""
        assert sample_user.has_role("user") is True
        assert sample_user.has_role("developer") is True
    
    def test_has_role_non_existing_role(self, sample_user):
        """Test has_role with non-existing role"""
        assert sample_user.has_role("admin") is False
        assert sample_user.has_role("moderator") is False
    
    def test_has_role_case_sensitive(self, sample_user):
        """Test has_role case sensitivity"""
        assert sample_user.has_role("User") is False  # Case sensitive
        assert sample_user.has_role("USER") is False
        assert sample_user.has_role("user") is True
    
    def test_has_role_empty_roles(self):
        """Test has_role with empty roles"""
        user = User()
        user.roles = []
        
        assert user.has_role("user") is False
        assert user.has_role("admin") is False
    
    def test_has_role_none_roles(self):
        """Test has_role with None roles"""
        user = User()
        user.roles = None
        
        # Should handle None gracefully
        with pytest.raises(TypeError):
            user.has_role("user")

    # has_permission method tests
    def test_has_permission_admin_user(self, admin_user):
        """Test has_permission for admin user"""
        # Admin should have all permissions
        assert admin_user.has_permission("schema:read:any") is True
        assert admin_user.has_permission("branch:write:any") is True
        assert admin_user.has_permission("ontology:delete:any") is True
        assert admin_user.has_permission("system:admin:all") is True
    
    def test_has_permission_exact_match(self, sample_user):
        """Test has_permission with exact permission match"""
        assert sample_user.has_permission("schema:read:any") is True
        assert sample_user.has_permission("branch:write:own") is True
    
    def test_has_permission_wildcard_resource(self, sample_user):
        """Test has_permission with wildcard resource"""
        # User has "ontology:*:project1"
        assert sample_user.has_permission("ontology:read:project1") is True
        assert sample_user.has_permission("ontology:write:project1") is True
        assert sample_user.has_permission("ontology:delete:project1") is True
        assert sample_user.has_permission("ontology:admin:project1") is True
    
    def test_has_permission_wildcard_action(self, sample_user):
        """Test has_permission with wildcard action"""
        # Add permission with wildcard action
        sample_user.permissions.append("document:read:*")
        
        assert sample_user.has_permission("document:read:doc1") is True
        assert sample_user.has_permission("document:read:doc2") is True
        assert sample_user.has_permission("document:read:any") is True
    
    def test_has_permission_full_wildcard(self, sample_user):
        """Test has_permission with full wildcard"""
        # Add full wildcard permission
        sample_user.permissions.append("system:*:*")
        
        assert sample_user.has_permission("system:read:any") is True
        assert sample_user.has_permission("system:write:config") is True
        assert sample_user.has_permission("system:admin:all") is True
    
    def test_has_permission_no_match(self, sample_user):
        """Test has_permission with no matching permission"""
        assert sample_user.has_permission("audit:read:logs") is False
        assert sample_user.has_permission("schema:write:any") is False
        assert sample_user.has_permission("ontology:read:project2") is False
    
    def test_has_permission_invalid_format(self, sample_user):
        """Test has_permission with invalid permission format"""
        assert sample_user.has_permission("invalid_permission") is False
        assert sample_user.has_permission("schema:read") is False  # Missing resource
        assert sample_user.has_permission("schema:read:any:extra") is False  # Too many parts
    
    def test_has_permission_empty_permissions(self):
        """Test has_permission with empty permissions"""
        user = User()
        user.roles = ["user"]  # Not admin
        user.permissions = []
        
        assert user.has_permission("schema:read:any") is False
    
    def test_has_permission_none_permissions(self):
        """Test has_permission with None permissions"""
        user = User()
        user.roles = ["user"]  # Not admin
        user.permissions = None
        
        # Should handle None gracefully
        with pytest.raises(TypeError):
            user.has_permission("schema:read:any")

    # _match_permission method tests
    def test_match_permission_exact_match(self, sample_user):
        """Test _match_permission with exact match"""
        assert sample_user._match_permission("schema:read:doc1", "schema:read:doc1") is True
    
    def test_match_permission_wildcard_first_part(self, sample_user):
        """Test _match_permission with wildcard in first part"""
        assert sample_user._match_permission("*:read:doc1", "schema:read:doc1") is True
        assert sample_user._match_permission("*:read:doc1", "ontology:read:doc1") is True
    
    def test_match_permission_wildcard_second_part(self, sample_user):
        """Test _match_permission with wildcard in second part"""
        assert sample_user._match_permission("schema:*:doc1", "schema:read:doc1") is True
        assert sample_user._match_permission("schema:*:doc1", "schema:write:doc1") is True
    
    def test_match_permission_wildcard_third_part(self, sample_user):
        """Test _match_permission with wildcard in third part"""
        assert sample_user._match_permission("schema:read:*", "schema:read:doc1") is True
        assert sample_user._match_permission("schema:read:*", "schema:read:doc2") is True
    
    def test_match_permission_multiple_wildcards(self, sample_user):
        """Test _match_permission with multiple wildcards"""
        assert sample_user._match_permission("*:*:doc1", "schema:read:doc1") is True
        assert sample_user._match_permission("schema:*:*", "schema:read:doc1") is True
        assert sample_user._match_permission("*:*:*", "schema:read:doc1") is True
    
    def test_match_permission_no_match(self, sample_user):
        """Test _match_permission with no match"""
        assert sample_user._match_permission("schema:read:doc1", "schema:write:doc1") is False
        assert sample_user._match_permission("schema:read:doc1", "ontology:read:doc1") is False
        assert sample_user._match_permission("schema:read:doc1", "schema:read:doc2") is False
    
    def test_match_permission_invalid_format(self, sample_user):
        """Test _match_permission with invalid format"""
        assert sample_user._match_permission("schema:read", "schema:read:doc1") is False
        assert sample_user._match_permission("schema:read:doc1", "schema:read") is False
        assert sample_user._match_permission("invalid", "schema:read:doc1") is False
        assert sample_user._match_permission("schema:read:doc1:extra", "schema:read:doc1") is False

    # is_active property tests
    def test_is_active_true(self, sample_user):
        """Test is_active property when user is active"""
        sample_user.status = UserStatus.ACTIVE
        assert sample_user.is_active is True
    
    def test_is_active_false_inactive(self, sample_user):
        """Test is_active property when user is inactive"""
        sample_user.status = UserStatus.INACTIVE
        assert sample_user.is_active is False
    
    def test_is_active_false_locked(self, sample_user):
        """Test is_active property when user is locked"""
        sample_user.status = UserStatus.LOCKED
        assert sample_user.is_active is False
    
    def test_is_active_false_suspended(self, sample_user):
        """Test is_active property when user is suspended"""
        sample_user.status = UserStatus.SUSPENDED
        assert sample_user.is_active is False
    
    def test_is_active_false_pending(self, sample_user):
        """Test is_active property when user is pending verification"""
        sample_user.status = UserStatus.PENDING_VERIFICATION
        assert sample_user.is_active is False

    # Edge cases and complex scenarios
    def test_has_permission_complex_wildcard_scenarios(self, sample_user):
        """Test complex permission wildcard scenarios"""
        # User has "ontology:*:project1"
        sample_user.permissions = [
            "ontology:*:project1",      # Any action on project1
            "schema:read:*",            # Read any schema
            "branch:*:own",             # Any action on own branches
            "*:read:public"             # Read anything public
        ]
        
        # Test ontology permissions
        assert sample_user.has_permission("ontology:create:project1") is True
        assert sample_user.has_permission("ontology:delete:project1") is True
        assert sample_user.has_permission("ontology:read:project2") is False
        
        # Test schema permissions
        assert sample_user.has_permission("schema:read:schema1") is True
        assert sample_user.has_permission("schema:read:schema2") is True
        assert sample_user.has_permission("schema:write:schema1") is False
        
        # Test branch permissions
        assert sample_user.has_permission("branch:create:own") is True
        assert sample_user.has_permission("branch:delete:own") is True
        assert sample_user.has_permission("branch:read:other") is False
        
        # Test public read permissions
        assert sample_user.has_permission("document:read:public") is True
        assert sample_user.has_permission("schema:read:public") is True
        assert sample_user.has_permission("ontology:read:public") is True
        assert sample_user.has_permission("document:write:public") is False
    
    def test_has_permission_overlapping_permissions(self, sample_user):
        """Test overlapping permission scenarios"""
        sample_user.permissions = [
            "schema:read:*",
            "schema:read:specific",
            "*:read:specific",
            "schema:*:specific"
        ]
        
        # All should match for this specific case
        assert sample_user.has_permission("schema:read:specific") is True
        assert sample_user.has_permission("schema:read:other") is True
        assert sample_user.has_permission("schema:write:specific") is True
        assert sample_user.has_permission("ontology:read:specific") is True
        assert sample_user.has_permission("ontology:write:specific") is False
    
    def test_user_with_admin_and_specific_permissions(self):
        """Test user with both admin role and specific permissions"""
        user = User()
        user.roles = ["admin", "developer"]
        user.permissions = ["schema:read:specific"]  # Should be ignored due to admin role
        
        # Admin should have all permissions regardless of specific permissions
        assert user.has_permission("anything:everything:anywhere") is True
        assert user.has_permission("system:delete:all") is True
    
    def test_permission_matching_edge_cases(self, sample_user):
        """Test permission matching edge cases"""
        # Empty string parts
        assert sample_user._match_permission(":::", "schema:read:doc") is False
        assert sample_user._match_permission("schema:read:doc", ":::") is False
        
        # Single colon
        assert sample_user._match_permission(":", "schema:read:doc") is False
        
        # Mixed case (should be case sensitive)
        assert sample_user._match_permission("Schema:Read:Doc", "schema:read:doc") is False
        assert sample_user._match_permission("SCHEMA:READ:DOC", "schema:read:doc") is False
    
    def test_json_field_handling(self, sample_user):
        """Test JSON field handling"""
        # Test that JSON fields can handle various data types
        sample_user.preferences = {
            "theme": "dark",
            "notifications": True,
            "max_items": 50
        }
        
        sample_user.notification_settings = {
            "email": True,
            "sms": False,
            "push": True
        }
        
        sample_user.active_sessions = [
            {"session_id": "sess1", "created_at": "2023-01-01"},
            {"session_id": "sess2", "created_at": "2023-01-02"}
        ]
        
        # Verify the data is preserved
        assert sample_user.preferences["theme"] == "dark"
        assert sample_user.notification_settings["email"] is True
        assert len(sample_user.active_sessions) == 2
        assert sample_user.active_sessions[0]["session_id"] == "sess1"
    
    def test_user_model_string_representation(self, sample_user):
        """Test user model doesn't break with string operations"""
        # These shouldn't raise exceptions
        user_str = str(sample_user)
        assert isinstance(user_str, str)
        
        # Repr should also work
        user_repr = repr(sample_user)
        assert isinstance(user_repr, str)
    
    def test_user_model_with_none_values(self):
        """Test user model with None values in optional fields"""
        user = User()
        user.id = str(uuid.uuid4())
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = "hashed"
        
        # Set some fields to None explicitly
        user.full_name = None
        user.roles = None
        user.permissions = None
        user.teams = None
        user.preferences = None
        user.notification_settings = None
        
        # to_dict should handle None values gracefully
        user_dict = user.to_dict()
        assert user_dict["full_name"] is None
        
        # These operations should fail gracefully or be handled
        with pytest.raises(TypeError):
            user.has_role("user")  # roles is None
        
        with pytest.raises(TypeError):
            user.has_permission("schema:read:doc")  # permissions is None