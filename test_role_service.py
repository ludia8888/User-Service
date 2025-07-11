#!/usr/bin/env python3
"""
Test RoleService database integration
Tests the updated RoleService that integrates with RBACService
"""
import asyncio
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, UTC
import json

from core.config import settings
from services.role_service import RoleService
from services.rbac_service import RBACService
from models.user import User
from models.rbac import Role, Permission
from core.database import Base


# Test configuration
DATABASE_URL = settings.DATABASE_URL


class RoleServiceTester:
    def __init__(self):
        self.engine = None
        self.session = None
        self.role_service = None
        self.rbac_service = None
        self.test_results = []
        self.test_user_id = None
    
    def log_result(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now(UTC).isoformat()
        }
        self.test_results.append(result)
        print(f"[{status}] {test_name}: {details}")
    
    async def setup(self):
        """Setup database connection and services"""
        try:
            self.engine = create_async_engine(DATABASE_URL, echo=False)
            async_session = sessionmaker(
                self.engine, class_=AsyncSession, expire_on_commit=False
            )
            self.session = async_session()
            
            # Create services
            self.role_service = RoleService.create_with_db(self.session)
            self.rbac_service = RBACService(self.session)
            
            self.log_result("Setup", "PASS", "Database connection and services initialized")
            return True
            
        except Exception as e:
            self.log_result("Setup", "ERROR", str(e))
            return False
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.session:
                await self.session.close()
            if self.engine:
                await self.engine.dispose()
        except Exception as e:
            print(f"Cleanup error: {e}")
    
    async def test_config_mode(self):
        """Test RoleService in config-only mode"""
        try:
            config_service = RoleService.create_config_only()
            
            # Test basic validation
            if not config_service.is_valid_role("admin"):
                self.log_result("Config Mode - Role Validation", "FAIL", "Admin role not valid")
                return False
            
            # Test get permissions
            permissions = config_service.get_permissions_for_roles(["admin"])
            if not permissions:
                self.log_result("Config Mode - Permissions", "FAIL", "No permissions returned")
                return False
            
            # Test configuration summary
            summary = config_service.get_configuration_summary()
            if summary["mode"] != "config":
                self.log_result("Config Mode - Summary", "FAIL", f"Expected config mode, got {summary['mode']}")
                return False
            
            self.log_result("Config Mode", "PASS", f"Config mode working, {len(permissions)} permissions found")
            return True
            
        except Exception as e:
            self.log_result("Config Mode", "ERROR", str(e))
            return False
    
    async def test_database_mode(self):
        """Test RoleService in database mode"""
        try:
            # Test configuration summary
            summary = self.role_service.get_configuration_summary()
            if summary["mode"] != "database":
                self.log_result("Database Mode - Summary", "FAIL", f"Expected database mode, got {summary['mode']}")
                return False
            
            # Test validation
            validation = self.role_service.validate_configuration()
            if not validation["has_database_connection"]:
                self.log_result("Database Mode - Validation", "FAIL", "Database connection not detected")
                return False
            
            self.log_result("Database Mode", "PASS", "Database mode working properly")
            return True
            
        except Exception as e:
            self.log_result("Database Mode", "ERROR", str(e))
            return False
    
    async def find_test_user(self):
        """Find a test user to work with"""
        try:
            from sqlalchemy import select
            result = await self.session.execute(
                select(User).where(User.username == "testuser_direct")
            )
            user = result.scalar_one_or_none()
            
            if user:
                self.test_user_id = user.id
                self.log_result("Find Test User", "PASS", f"Found user: {user.username}")
                return True
            else:
                self.log_result("Find Test User", "FAIL", "Test user not found")
                return False
                
        except Exception as e:
            self.log_result("Find Test User", "ERROR", str(e))
            return False
    
    async def test_async_operations(self):
        """Test async database operations"""
        if not self.test_user_id:
            self.log_result("Async Operations", "SKIP", "No test user available")
            return False
        
        try:
            # Test get user roles
            roles = await self.role_service.get_user_roles_async(self.test_user_id)
            self.log_result("Get User Roles", "PASS", f"User has {len(roles)} roles: {roles}")
            
            # Test get user permissions
            permissions = await self.role_service.get_user_permissions_async(self.test_user_id)
            self.log_result("Get User Permissions", "PASS", f"User has {len(permissions)} permissions")
            
            # Test assign role (if user doesn't have admin role)
            if "admin" not in roles:
                success = await self.role_service.assign_role_async(self.test_user_id, "admin", "test_system")
                if success:
                    self.log_result("Assign Role", "PASS", "Successfully assigned admin role")
                else:
                    self.log_result("Assign Role", "FAIL", "Failed to assign admin role")
            else:
                self.log_result("Assign Role", "SKIP", "User already has admin role")
            
            return True
            
        except Exception as e:
            self.log_result("Async Operations", "ERROR", str(e))
            return False
    
    async def test_role_sync(self):
        """Test syncing roles from config to database"""
        if not self.test_user_id:
            self.log_result("Role Sync", "SKIP", "No test user available")
            return False
        
        try:
            # Define config roles to sync
            config_roles = ["viewer", "developer"]
            
            # Sync roles
            await self.role_service.sync_user_roles_with_config(self.test_user_id, config_roles)
            
            # Verify sync worked
            current_roles = await self.role_service.get_user_roles_async(self.test_user_id)
            
            synced_count = sum(1 for role in config_roles if role in current_roles)
            
            self.log_result("Role Sync", "PASS", 
                          f"Synced {synced_count}/{len(config_roles)} roles successfully")
            return True
            
        except Exception as e:
            self.log_result("Role Sync", "ERROR", str(e))
            return False
    
    async def test_backward_compatibility(self):
        """Test backward compatibility methods"""
        try:
            # Test traditional methods
            valid_roles = self.role_service.validate_roles(["admin", "invalid_role"])
            if "admin" not in valid_roles:
                self.log_result("Backward Compatibility", "FAIL", "Role validation failed")
                return False
            
            # Test user config generation
            config = self.role_service.get_user_config_for_roles(["admin"])
            if not config.get("roles") or not config.get("permissions"):
                self.log_result("Backward Compatibility", "FAIL", "User config generation failed")
                return False
            
            self.log_result("Backward Compatibility", "PASS", 
                          f"Traditional methods working, {len(config['permissions'])} permissions")
            return True
            
        except Exception as e:
            self.log_result("Backward Compatibility", "ERROR", str(e))
            return False
    
    async def run_all_tests(self):
        """Run all RoleService tests"""
        print("\n=== RoleService Integration Tests ===\n")
        
        # Setup
        if not await self.setup():
            print("\nSetup failed. Cannot proceed with tests.")
            return
        
        try:
            # Run tests
            await self.test_config_mode()
            await self.test_database_mode()
            await self.find_test_user()
            await self.test_async_operations()
            await self.test_role_sync()
            await self.test_backward_compatibility()
            
        finally:
            await self.cleanup()
        
        # Summary
        print("\n=== Test Summary ===")
        passed = sum(1 for r in self.test_results if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results if r["status"] == "FAIL")
        errors = sum(1 for r in self.test_results if r["status"] == "ERROR")
        skipped = sum(1 for r in self.test_results if r["status"] == "SKIP")
        
        print(f"Total: {len(self.test_results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Errors: {errors}")
        print(f"Skipped: {skipped}")
        
        # Save results
        with open("role_service_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        print("\nResults saved to role_service_test_results.json")


async def main():
    tester = RoleServiceTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())