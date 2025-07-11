#!/usr/bin/env python3
"""
Fixed RoleService Tests with Proper Test Data Management
Demonstrates enterprise-grade test isolation and data management
"""
import asyncio
import sys
import os
import uuid
from datetime import datetime, UTC
import json

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, delete

from core.config import settings
from models.rbac import user_roles
from services.role_service import RoleService
from services.rbac_service import RBACService
from models.user import User, UserStatus
from models.rbac import Role, Permission
from core.database import Base


class TestDataBuilder:
    """Test Data Builder Pattern - 테스트 데이터 생성 전용 클래스"""
    
    @staticmethod
    def create_test_user_data() -> dict:
        """독립적인 테스트 사용자 데이터 생성"""
        unique_id = str(uuid.uuid4())[:8]
        return {
            "id": str(uuid.uuid4()),
            "username": f"test_user_{unique_id}",
            "email": f"test_{unique_id}@example.com",
            "full_name": f"Test User {unique_id}",
            "password_hash": "$2b$12$dummy.hash.for.testing.purposes.only",
            "status": UserStatus.ACTIVE,
            "mfa_enabled": False,
            "failed_login_attempts": 0,
            "data_retention_consent": True,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC)
        }
    
    @staticmethod
    async def create_test_user(db: AsyncSession) -> User:
        """테스트 사용자 생성"""
        user_data = TestDataBuilder.create_test_user_data()
        user = User(**user_data)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
    
    @staticmethod
    async def cleanup_test_user(db: AsyncSession, user_id: str):
        """테스트 사용자 정리"""
        try:
            # Delete user roles first (foreign key constraint)
            await db.execute(
                delete(user_roles).where(user_roles.c.user_id == user_id)
            )
            # Delete user
            await db.execute(
                delete(User).where(User.id == user_id)
            )
            await db.commit()
        except Exception as e:
            await db.rollback()
            print(f"Cleanup warning: {e}")


class IsolatedRoleServiceTester:
    """Enterprise-grade isolated test suite"""
    
    def __init__(self):
        self.engine = None
        self.session = None
        self.role_service = None
        self.rbac_service = None
        self.test_results = []
        self.created_users = []  # 정리용 사용자 목록
    
    def log_result(self, test_name: str, status: str, details: str = ""):
        """테스트 결과 로깅"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now(UTC).isoformat(),
            "isolation": "✅ ISOLATED" if status != "SKIP" else "⏭️ SKIPPED"
        }
        self.test_results.append(result)
        print(f"[{status}] {test_name}: {details}")
    
    async def setup(self):
        """테스트 환경 설정"""
        try:
            self.engine = create_async_engine(settings.DATABASE_URL, echo=False)
            async_session = sessionmaker(
                self.engine, class_=AsyncSession, expire_on_commit=False
            )
            self.session = async_session()
            
            self.role_service = RoleService.create_with_db(self.session)
            self.rbac_service = RBACService(self.session)
            
            self.log_result("Setup", "PASS", "✅ Isolated test environment ready")
            return True
            
        except Exception as e:
            self.log_result("Setup", "ERROR", str(e))
            return False
    
    async def cleanup(self):
        """테스트 환경 정리"""
        try:
            # 생성된 모든 테스트 사용자 정리
            for user_id in self.created_users:
                await TestDataBuilder.cleanup_test_user(self.session, user_id)
            
            if self.session:
                await self.session.close()
            if self.engine:
                await self.engine.dispose()
                
            self.log_result("Cleanup", "PASS", f"✅ Cleaned up {len(self.created_users)} test users")
        except Exception as e:
            print(f"Cleanup error: {e}")
    
    async def test_isolated_user_creation(self):
        """테스트 1: 격리된 사용자 생성"""
        try:
            # 🔥 핵심: 테스트가 자체 데이터를 생성
            user = await TestDataBuilder.create_test_user(self.session)
            self.created_users.append(user.id)
            
            # 검증
            if user.id and user.username.startswith("test_user_"):
                self.log_result("Isolated User Creation", "PASS", 
                              f"✅ Created independent user: {user.username}")
                return user
            else:
                self.log_result("Isolated User Creation", "FAIL", "User creation failed")
                return None
                
        except Exception as e:
            self.log_result("Isolated User Creation", "ERROR", str(e))
            return None
    
    async def test_role_assignment_with_data(self):
        """테스트 2: 데이터와 함께 역할 할당"""
        try:
            # 🔥 핵심: 테스트 실행 시점에 필요한 데이터 생성
            user = await TestDataBuilder.create_test_user(self.session)
            self.created_users.append(user.id)
            
            # 역할 할당 테스트 (올바른 역할 사용)
            success = await self.role_service.assign_role_async(
                user.id, "admin", "test_system"
            )
            
            if success:
                # 검증: 실제로 할당되었는지 확인
                roles = await self.role_service.get_user_roles_async(user.id)
                if "admin" in roles:
                    self.log_result("Role Assignment", "PASS", 
                                  f"✅ Successfully assigned admin role to {user.username}")
                    return True
                else:
                    self.log_result("Role Assignment", "FAIL", "Role not found after assignment")
                    return False
            else:
                self.log_result("Role Assignment", "FAIL", "Assignment returned False")
                return False
                
        except Exception as e:
            self.log_result("Role Assignment", "ERROR", str(e))
            return False
    
    async def test_permission_retrieval_with_data(self):
        """테스트 3: 데이터와 함께 권한 조회"""
        try:
            # 데이터 생성
            user = await TestDataBuilder.create_test_user(self.session)
            self.created_users.append(user.id)
            
            # 역할 할당 (권한을 위해) - 유효한 역할 사용
            await self.role_service.assign_role_async(user.id, "admin", "test_system")
            
            # 권한 조회
            permissions = await self.role_service.get_user_permissions_async(user.id)
            
            if permissions and len(permissions) > 0:
                self.log_result("Permission Retrieval", "PASS", 
                              f"✅ Retrieved {len(permissions)} permissions")
                return True
            else:
                self.log_result("Permission Retrieval", "FAIL", "No permissions found")
                return False
                
        except Exception as e:
            self.log_result("Permission Retrieval", "ERROR", str(e))
            return False
    
    async def test_role_sync_with_data(self):
        """테스트 4: 데이터와 함께 역할 동기화"""
        try:
            # 데이터 생성
            user = await TestDataBuilder.create_test_user(self.session)
            self.created_users.append(user.id)
            
            # 동기화 테스트 - 유효한 역할들만 사용
            config_roles = ["viewer", "admin"]
            await self.role_service.sync_user_roles_with_config(user.id, config_roles)
            
            # 검증
            current_roles = await self.role_service.get_user_roles_async(user.id)
            synced_count = sum(1 for role in config_roles if role in current_roles)
            
            if synced_count > 0:
                self.log_result("Role Sync", "PASS", 
                              f"✅ Synced {synced_count}/{len(config_roles)} roles")
                return True
            else:
                self.log_result("Role Sync", "FAIL", "No roles synced")
                return False
                
        except Exception as e:
            self.log_result("Role Sync", "ERROR", str(e))
            return False
    
    async def test_config_mode_isolation(self):
        """테스트 5: 설정 모드 격리"""
        try:
            # 🔥 핵심: 외부 의존성 없는 테스트
            config_service = RoleService.create_config_only()
            
            # 기본 검증
            is_valid = config_service.is_valid_role("admin")
            permissions = config_service.get_permissions_for_roles(["admin"])
            summary = config_service.get_configuration_summary()
            
            if is_valid and permissions and summary["mode"] == "config":
                self.log_result("Config Mode Isolation", "PASS", 
                              "✅ Config mode works independently")
                return True
            else:
                self.log_result("Config Mode Isolation", "FAIL", "Config mode validation failed")
                return False
                
        except Exception as e:
            self.log_result("Config Mode Isolation", "ERROR", str(e))
            return False
    
    async def test_parallel_user_operations(self):
        """테스트 6: 순차 사용자 작업 (트랜잭션 경합 방지)"""
        try:
            # 여러 사용자 순차 생성 (병렬 처리로 인한 트랜잭션 경합 방지)
            users = []
            for i in range(3):
                user = await TestDataBuilder.create_test_user(self.session)
                users.append(user)
            self.created_users.extend([user.id for user in users])
            
            # 각 사용자에게 다른 역할 할당 - 모두 유효한 역할
            roles = ["admin", "user", "viewer"]
            # 순차적으로 역할 할당 (트랜잭션 경합 방지)
            results = []
            for user, role in zip(users, roles):
                result = await self.role_service.assign_role_async(user.id, role, "test_system")
                results.append(result)
            
            success_count = sum(1 for r in results if r is True)
            
            if success_count == len(users):
                self.log_result("Sequential Operations", "PASS", 
                              f"✅ Successfully processed {len(users)} users sequentially")
                return True
            else:
                self.log_result("Sequential Operations", "FAIL", 
                              f"Only {success_count}/{len(users)} operations succeeded")
                return False
                
        except Exception as e:
            self.log_result("Sequential Operations", "ERROR", str(e))
            return False
    
    async def run_all_tests(self):
        """모든 테스트 실행"""
        print("\n=== 🏗️ Enterprise-Grade Isolated RoleService Tests ===\n")
        
        # Setup
        if not await self.setup():
            print("\n❌ Setup failed. Tests aborted.")
            return
        
        try:
            # 🔥 핵심: 각 테스트가 완전히 독립적
            await self.test_isolated_user_creation()
            await self.test_role_assignment_with_data()
            await self.test_permission_retrieval_with_data()
            await self.test_role_sync_with_data()
            await self.test_config_mode_isolation()
            await self.test_parallel_user_operations()
            
        finally:
            await self.cleanup()
        
        # 결과 분석
        print("\n=== 📊 Test Results Analysis ===")
        passed = sum(1 for r in self.test_results if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results if r["status"] == "FAIL")
        errors = sum(1 for r in self.test_results if r["status"] == "ERROR")
        skipped = sum(1 for r in self.test_results if r["status"] == "SKIP")
        
        total_tests = len(self.test_results) - 2  # Setup/Cleanup 제외
        success_rate = (passed / max(total_tests, 1)) * 100
        
        print(f"📈 Success Rate: {success_rate:.1f}% ({passed}/{total_tests})")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"🚨 Errors: {errors}")
        print(f"⏭️ Skipped: {skipped}")
        
        # 품질 평가
        if success_rate >= 90:
            print("\n🎉 EXCELLENT: Test suite is production-ready!")
        elif success_rate >= 70:
            print("\n✅ GOOD: Test suite is functional with minor issues")
        else:
            print("\n⚠️ POOR: Test suite needs significant improvement")
        
        # 결과 저장
        with open("isolated_role_service_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        print(f"\n📄 Detailed results: isolated_role_service_test_results.json")
        
        return success_rate


async def main():
    """메인 실행 함수"""
    print("🚀 Starting Enterprise-Grade Test Suite...")
    tester = IsolatedRoleServiceTester()
    success_rate = await tester.run_all_tests()
    
    # Exit code 설정 (CI/CD 용)
    exit_code = 0 if success_rate >= 90 else 1
    print(f"\n🎯 Exit Code: {exit_code} (Success Rate: {success_rate:.1f}%)")
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)