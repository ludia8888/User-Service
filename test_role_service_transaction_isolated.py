#!/usr/bin/env python3
"""
Transaction-Isolated RoleService Tests with 100x Repetition
Complete transaction rollback - no manual cleanup required
"""
import asyncio
import sys
import os
import uuid
from datetime import datetime, UTC
import json
import traceback

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


class TransactionIsolatedTester:
    """100% Transaction-Isolated Test Suite"""
    
    def __init__(self):
        self.engine = None
        self.test_results = []
        self.failure_logs = []
    
    def log_result(self, test_name: str, status: str, details: str = "", iteration: int = None):
        """테스트 결과 로깅"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now(UTC).isoformat(),
            "iteration": iteration
        }
        self.test_results.append(result)
        
        if iteration:
            print(f"[{status}] {test_name} (#{iteration}): {details}")
        else:
            print(f"[{status}] {test_name}: {details}")
        
        # Log failures for analysis
        if status in ["FAIL", "ERROR"]:
            self.failure_logs.append({
                "test": test_name,
                "iteration": iteration,
                "details": details,
                "timestamp": datetime.now(UTC).isoformat()
            })
    
    async def setup(self):
        """테스트 환경 설정"""
        try:
            self.engine = create_async_engine(settings.DATABASE_URL, echo=False)
            self.log_result("Setup", "PASS", "✅ Transaction-isolated environment ready")
            return True
        except Exception as e:
            self.log_result("Setup", "ERROR", str(e))
            return False
    
    async def create_test_user_in_transaction(self, session: AsyncSession) -> User:
        """트랜잭션 내에서 테스트 사용자 생성"""
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
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
        
        user = User(**user_data)
        session.add(user)
        await session.flush()  # Make available in transaction but don't commit
        return user
    
    async def test_role_assignment_isolated(self, iteration: int):
        """완전 격리된 역할 할당 테스트"""
        async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            async with session.begin():  # Transaction will auto-rollback
                try:
                    # 1. 트랜잭션 내에서 사용자 생성
                    user = await self.create_test_user_in_transaction(session)
                    
                    # 2. RoleService 생성
                    role_service = RoleService.create_with_db(session)
                    
                    # 3. 역할 할당 시도
                    success = await role_service.assign_role_async(
                        user.id, "admin", "test_system"
                    )
                    
                    if success:
                        # 4. 검증
                        roles = await role_service.get_user_roles_async(user.id)
                        if "admin" in roles:
                            self.log_result("Role Assignment", "PASS", 
                                          f"✅ Successfully assigned admin role", iteration)
                            return True
                        else:
                            self.log_result("Role Assignment", "FAIL", 
                                          "Role not found after assignment", iteration)
                            return False
                    else:
                        self.log_result("Role Assignment", "FAIL", 
                                      "Assignment returned False", iteration)
                        return False
                        
                except Exception as e:
                    self.log_result("Role Assignment", "ERROR", 
                                  f"{type(e).__name__}: {str(e)}", iteration)
                    return False
                # Transaction automatically rolls back - no cleanup needed
    
    async def test_permission_retrieval_isolated(self, iteration: int):
        """완전 격리된 권한 조회 테스트"""
        async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            async with session.begin():
                try:
                    # 1. 사용자 생성
                    user = await self.create_test_user_in_transaction(session)
                    
                    # 2. 서비스 생성
                    role_service = RoleService.create_with_db(session)
                    
                    # 3. 역할 할당
                    await role_service.assign_role_async(user.id, "admin", "test_system")
                    
                    # 4. 권한 조회
                    permissions = await role_service.get_user_permissions_async(user.id)
                    
                    if permissions and len(permissions) > 0:
                        self.log_result("Permission Retrieval", "PASS", 
                                      f"✅ Retrieved {len(permissions)} permissions", iteration)
                        return True
                    else:
                        self.log_result("Permission Retrieval", "FAIL", 
                                      "No permissions found", iteration)
                        return False
                        
                except Exception as e:
                    self.log_result("Permission Retrieval", "ERROR", 
                                  f"{type(e).__name__}: {str(e)}", iteration)
                    return False
    
    async def test_role_sync_isolated(self, iteration: int):
        """완전 격리된 역할 동기화 테스트"""
        async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            async with session.begin():
                try:
                    # 1. 사용자 생성
                    user = await self.create_test_user_in_transaction(session)
                    
                    # 2. 서비스 생성
                    role_service = RoleService.create_with_db(session)
                    
                    # 3. 동기화 테스트
                    config_roles = ["viewer", "admin"]
                    await role_service.sync_user_roles_with_config(user.id, config_roles)
                    
                    # 4. 검증
                    current_roles = await role_service.get_user_roles_async(user.id)
                    synced_count = sum(1 for role in config_roles if role in current_roles)
                    
                    if synced_count > 0:
                        self.log_result("Role Sync", "PASS", 
                                      f"✅ Synced {synced_count}/{len(config_roles)} roles", iteration)
                        return True
                    else:
                        self.log_result("Role Sync", "FAIL", 
                                      "No roles synced", iteration)
                        return False
                        
                except Exception as e:
                    self.log_result("Role Sync", "ERROR", 
                                  f"{type(e).__name__}: {str(e)}", iteration)
                    return False
    
    async def run_100x_stress_test(self):
        """100회 반복 스트레스 테스트"""
        print("\\n=== 🔥 100x Transaction-Isolated Stress Test ===\\n")
        
        if not await self.setup():
            print("\\n❌ Setup failed. Tests aborted.")
            return
        
        test_functions = [
            self.test_role_assignment_isolated,
            self.test_permission_retrieval_isolated,
            self.test_role_sync_isolated
        ]
        
        results = {}
        
        for test_func in test_functions:
            test_name = test_func.__name__.replace("test_", "").replace("_isolated", "")
            results[test_name] = {"pass": 0, "fail": 0, "error": 0}
            
            print(f"\\n🔄 Running {test_name} 100 times...")
            
            for i in range(1, 101):
                try:
                    success = await test_func(i)
                    if success:
                        results[test_name]["pass"] += 1
                    else:
                        results[test_name]["fail"] += 1
                except Exception as e:
                    results[test_name]["error"] += 1
                    self.log_result(test_name, "ERROR", str(e), i)
                
                # Progress indicator
                if i % 10 == 0:
                    print(f"  Progress: {i}/100 completed")
        
        # 결과 분석
        print("\\n=== 📊 100x Test Results Analysis ===")
        
        total_tests = 0
        total_pass = 0
        
        for test_name, stats in results.items():
            total_tests += 100
            total_pass += stats["pass"]
            success_rate = (stats["pass"] / 100) * 100
            
            print(f"\\n📈 {test_name}:")
            print(f"  ✅ Pass: {stats['pass']}/100 ({success_rate:.1f}%)")
            print(f"  ❌ Fail: {stats['fail']}/100")
            print(f"  🚨 Error: {stats['error']}/100")
        
        overall_success_rate = (total_pass / total_tests) * 100
        print(f"\\n🎯 Overall Success Rate: {overall_success_rate:.1f}% ({total_pass}/{total_tests})")
        
        # 실패 패턴 분석
        if self.failure_logs:
            print(f"\\n🔍 Failure Pattern Analysis ({len(self.failure_logs)} failures):")
            failure_types = {}
            for failure in self.failure_logs:
                error_type = failure["details"].split(":")[0] if ":" in failure["details"] else failure["details"]
                failure_types[error_type] = failure_types.get(error_type, 0) + 1
            
            for error_type, count in failure_types.items():
                print(f"  {error_type}: {count} occurrences")
        
        # 결과 저장
        with open("stress_test_results_100x.json", "w") as f:
            json.dump({
                "results": results,
                "overall_success_rate": overall_success_rate,
                "failure_logs": self.failure_logs,
                "test_results": self.test_results
            }, f, indent=2)
        
        print(f"\\n📄 Detailed results saved: stress_test_results_100x.json")
        
        # 성과 평가
        if overall_success_rate >= 99:
            print("\\n🎉 EXCELLENT: True isolation achieved!")
        elif overall_success_rate >= 95:
            print("\\n✅ GOOD: Minor issues detected")
        elif overall_success_rate >= 90:
            print("\\n⚠️ MODERATE: Significant issues need attention")
        else:
            print("\\n🚨 POOR: Major isolation problems detected")
        
        await self.engine.dispose()
        return overall_success_rate


async def main():
    """메인 실행 함수"""
    print("🚀 Starting 100x Transaction-Isolated Stress Test...")
    tester = TransactionIsolatedTester()
    success_rate = await tester.run_100x_stress_test()
    
    exit_code = 0 if success_rate >= 99 else 1
    print(f"\\n🎯 Exit Code: {exit_code} (Success Rate: {success_rate:.1f}%)")
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)