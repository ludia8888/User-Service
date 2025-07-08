"""
Business Rules Engine - Single Source of Truth (SSOT)
모든 비즈니스 규칙과 정책의 중앙 집중식 관리

SSOT 원칙:
- 모든 비즈니스 규칙이 이 파일에 정의됨
- 다른 곳에서 중복 정의 금지
- 규칙 변경 시 이 파일만 수정
- 규칙의 버전 관리 및 추적 가능
"""
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, time
from enum import Enum
from dataclasses import dataclass


class BusinessRuleCategory(str, Enum):
    """비즈니스 규칙 카테고리"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    USER_MANAGEMENT = "user_management"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"


class RiskLevel(str, Enum):
    """위험 수준"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BusinessRule:
    """비즈니스 규칙 정의"""
    id: str
    name: str
    description: str
    category: BusinessRuleCategory
    risk_level: RiskLevel
    is_active: bool = True
    version: str = "1.0"
    last_updated: datetime = None
    compliance_requirements: List[str] = None
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now()
        if self.compliance_requirements is None:
            self.compliance_requirements = []


class BusinessRulesEngine:
    """
    비즈니스 규칙 엔진 - SSOT 구현
    
    모든 비즈니스 규칙의 중앙 집중식 정의 및 관리
    """
    
    def __init__(self):
        self._rules = self._initialize_rules()
        self._rule_cache = {}
    
    def _initialize_rules(self) -> Dict[str, BusinessRule]:
        """모든 비즈니스 규칙 초기화"""
        rules = {}
        
        # ========================================
        # AUTHENTICATION RULES
        # ========================================
        
        rules["AUTH_001"] = BusinessRule(
            id="AUTH_001",
            name="Admin Bypass Rule",
            description="Admin 역할은 모든 권한 검사를 우회함 (단, 정지/잠금 상태 제외)",
            category=BusinessRuleCategory.AUTHORIZATION,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX", "GDPR"]
        )
        
        rules["AUTH_002"] = BusinessRule(
            id="AUTH_002",
            name="Suspended User Restriction",
            description="정지된 사용자는 모든 권한이 박탈됨",
            category=BusinessRuleCategory.AUTHORIZATION,
            risk_level=RiskLevel.CRITICAL,
            compliance_requirements=["SOX", "GDPR", "ISO27001"]
        )
        
        rules["AUTH_003"] = BusinessRule(
            id="AUTH_003",
            name="Locked User Restriction",
            description="잠긴 사용자는 모든 권한이 박탈됨",
            category=BusinessRuleCategory.AUTHORIZATION,
            risk_level=RiskLevel.CRITICAL,
            compliance_requirements=["SOX", "GDPR", "ISO27001"]
        )
        
        rules["AUTH_004"] = BusinessRule(
            id="AUTH_004",
            name="Inactive User Read-Only",
            description="비활성 사용자는 읽기 전용 권한만 보유",
            category=BusinessRuleCategory.AUTHORIZATION,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["GDPR"]
        )
        
        rules["AUTH_005"] = BusinessRule(
            id="AUTH_005",
            name="MFA Required for Sensitive Operations",
            description="민감한 작업(admin, delete, write, approve)은 MFA 필수",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX", "ISO27001"]
        )
        
        # ========================================
        # USER MANAGEMENT RULES
        # ========================================
        
        rules["USER_001"] = BusinessRule(
            id="USER_001",
            name="Admin Role Assignment Restriction",
            description="Admin 역할은 기존 Admin에 의해서만 할당 가능",
            category=BusinessRuleCategory.USER_MANAGEMENT,
            risk_level=RiskLevel.CRITICAL,
            compliance_requirements=["SOX", "ISO27001"]
        )
        
        rules["USER_002"] = BusinessRule(
            id="USER_002",
            name="Service Account Role Restriction",
            description="서비스 계정은 service 또는 readonly 역할만 보유 가능",
            category=BusinessRuleCategory.USER_MANAGEMENT,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX"]
        )
        
        rules["USER_003"] = BusinessRule(
            id="USER_003",
            name="Role Conflict Prevention",
            description="상충되는 역할의 동시 보유 금지",
            category=BusinessRuleCategory.USER_MANAGEMENT,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX"]
        )
        
        rules["USER_004"] = BusinessRule(
            id="USER_004",
            name="Sensitive Role Justification",
            description="민감한 역할 할당 시 비즈니스 근거 필수",
            category=BusinessRuleCategory.COMPLIANCE,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["SOX", "GDPR"]
        )
        
        # ========================================
        # TEAM MANAGEMENT RULES
        # ========================================
        
        rules["TEAM_001"] = BusinessRule(
            id="TEAM_001",
            name="Team Capacity Limit",
            description="팀 최대 멤버 수 제한 준수",
            category=BusinessRuleCategory.USER_MANAGEMENT,
            risk_level=RiskLevel.LOW,
            compliance_requirements=[]
        )
        
        rules["TEAM_002"] = BusinessRule(
            id="TEAM_002",
            name="Active User Team Membership",
            description="활성 사용자만 팀 가입 가능",
            category=BusinessRuleCategory.USER_MANAGEMENT,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["GDPR"]
        )
        
        rules["TEAM_003"] = BusinessRule(
            id="TEAM_003",
            name="Team Lead Assignment Permission",
            description="팀 리더 지정은 팀 관리자 권한 필요",
            category=BusinessRuleCategory.AUTHORIZATION,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["SOX"]
        )
        
        rules["TEAM_004"] = BusinessRule(
            id="TEAM_004",
            name="Team Conflict Prevention",
            description="보안상 상충되는 팀의 동시 소속 금지",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX", "ISO27001"]
        )
        
        # ========================================
        # SECURITY RULES
        # ========================================
        
        rules["SEC_001"] = BusinessRule(
            id="SEC_001",
            name="Password History Limit",
            description="패스워드 이력 최대 보관 개수 제한",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["ISO27001"]
        )
        
        rules["SEC_002"] = BusinessRule(
            id="SEC_002",
            name="Failed Login Attempt Limit",
            description="연속 로그인 실패 횟수 제한",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["ISO27001"]
        )
        
        rules["SEC_003"] = BusinessRule(
            id="SEC_003",
            name="Session Timeout",
            description="비활성 세션 자동 만료",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["ISO27001"]
        )
        
        rules["SEC_004"] = BusinessRule(
            id="SEC_004",
            name="Time-based Access Control",
            description="시간 기반 접근 제어 (업무 시간 외 제한)",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.MEDIUM,
            compliance_requirements=["SOX"]
        )
        
        rules["SEC_005"] = BusinessRule(
            id="SEC_005",
            name="IP-based Access Control",
            description="IP 주소 기반 접근 제어",
            category=BusinessRuleCategory.SECURITY,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["SOX", "ISO27001"]
        )
        
        # ========================================
        # COMPLIANCE RULES
        # ========================================
        
        rules["COMP_001"] = BusinessRule(
            id="COMP_001",
            name="Audit Trail Requirement",
            description="모든 권한 변경 사항의 감사 추적 필수",
            category=BusinessRuleCategory.COMPLIANCE,
            risk_level=RiskLevel.CRITICAL,
            compliance_requirements=["SOX", "GDPR"]
        )
        
        rules["COMP_002"] = BusinessRule(
            id="COMP_002",
            name="Data Retention Policy",
            description="사용자 데이터 보관 정책 준수",
            category=BusinessRuleCategory.COMPLIANCE,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["GDPR"]
        )
        
        rules["COMP_003"] = BusinessRule(
            id="COMP_003",
            name="Privacy Consent Tracking",
            description="개인정보 처리 동의 추적",
            category=BusinessRuleCategory.COMPLIANCE,
            risk_level=RiskLevel.HIGH,
            compliance_requirements=["GDPR"]
        )
        
        return rules
    
    # ========================================
    # RULE ACCESS METHODS
    # ========================================
    
    def get_rule(self, rule_id: str) -> Optional[BusinessRule]:
        """규칙 ID로 규칙 조회"""
        return self._rules.get(rule_id)
    
    def get_rules_by_category(self, category: BusinessRuleCategory) -> List[BusinessRule]:
        """카테고리별 규칙 조회"""
        return [rule for rule in self._rules.values() if rule.category == category]
    
    def get_rules_by_risk_level(self, risk_level: RiskLevel) -> List[BusinessRule]:
        """위험 수준별 규칙 조회"""
        return [rule for rule in self._rules.values() if rule.risk_level == risk_level]
    
    def get_active_rules(self) -> List[BusinessRule]:
        """활성 규칙만 조회"""
        return [rule for rule in self._rules.values() if rule.is_active]
    
    # ========================================
    # CONFIGURATION VALUES (SSOT)
    # ========================================
    
    @property
    def PASSWORD_HISTORY_LIMIT(self) -> int:
        """패스워드 이력 보관 개수"""
        return 5
    
    @property
    def MAX_FAILED_LOGIN_ATTEMPTS(self) -> int:
        """최대 로그인 실패 횟수"""
        return 5
    
    @property
    def ACCOUNT_LOCKOUT_DURATION_MINUTES(self) -> int:
        """계정 잠금 지속 시간 (분)"""
        return 30
    
    @property
    def SESSION_TIMEOUT_MINUTES(self) -> int:
        """세션 타임아웃 (분)"""
        return 480  # 8 hours
    
    @property
    def MFA_BACKUP_CODES_COUNT(self) -> int:
        """MFA 백업 코드 개수"""
        return 10
    
    @property
    def ADMIN_ROLES(self) -> Set[str]:
        """관리자 역할 목록"""
        return {"admin", "super_admin", "system_admin"}
    
    @property
    def SERVICE_ACCOUNT_ALLOWED_ROLES(self) -> Set[str]:
        """서비스 계정 허용 역할"""
        return {"service", "readonly", "api_client"}
    
    @property
    def SENSITIVE_ROLES(self) -> Set[str]:
        """민감한 역할 목록 (근거 필요)"""
        return {"admin", "reviewer", "developer", "security_officer"}
    
    @property
    def READ_ONLY_PERMISSIONS(self) -> Set[str]:
        """읽기 전용 권한 액션"""
        return {"read", "view", "list", "get", "search"}
    
    @property
    def SENSITIVE_PERMISSIONS(self) -> Set[str]:
        """민감한 권한 액션 (MFA 필요)"""
        return {"admin", "delete", "write", "approve", "create", "update"}
    
    @property
    def CONFLICTING_ROLES(self) -> Dict[str, Set[str]]:
        """상충되는 역할 매핑"""
        return {
            'admin': {'service', 'readonly', 'external_contractor'},
            'service': {'admin', 'user', 'developer', 'reviewer'},
            'readonly': {'admin', 'developer', 'reviewer'},
            'external_contractor': {'admin', 'security_officer', 'financial_officer'},
            'vendor': {'admin', 'security_officer', 'financial_officer'}
        }
    
    @property
    def CONFLICTING_TEAMS(self) -> Dict[str, Set[str]]:
        """상충되는 팀 매핑"""
        return {
            'security': {'external_contractor', 'vendor'},
            'admin': {'external_contractor', 'vendor'},
            'financial': {'external_contractor', 'vendor'},
            'hr': {'external_contractor'},
            'legal': {'external_contractor', 'vendor'}
        }
    
    @property
    def BUSINESS_HOURS(self) -> Dict[str, time]:
        """업무 시간 정의"""
        return {
            'start': time(9, 0),    # 09:00
            'end': time(18, 0)      # 18:00
        }
    
    @property
    def COMPLIANCE_REQUIREMENTS_MAP(self) -> Dict[str, Dict[str, Any]]:
        """컴플라이언스 요구사항 매핑"""
        return {
            'SOX': {
                'name': 'Sarbanes-Oxley Act',
                'audit_retention_years': 7,
                'separation_of_duties_required': True,
                'admin_approval_required': True
            },
            'GDPR': {
                'name': 'General Data Protection Regulation',
                'data_retention_years': 3,
                'consent_tracking_required': True,
                'right_to_deletion': True
            },
            'ISO27001': {
                'name': 'ISO/IEC 27001',
                'security_controls_required': True,
                'access_review_frequency_months': 6,
                'incident_response_required': True
            }
        }
    
    # ========================================
    # BUSINESS LOGIC EVALUATION METHODS
    # ========================================
    
    def evaluate_admin_bypass_rule(self, user_roles: Set[str], user_status: str) -> bool:
        """AUTH_001: Admin Bypass Rule 평가"""
        rule = self.get_rule("AUTH_001")
        if not rule or not rule.is_active:
            return False
        
        # 정지/잠금 상태 제외
        if user_status in ['suspended', 'locked']:
            return False
        
        # Admin 역할 확인
        return bool(self.ADMIN_ROLES.intersection(user_roles))
    
    def evaluate_user_status_restriction(self, user_status: str) -> Dict[str, bool]:
        """AUTH_002, AUTH_003, AUTH_004: 사용자 상태별 제한 평가"""
        return {
            'suspended_restriction': user_status == 'suspended',  # AUTH_002
            'locked_restriction': user_status == 'locked',        # AUTH_003
            'inactive_readonly': user_status == 'inactive'        # AUTH_004
        }
    
    def evaluate_mfa_requirement(self, permission_action: str, user_mfa_enabled: bool) -> bool:
        """SEC_005: MFA 요구사항 평가"""
        rule = self.get_rule("AUTH_005")
        if not rule or not rule.is_active:
            return True  # 규칙이 비활성화면 통과
        
        # 민감한 권한인지 확인
        if permission_action in self.SENSITIVE_PERMISSIONS:
            return user_mfa_enabled
        
        return True  # 민감하지 않은 권한은 MFA 불필요
    
    def evaluate_role_assignment_validity(
        self, 
        target_user_type: str,
        role_name: str,
        assigner_roles: Set[str],
        business_justification: Optional[str]
    ) -> Dict[str, Any]:
        """USER_001~004: 역할 할당 유효성 평가"""
        result = {
            'is_valid': True,
            'violations': [],
            'warnings': []
        }
        
        # USER_001: Admin 역할 할당 제한
        if role_name in self.ADMIN_ROLES:
            if not self.ADMIN_ROLES.intersection(assigner_roles):
                result['is_valid'] = False
                result['violations'].append('Admin role can only be assigned by existing admins')
        
        # USER_002: 서비스 계정 역할 제한
        if target_user_type == 'service_account':
            if role_name not in self.SERVICE_ACCOUNT_ALLOWED_ROLES:
                result['is_valid'] = False
                result['violations'].append(f'Service accounts can only have roles: {self.SERVICE_ACCOUNT_ALLOWED_ROLES}')
        
        # USER_004: 민감한 역할 근거 필요
        if role_name in self.SENSITIVE_ROLES:
            if not business_justification:
                result['is_valid'] = False
                result['violations'].append('Business justification required for sensitive roles')
        
        return result
    
    def evaluate_role_conflicts(self, current_roles: Set[str], new_role: str) -> List[str]:
        """USER_003: 역할 충돌 평가"""
        conflicts = []
        
        if new_role in self.CONFLICTING_ROLES:
            conflicting_roles = self.CONFLICTING_ROLES[new_role]
            for current_role in current_roles:
                if current_role in conflicting_roles:
                    conflicts.append(current_role)
        
        return conflicts
    
    def evaluate_team_membership_validity(
        self, 
        user_status: str,
        current_teams: Set[str],
        new_team: str,
        team_capacity: Optional[int],
        current_members: int
    ) -> Dict[str, Any]:
        """TEAM_001~004: 팀 멤버십 유효성 평가"""
        result = {
            'is_valid': True,
            'violations': [],
            'warnings': []
        }
        
        # TEAM_001: 팀 용량 제한
        if team_capacity and current_members >= team_capacity:
            result['is_valid'] = False
            result['violations'].append(f'Team capacity limit ({team_capacity}) exceeded')
        
        # TEAM_002: 활성 사용자만 팀 가입
        if user_status != 'active':
            result['is_valid'] = False
            result['violations'].append('Only active users can join teams')
        
        # TEAM_004: 팀 충돌 방지
        if new_team in self.CONFLICTING_TEAMS:
            conflicting_teams = self.CONFLICTING_TEAMS[new_team]
            for current_team in current_teams:
                if current_team in conflicting_teams:
                    result['is_valid'] = False
                    result['violations'].append(f'Team {new_team} conflicts with current team {current_team}')
        
        return result
    
    def evaluate_time_based_access(self, current_time: datetime) -> bool:
        """SEC_004: 시간 기반 접근 제어 평가"""
        rule = self.get_rule("SEC_004")
        if not rule or not rule.is_active:
            return True
        
        current_time_only = current_time.time()
        business_hours = self.BUSINESS_HOURS
        
        return business_hours['start'] <= current_time_only <= business_hours['end']
    
    def should_audit_action(self, action_type: str, risk_level: RiskLevel) -> bool:
        """COMP_001: 감사 추적 필요성 평가"""
        rule = self.get_rule("COMP_001")
        if not rule or not rule.is_active:
            return False
        
        # 모든 권한 변경 사항은 감사 필요
        permission_actions = [
            'role_assigned', 'role_removed', 'permission_granted', 'permission_revoked',
            'team_joined', 'team_left', 'user_created', 'user_deleted', 'user_suspended'
        ]
        
        if action_type in permission_actions:
            return True
        
        # 높은 위험 수준의 작업도 감사 필요
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        return False
    
    # ========================================
    # RULE MANAGEMENT METHODS
    # ========================================
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """규칙 업데이트"""
        if rule_id not in self._rules:
            return False
        
        rule = self._rules[rule_id]
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        
        rule.last_updated = datetime.now()
        return True
    
    def deactivate_rule(self, rule_id: str) -> bool:
        """규칙 비활성화"""
        return self.update_rule(rule_id, {'is_active': False})
    
    def activate_rule(self, rule_id: str) -> bool:
        """규칙 활성화"""
        return self.update_rule(rule_id, {'is_active': True})
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """컴플라이언스 보고서 생성"""
        report = {
            'total_rules': len(self._rules),
            'active_rules': len(self.get_active_rules()),
            'by_category': {},
            'by_risk_level': {},
            'by_compliance': {}
        }
        
        # 카테고리별 통계
        for category in BusinessRuleCategory:
            rules = self.get_rules_by_category(category)
            report['by_category'][category.value] = len(rules)
        
        # 위험 수준별 통계
        for risk_level in RiskLevel:
            rules = self.get_rules_by_risk_level(risk_level)
            report['by_risk_level'][risk_level.value] = len(rules)
        
        # 컴플라이언스별 통계
        compliance_count = {}
        for rule in self._rules.values():
            for compliance in rule.compliance_requirements:
                compliance_count[compliance] = compliance_count.get(compliance, 0) + 1
        report['by_compliance'] = compliance_count
        
        return report


# 글로벌 비즈니스 규칙 엔진 인스턴스 (싱글톤)
business_rules = BusinessRulesEngine()


# 편의 함수들
def get_business_rule(rule_id: str) -> Optional[BusinessRule]:
    """비즈니스 규칙 조회"""
    return business_rules.get_rule(rule_id)


def evaluate_admin_bypass(user_roles: Set[str], user_status: str) -> bool:
    """Admin 우회 규칙 평가"""
    return business_rules.evaluate_admin_bypass_rule(user_roles, user_status)


def evaluate_mfa_requirement(permission_action: str, user_mfa_enabled: bool) -> bool:
    """MFA 요구사항 평가"""
    return business_rules.evaluate_mfa_requirement(permission_action, user_mfa_enabled)


def get_conflicting_roles(role: str) -> Set[str]:
    """충돌하는 역할 조회"""
    return business_rules.CONFLICTING_ROLES.get(role, set())


def get_conflicting_teams(team: str) -> Set[str]:
    """충돌하는 팀 조회"""
    return business_rules.CONFLICTING_TEAMS.get(team, set())