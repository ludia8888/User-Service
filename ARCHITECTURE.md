# User Service 상세 아키텍처 문서

## 목차

1. [시스템 개요](#시스템-개요)
2. [아키텍처 설계 원칙](#아키텍처-설계-원칙)
3. [시스템 구성도](#시스템-구성도)
4. [핵심 컴포넌트](#핵심-컴포넌트)
5. [데이터 모델](#데이터-모델)
6. [보안 아키텍처](#보안-아키텍처)
7. [API 설계](#api-설계)
8. [성능 최적화](#성능-최적화)
9. [확장성 고려사항](#확장성-고려사항)

## 시스템 개요

User Service는 Arrakis 프로젝트의 인증/인가를 담당하는 핵심 마이크로서비스입니다. 모든 사용자 관련 작업(인증, 권한 관리, 프로필 관리)을 중앙에서 처리하며, 다른 마이크로서비스들이 사용자 검증을 위해 의존하는 서비스입니다.

### 주요 책임

- **인증(Authentication)**: 사용자 신원 확인
- **인가(Authorization)**: 리소스 접근 권한 확인
- **사용자 관리**: 계정 생성, 수정, 삭제
- **세션 관리**: 토큰 발급 및 검증
- **보안 정책 시행**: 비밀번호 정책, MFA, Rate Limiting

## 아키텍처 설계 원칙

### 1. 마이크로서비스 원칙
- **단일 책임**: 사용자 인증/인가만 담당
- **독립적 배포**: 다른 서비스와 독립적으로 배포 가능
- **API 우선**: RESTful API를 통한 통신

### 2. 보안 우선 설계
- **Zero Trust**: 모든 요청을 검증
- **Defense in Depth**: 다층 보안 구조
- **Secure by Default**: 안전한 기본 설정

### 3. 확장성
- **수평적 확장**: 스테이트리스 설계
- **캐싱**: Redis를 활용한 성능 최적화
- **비동기 처리**: 높은 동시성 지원

## 시스템 구성도

### 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Applications                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                          API Gateway                             │
│                    (인증 토큰 검증, 라우팅)                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                         User Service                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │   API Layer │  │Service Layer │  │ Repository Layer   │    │
│  │             │  │              │  │                    │    │
│  │ - FastAPI   │─▶│- Auth Service│─▶│ - User Repository  │    │
│  │ - Routers   │  │- User Service│  │ - Session Repo     │    │
│  │ - Middleware│  │- MFA Service │  │ - Audit Repo       │    │
│  └─────────────┘  └──────────────┘  └──────────┬─────────┘    │
└─────────────────────────────────────────────────┼───────────────┘
                                                  │
                 ┌────────────────────────────────┼────────────┐
                 │                                │            │
          ┌──────▼──────┐                 ┌──────▼──────┐     │
          │ PostgreSQL  │                 │    Redis    │     │
          │             │                 │             │     │
          │ - Users     │                 │ - Sessions  │     │
          │ - Audit Logs│                 │ - Rate Limit│     │
          └─────────────┘                 └─────────────┘     │
```

### 내부 컴포넌트 구조

```
src/
├── api/                    # API 엔드포인트
│   ├── auth.py            # 인증 관련 API
│   └── iam_adapter.py     # IAM 호환 API
├── core/                   # 핵심 설정 및 유틸리티
│   ├── config.py          # 환경 설정
│   ├── database.py        # DB 연결 관리
│   ├── redis.py           # Redis 클라이언트
│   ├── validators.py      # 입력 검증
│   ├── rate_limit.py      # Rate Limiting
│   └── security_headers.py # 보안 헤더
├── models/                 # 데이터 모델
│   └── user.py            # User 엔티티
├── services/              # 비즈니스 로직
│   ├── auth_service.py    # 인증 서비스
│   ├── user_service.py    # 사용자 관리
│   ├── mfa_service.py     # MFA 서비스
│   └── audit_service.py   # 감사 로깅
└── main.py                # 애플리케이션 진입점
```

## 핵심 컴포넌트

### 1. API Layer

**책임**: HTTP 요청 처리, 입력 검증, 응답 포맷팅

```python
# 주요 엔드포인트
/auth/register     # 사용자 등록
/auth/login        # 로그인
/auth/logout       # 로그아웃
/auth/refresh      # 토큰 갱신
/auth/userinfo     # 사용자 정보
/auth/mfa/*        # MFA 관련
```

**보안 미들웨어**:
- CORS 처리
- Security Headers
- Rate Limiting
- Request Logging

### 2. Service Layer

**AuthService**
- JWT 토큰 생성/검증
- 사용자 인증
- 세션 관리

**UserService**
- 사용자 CRUD 작업
- 비밀번호 관리
- 프로필 업데이트

**MFAService**
- TOTP 시크릿 생성
- OTP 검증
- 백업 코드 관리

**AuditService**
- 보안 이벤트 로깅
- 실시간 모니터링
- 컴플라이언스 보고

### 3. Repository Layer

**패턴**: Repository Pattern을 통한 데이터 접근 추상화

```python
# 예시: User Repository
class UserRepository:
    async def create(user_data) -> User
    async def find_by_id(user_id) -> User
    async def find_by_username(username) -> User
    async def update(user_id, updates) -> User
```

## 데이터 모델

### User 엔티티

```python
class User:
    id: UUID                    # 고유 식별자
    username: str              # 로그인 ID
    email: str                 # 이메일
    password_hash: str         # 해시된 비밀번호
    
    # 프로필
    full_name: str
    phone_number: str
    
    # 보안
    mfa_enabled: bool
    mfa_secret: str
    mfa_backup_codes: List[str]
    failed_login_attempts: int
    locked_until: datetime
    
    # 권한
    roles: List[str]          # 역할 (admin, user, operator)
    permissions: List[str]    # 세부 권한
    teams: List[str]         # 소속 팀
    
    # 메타데이터
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime
    password_changed_at: datetime
    password_history: List[str]
```

### 데이터베이스 스키마

```sql
-- Users 테이블
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    -- ... 기타 필드
    
    -- 인덱스
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

-- Audit Events 테이블
CREATE TABLE audit_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id UUID,
    username VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    
    -- 인덱스
    INDEX idx_event_type (event_type),
    INDEX idx_user_id (user_id),
    INDEX idx_timestamp (timestamp)
);
```

## 보안 아키텍처

### 1. 인증 흐름

```
┌──────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│Client│────▶│User Service  │────▶│ PostgreSQL  │     │  Redis   │
└──────┘     └──────────────┘     └─────────────┘     └──────────┘
   │               │                      │                  │
   │  1. Login     │                      │                  │
   │──────────────▶│                      │                  │
   │               │  2. Verify Password  │                  │
   │               │─────────────────────▶│                  │
   │               │                      │                  │
   │               │  3. Check MFA        │                  │
   │               │◀─────────────────────│                  │
   │               │                      │                  │
   │  4. MFA Code  │                      │                  │
   │──────────────▶│                      │                  │
   │               │  5. Create Session   │                  │
   │               │─────────────────────────────────────────▶│
   │               │                      │                  │
   │  6. JWT Token │                      │                  │
   │◀──────────────│                      │                  │
```

### 2. 토큰 구조

**Access Token (JWT)**
```json
{
  "sub": "user-uuid",
  "username": "john.doe",
  "email": "john@example.com",
  "roles": ["user"],
  "permissions": ["read:ontology", "write:schema"],
  "teams": ["backend", "platform"],
  "type": "access",
  "exp": 1234567890,
  "iat": 1234567890,
  "sid": "session-uuid"
}
```

**Refresh Token**
- 더 긴 만료 시간
- 최소한의 클레임
- 토큰 회전 지원

### 3. 보안 계층

1. **네트워크 보안**
   - HTTPS 필수
   - TLS 1.2+

2. **애플리케이션 보안**
   - 입력 검증
   - SQL Injection 방지
   - XSS/CSRF 보호

3. **데이터 보안**
   - 비밀번호: Argon2/Bcrypt
   - MFA 시크릿: 암호화
   - 민감 데이터 마스킹

4. **접근 제어**
   - RBAC
   - 최소 권한 원칙
   - API Rate Limiting

## API 설계

### RESTful 원칙

- **자원 중심**: /users, /sessions
- **HTTP 메서드 활용**: GET, POST, PUT, DELETE
- **상태 코드**: 적절한 HTTP 상태 코드 사용
- **HATEOAS**: 링크를 통한 상태 전이 (부분 적용)

### API 버전 관리

```
/api/v1/auth/login    # 현재 버전
/api/v2/auth/login    # 미래 버전 (계획)
```

### 에러 응답 표준

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid username or password",
    "details": {
      "field": "password",
      "reason": "incorrect"
    },
    "timestamp": "2024-01-15T10:00:00Z",
    "request_id": "req-123456"
  }
}
```

## 성능 최적화

### 1. 캐싱 전략

**Redis 캐시 사용**
- 세션 데이터
- 사용자 권한
- Rate Limit 카운터
- 토큰 블랙리스트

```python
# 캐시 키 구조
user:session:{session_id}     # 세션 데이터
user:permissions:{user_id}    # 권한 캐시
rate_limit:ip:{ip_address}    # Rate Limit
revoked_token:{jti}          # 철회된 토큰
```

### 2. 데이터베이스 최적화

- **인덱싱**: 자주 조회되는 필드
- **Connection Pooling**: 연결 재사용
- **Prepared Statements**: SQL 파싱 최소화
- **비동기 쿼리**: AsyncPG 활용

### 3. 비동기 처리

```python
# FastAPI + AsyncIO
async def login(credentials):
    # 병렬 처리
    user_task = get_user(credentials.username)
    rate_limit_task = check_rate_limit(request.ip)
    
    user, rate_limit_ok = await asyncio.gather(
        user_task, rate_limit_task
    )
```

## 확장성 고려사항

### 1. 수평적 확장

**스테이트리스 설계**
- 세션 데이터는 Redis에 저장
- 각 인스턴스는 독립적으로 동작

**로드 밸런싱**
```
                 ┌─────────────┐
                 │Load Balancer│
                 └──────┬──────┘
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼───┐    ┌────▼───┐    ┌────▼───┐
   │Service1│    │Service2│    │Service3│
   └────────┘    └────────┘    └────────┘
```

### 2. 데이터베이스 확장

**읽기 복제본**
- 읽기 전용 쿼리는 복제본으로
- 쓰기는 마스터로

**샤딩 (미래 계획)**
- User ID 기반 샤딩
- 지역별 샤딩

### 3. 캐시 확장

**Redis Cluster**
- 자동 샤딩
- 고가용성
- 선형적 확장

### 4. 모니터링 및 관찰성

**메트릭 수집**
- Prometheus 형식
- 응답 시간
- 에러율
- 동시 사용자

**로깅**
- 구조화된 JSON 로그
- 분산 추적 (OpenTelemetry)
- 중앙 집중식 로그 수집

**알림**
- 이상 징후 감지
- 임계값 기반 알림
- 자동 스케일링 트리거

## 재해 복구

### 백업 전략
- 데이터베이스: 일일 전체 백업, 시간별 증분
- 설정: Git 버전 관리
- 시크릿: 안전한 금고 (Vault)

### 복구 절차
1. 데이터베이스 복원
2. Redis 캐시 재구축
3. 서비스 재시작
4. 헬스 체크 확인

### RTO/RPO 목표
- RTO (Recovery Time Objective): < 1시간
- RPO (Recovery Point Objective): < 1시간