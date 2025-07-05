# User Service 테스트 가이드

## 개요
이 문서는 User Service의 완전한 테스트를 수행하는 방법을 설명합니다.

## 테스트 유형

### 1. 단위 테스트 (Unit Tests)
개별 함수와 클래스를 테스트합니다.

```bash
# 모든 단위 테스트 실행
pytest tests/test_validators.py -v

# 보안 요약 테스트 실행
pytest tests/test_security_summary.py -v
```

### 2. 통합 테스트 (Integration Tests)
데이터베이스와 Redis를 포함한 통합 테스트입니다.

```bash
# 테스트 환경 시작
docker-compose -f docker-compose.test.yml up -d

# 통합 테스트 실행
pytest tests/test_integration.py -v
```

### 3. E2E 테스트 (End-to-End Tests)
실제 서비스를 띄우고 전체 사용자 플로우를 테스트합니다.

```bash
# E2E 테스트 실행 (서비스 자동 시작)
./run_e2e_tests.sh
```

E2E 테스트는 다음을 검증합니다:
- 완전한 사용자 생명주기 (등록, 로그인, 정보 조회, 비밀번호 변경)
- 보안 헤더 검증
- 속도 제한 기능
- 입력 검증 및 살균
- 비밀번호 정책

### 4. 부하 테스트 (Load Tests)
Locust를 사용하여 서비스의 성능과 확장성을 테스트합니다.

```bash
# 서비스가 실행 중이어야 함
./run_load_tests.sh
```

부하 테스트 시나리오:
- 일반 부하: 10 사용자
- 높은 부하: 50 사용자
- 스트레스 테스트: 100 사용자
- 속도 제한 테스트: 빠른 요청

결과는 HTML 리포트로 생성됩니다:
- `tests/load_test_report_normal.html`
- `tests/load_test_report_high.html`
- `tests/load_test_report_stress.html`
- `tests/load_test_report_rate_limit.html`

### 5. 보안 스캔 (Security Scan)
여러 보안 도구를 사용하여 취약점을 검사합니다.

```bash
# 보안 스캔 실행
./security_scan.sh
```

사용되는 도구:
- **Bandit**: Python 코드 보안 분석
- **Safety**: 의존성 취약점 검사
- **pip-audit**: Python 패키지 감사
- **Semgrep**: 정적 보안 분석
- **Custom Checks**: 프로젝트별 보안 패턴

결과는 `security_reports/` 디렉토리에 저장됩니다.

## 테스트 환경 설정

### 1. 의존성 설치
```bash
# 테스트 의존성 설치
pip install pytest pytest-asyncio httpx

# 부하 테스트 도구
pip install locust

# 보안 스캔 도구
pip install bandit safety pip-audit semgrep
```

### 2. Docker 컨테이너
```bash
# 테스트 DB와 Redis 시작
docker-compose -f docker-compose.test.yml up -d

# 상태 확인
docker-compose -f docker-compose.test.yml ps

# 종료
docker-compose -f docker-compose.test.yml down
```

### 3. 환경 변수
테스트용 `.env.test` 파일이 제공됩니다:
```
DATABASE_URL=postgresql+asyncpg://test_user:test_password@localhost:5433/test_user_service
REDIS_URL=redis://localhost:6380
JWT_SECRET=test-secret-key-for-testing-purposes-only-minimum-32-characters
DEBUG=true
```

## CI/CD 통합

GitHub Actions를 위한 예제 워크플로우:

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
          POSTGRES_USER: test_user
          POSTGRES_DB: test_user_service
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5433:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6380:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio httpx
    
    - name: Run unit tests
      run: pytest tests/test_validators.py tests/test_security_summary.py -v
    
    - name: Run security scan
      run: |
        pip install bandit safety
        bandit -r src/
        safety check
```

## 테스트 커버리지

현재 구현된 테스트:
- ✅ 입력 검증 (22 테스트)
- ✅ 보안 기능 검증 (10 테스트)
- ✅ 통합 테스트 (18 테스트)
- ✅ E2E 테스트 (5 시나리오)
- ✅ 부하 테스트 (4 시나리오)
- ✅ 보안 스캔 (5 도구)

## 문제 해결

### 통합 테스트 실패
- Docker 컨테이너가 실행 중인지 확인
- 포트 충돌 확인 (5433, 6380)
- 데이터베이스 연결 확인

### E2E 테스트 실패
- 서비스가 8000 포트에서 실행 중인지 확인
- 환경 변수가 올바르게 설정되었는지 확인

### 부하 테스트 실패
- 서비스가 실행 중인지 확인
- 시스템 리소스 확인 (CPU, 메모리)

## 모범 사례

1. **정기적인 테스트**: CI/CD 파이프라인에 모든 테스트 통합
2. **보안 스캔**: 매주 보안 스캔 실행
3. **부하 테스트**: 주요 변경 사항 후 부하 테스트 실행
4. **테스트 데이터**: 프로덕션 데이터를 테스트에 사용하지 않음
5. **테스트 격리**: 각 테스트는 독립적으로 실행 가능해야 함