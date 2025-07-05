# User Service

엔터프라이즈급 사용자 인증 및 권한 관리 마이크로서비스

## 📋 목차

- [개요](#개요)
- [주요 기능](#주요-기능)
- [기술 스택](#기술-스택)
- [시작하기](#시작하기)
- [API 문서](#api-문서)
- [보안](#보안)
- [테스트](#테스트)
- [배포](#배포)

## 개요

User Service는 Arrakis 프로젝트의 핵심 인증/인가 마이크로서비스입니다. JWT 기반 인증, RBAC(Role-Based Access Control), MFA(Multi-Factor Authentication) 등 엔터프라이즈급 보안 기능을 제공합니다.

### 아키텍처 위치

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Gateway   │────▶│User Service │◀────│Other Services│
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │  PostgreSQL │
                    └─────────────┘
```

## 주요 기능

### 🔐 인증 (Authentication)
- JWT 토큰 기반 인증
- Access Token / Refresh Token 지원
- 세션 관리 및 토큰 철회

### 🔑 인가 (Authorization)
- RBAC (Role-Based Access Control)
- 세밀한 권한 관리 (Permissions)
- 팀 기반 접근 제어

### 🛡️ 보안 기능
- **MFA (Multi-Factor Authentication)**
  - TOTP (Time-based One-Time Password)
  - QR 코드 생성
  - 백업 코드 지원
- **비밀번호 정책**
  - 복잡도 요구사항
  - 비밀번호 히스토리
  - 만료 정책
- **Rate Limiting**
  - IP 기반 요청 제한
  - 엔드포인트별 세밀한 제어
- **감사 로깅**
  - 모든 보안 이벤트 기록
  - 실시간 모니터링 지원

### 🔄 통합 기능
- OMS IAM 호환 API
- 표준 OAuth2 흐름 지원
- 마이크로서비스 간 인증

## 기술 스택

- **Language**: Python 3.11+
- **Framework**: FastAPI
- **Database**: PostgreSQL (AsyncPG)
- **Cache**: Redis
- **ORM**: SQLAlchemy 2.0
- **Security**: 
  - JWT (PyJWT)
  - Argon2 + Bcrypt (Passlib)
  - TOTP (PyOTP)

## 시작하기

### 사전 요구사항

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Docker (선택사항)

### 설치

1. **저장소 클론**
```bash
git clone https://github.com/ludia8888/User-Service.git
cd User-Service
```

2. **가상환경 설정**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3. **의존성 설치**
```bash
pip install -r requirements.txt
```

4. **환경 변수 설정**
```bash
cp .env.example .env
# .env 파일을 편집하여 설정값 입력
```

필수 환경 변수:
```env
# 데이터베이스
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/userservice

# Redis
REDIS_URL=redis://localhost:6379

# JWT (반드시 변경!)
JWT_SECRET=your-secure-random-secret-key-at-least-32-chars

# CORS
CORS_ORIGINS=["http://localhost:3000", "https://yourdomain.com"]
```

5. **데이터베이스 마이그레이션**
```bash
alembic upgrade head
```

6. **서비스 실행**
```bash
uvicorn src.main:app --reload --port 8000
```

### Docker 실행

```bash
# 빌드
docker build -t user-service .

# 실행
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql+asyncpg://..." \
  -e REDIS_URL="redis://..." \
  -e JWT_SECRET="your-secret" \
  user-service
```

### Docker Compose

```bash
docker-compose up -d
```

## API 문서

서비스 실행 후 아래 URL에서 API 문서를 확인할 수 있습니다:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### 주요 엔드포인트

#### 인증
- `POST /auth/register` - 사용자 등록
- `POST /auth/login` - 로그인
- `POST /auth/logout` - 로그아웃
- `POST /auth/refresh` - 토큰 갱신
- `GET /auth/userinfo` - 사용자 정보 조회

#### MFA
- `POST /auth/mfa/setup` - MFA 설정
- `POST /auth/mfa/enable` - MFA 활성화
- `POST /auth/mfa/disable` - MFA 비활성화
- `POST /auth/mfa/regenerate-backup-codes` - 백업 코드 재생성

#### 비밀번호 관리
- `POST /auth/change-password` - 비밀번호 변경

#### IAM 호환 API
- `POST /iam/validate-token` - 토큰 검증
- `POST /iam/user-info` - 사용자 정보 조회
- `POST /iam/check-permission` - 권한 확인

## 보안

### 구현된 보안 기능

1. **JWT 토큰 보안**
   - 안전한 시크릿 키 검증
   - 토큰 만료 관리
   - 세션 ID를 통한 토큰 철회

2. **비밀번호 보안**
   - Argon2 해싱 (Bcrypt 폴백)
   - 정책 기반 검증
   - 히스토리 추적

3. **API 보안**
   - Rate Limiting
   - CORS 설정
   - 보안 헤더
   - 입력 검증

4. **감사 로깅**
   - 모든 인증 이벤트
   - 실패한 로그인 시도
   - 권한 변경 사항

자세한 내용은 [SECURITY_IMPROVEMENTS.md](SECURITY_IMPROVEMENTS.md) 참조

## 테스트

### 테스트 실행

```bash
# 모든 테스트 실행
pytest

# 커버리지 포함
pytest --cov=src

# 특정 테스트만 실행
pytest tests/test_security.py
```

### 테스트 범위

- 인증/인가 테스트
- 비밀번호 정책 테스트
- 입력 검증 테스트
- 보안 헤더 테스트
- MFA 기능 테스트
- Rate Limiting 테스트

## 배포

### 프로덕션 체크리스트

- [ ] JWT_SECRET 환경변수 설정
- [ ] DEBUG=False 설정
- [ ] CORS 오리진 제한
- [ ] HTTPS 적용
- [ ] 데이터베이스 백업 설정
- [ ] 로그 수집 설정
- [ ] 모니터링 설정

### 쿠버네티스 배포

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: your-registry/user-service:latest
        ports:
        - containerPort: 8000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: user-service-secrets
              key: jwt-secret
```

## 모니터링

- **Health Check**: `GET /health`
- **Metrics**: Prometheus 형식 지원 (계획됨)
- **Logs**: JSON 구조화 로깅

## 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.

## 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 문의

프로젝트 관련 문의사항은 이슈 트래커를 통해 등록해주세요.