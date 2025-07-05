# User Service MSA 통합 가이드

## 목차

1. [개요](#개요)
2. [통합 아키텍처](#통합-아키텍처)
3. [서비스 간 인증](#서비스-간-인증)
4. [API Gateway 통합](#api-gateway-통합)
5. [다른 마이크로서비스와의 통합](#다른-마이크로서비스와의-통합)
6. [통합 패턴](#통합-패턴)
7. [보안 고려사항](#보안-고려사항)
8. [모니터링 및 추적](#모니터링-및-추적)
9. [문제 해결](#문제-해결)

## 개요

User Service는 Arrakis MSA(Microservice Architecture) 환경에서 중앙 인증/인가 서비스 역할을 합니다. 모든 마이크로서비스는 사용자 인증과 권한 확인을 위해 User Service와 통합되어야 합니다.

### 핵심 역할

- **인증 제공자**: 모든 서비스의 사용자 인증 담당
- **권한 관리자**: 중앙에서 권한과 역할 관리
- **토큰 발급자**: JWT 토큰 생성 및 검증
- **감사 로깅**: 보안 이벤트 중앙 기록

## 통합 아키텍처

### MSA 전체 구조에서의 위치

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Client Applications                        │
│                    (Web, Mobile, Desktop, IoT)                      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                           API Gateway                                │
│                   (Kong, Nginx, Spring Cloud Gateway)                │
│  • 라우팅  • 로드밸런싱  • 인증 토큰 검증  • Rate Limiting          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────▼────────┐     ┌───────▼────────┐     ┌───────▼────────┐
│  User Service  │     │  OMS Service   │     │ Other Services │
│                │◀────│                │◀────│                │
│ • 인증/인가    │     │ • 주문 관리    │     │ • 비즈니스     │
│ • 사용자 관리  │     │ • 온톨로지     │     │   로직         │
└────────────────┘     └────────────────┘     └────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Service Discovery    │
                    │  (Consul, Eureka, K8s) │
                    └────────────────────────┘
```

### 서비스 간 통신 흐름

```
1. 클라이언트 → API Gateway
   - 인증 토큰 포함 요청

2. API Gateway → User Service
   - 토큰 검증 요청

3. User Service → API Gateway
   - 토큰 유효성 및 권한 정보 응답

4. API Gateway → Target Service
   - 검증된 사용자 정보와 함께 요청 전달

5. Target Service → User Service (필요시)
   - 추가 권한 확인 또는 사용자 정보 조회
```

## 서비스 간 인증

### 1. JWT 토큰 기반 인증

**토큰 전달 방식**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**토큰 검증 엔드포인트**
```http
POST /iam/validate-token
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "required_scopes": ["ontology:read", "schema:write"]
}
```

**응답 예시**
```json
{
  "valid": true,
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "john.doe",
  "email": "john@example.com",
  "roles": ["admin", "operator"],
  "permissions": ["ontology:*:*", "schema:*:*"],
  "teams": ["backend", "platform"],
  "exp": 1705312800
}
```

### 2. 서비스 간 직접 통신

**Service-to-Service 인증**
```python
# 다른 서비스에서 User Service 호출 예시
import httpx

class UserServiceClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.client = httpx.AsyncClient()
    
    async def validate_token(self, token: str):
        headers = {
            "X-API-Key": self.api_key,  # 서비스 간 인증
            "Content-Type": "application/json"
        }
        
        response = await self.client.post(
            f"{self.base_url}/iam/validate-token",
            json={"token": token},
            headers=headers
        )
        
        return response.json()
    
    async def get_user_info(self, user_id: str):
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        
        response = await self.client.post(
            f"{self.base_url}/iam/user-info",
            json={"user_id": user_id},
            headers=headers
        )
        
        return response.json()
```

## API Gateway 통합

### 1. Kong Gateway 설정 예시

```yaml
# kong.yaml
services:
  - name: user-service
    url: http://user-service:8000
    routes:
      - name: user-service-route
        paths:
          - /api/v1/auth
        strip_path: false

plugins:
  - name: jwt
    service: user-service
    config:
      secret_is_base64: false
      key_claim_name: sub
      claims_to_verify:
        - exp
        - type

  - name: request-transformer
    service: user-service
    config:
      add:
        headers:
          - X-User-Id:$(jwt.sub)
          - X-User-Roles:$(jwt.roles)
```

### 2. Spring Cloud Gateway 설정

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://USER-SERVICE
          predicates:
            - Path=/api/v1/auth/**
          filters:
            - name: AuthenticationFilter
              args:
                validateUrl: http://user-service:8000/iam/validate-token

        - id: protected-service
          uri: lb://OTHER-SERVICE
          predicates:
            - Path=/api/v1/protected/**
          filters:
            - AuthenticationFilter
            - AddRequestHeader=X-User-Id, #{principal.userId}
            - AddRequestHeader=X-User-Roles, #{principal.roles}
```

### 3. Nginx 설정 예시

```nginx
# nginx.conf
upstream user_service {
    server user-service-1:8000;
    server user-service-2:8000;
    server user-service-3:8000;
}

location /api/v1/auth {
    proxy_pass http://user_service;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location /api/v1/protected {
    # 인증 검증
    auth_request /auth/verify;
    auth_request_set $user_id $upstream_http_x_user_id;
    auth_request_set $user_roles $upstream_http_x_user_roles;
    
    # 헤더 전달
    proxy_set_header X-User-Id $user_id;
    proxy_set_header X-User-Roles $user_roles;
    
    proxy_pass http://backend_service;
}

location = /auth/verify {
    internal;
    proxy_pass http://user_service/iam/validate-token;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header Authorization $http_authorization;
}
```

## 다른 마이크로서비스와의 통합

### 1. OMS Service 통합 예시

```python
# OMS Service에서 User Service 활용
from fastapi import Depends, HTTPException, Header
from typing import Optional

class AuthMiddleware:
    def __init__(self, user_service_client: UserServiceClient):
        self.client = user_service_client
    
    async def verify_token(
        self, 
        authorization: Optional[str] = Header(None)
    ):
        if not authorization:
            raise HTTPException(401, "Missing authorization header")
        
        token = authorization.replace("Bearer ", "")
        result = await self.client.validate_token(token)
        
        if not result["valid"]:
            raise HTTPException(401, "Invalid token")
        
        return result

# 사용 예시
@app.get("/api/v1/ontology/{ontology_id}")
async def get_ontology(
    ontology_id: str,
    user_info = Depends(auth_middleware.verify_token)
):
    # 권한 확인
    if "ontology:read" not in user_info["permissions"]:
        raise HTTPException(403, "Insufficient permissions")
    
    # 비즈니스 로직
    return get_ontology_data(ontology_id)
```

### 2. 권한 기반 접근 제어

```python
# 권한 데코레이터
def require_permission(permission: str):
    def decorator(func):
        async def wrapper(*args, user_info = Depends(get_current_user), **kwargs):
            if permission not in user_info["permissions"]:
                raise HTTPException(
                    403, 
                    f"Permission '{permission}' required"
                )
            return await func(*args, user_info=user_info, **kwargs)
        return wrapper
    return decorator

# 사용 예시
@app.post("/api/v1/schema")
@require_permission("schema:write")
async def create_schema(
    schema_data: SchemaCreate,
    user_info: dict
):
    # user_info에서 사용자 정보 활용
    schema_data.created_by = user_info["user_id"]
    return create_new_schema(schema_data)
```

### 3. 이벤트 기반 통합

```python
# 사용자 이벤트 발행 (User Service)
async def publish_user_event(event_type: str, user_data: dict):
    message = {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": user_data
    }
    
    await redis_client.publish(
        "user_events", 
        json.dumps(message)
    )

# 다른 서비스에서 구독
async def subscribe_user_events():
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("user_events")
    
    async for message in pubsub.listen():
        if message["type"] == "message":
            event = json.loads(message["data"])
            
            if event["event_type"] == "user_created":
                await handle_new_user(event["data"])
            elif event["event_type"] == "permission_changed":
                await invalidate_permission_cache(event["data"]["user_id"])
```

## 통합 패턴

### 1. API Gateway 패턴

**장점**
- 중앙 집중식 인증
- 단일 진입점
- 횡단 관심사 처리

**구현**
```yaml
# Docker Compose 예시
services:
  api-gateway:
    image: kong:latest
    environment:
      - KONG_DATABASE=postgres
      - KONG_PG_HOST=kong-db
    ports:
      - "8000:8000"
    depends_on:
      - user-service
      
  user-service:
    build: ./user-service
    environment:
      - DATABASE_URL=postgresql://...
    ports:
      - "8001:8000"
```

### 2. Service Mesh 패턴 (Istio)

```yaml
# Istio 인증 정책
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: default
spec:
  selector:
    matchLabels:
      app: backend-services
  jwtRules:
  - issuer: "user-service"
    jwksUri: http://user-service:8000/.well-known/jwks.json
    audiences:
    - "oms"
    forwardOriginalToken: true
```

### 3. Sidecar 패턴

```yaml
# Kubernetes Pod with Auth Sidecar
apiVersion: v1
kind: Pod
metadata:
  name: oms-service
spec:
  containers:
  - name: oms-service
    image: oms-service:latest
    ports:
    - containerPort: 8080
    
  - name: auth-proxy
    image: auth-proxy:latest
    ports:
    - containerPort: 8000
    env:
    - name: USER_SERVICE_URL
      value: "http://user-service:8000"
    - name: UPSTREAM_URL
      value: "http://localhost:8080"
```

## 보안 고려사항

### 1. 네트워크 보안

**서비스 간 TLS**
```yaml
# Docker Compose with TLS
services:
  user-service:
    environment:
      - TLS_CERT=/certs/server.crt
      - TLS_KEY=/certs/server.key
      - TLS_CA=/certs/ca.crt
    volumes:
      - ./certs:/certs:ro
```

**네트워크 격리**
```yaml
networks:
  backend:
    driver: bridge
    internal: true  # 외부 접근 차단
  
  frontend:
    driver: bridge
```

### 2. 시크릿 관리

**HashiCorp Vault 통합**
```python
import hvac

class SecretManager:
    def __init__(self):
        self.client = hvac.Client(
            url='http://vault:8200',
            token=os.getenv('VAULT_TOKEN')
        )
    
    def get_jwt_secret(self):
        response = self.client.secrets.kv.v2.read_secret_version(
            path='user-service/jwt'
        )
        return response['data']['data']['secret']
```

### 3. Zero Trust 보안

```python
# 모든 요청 검증
class ZeroTrustMiddleware:
    async def __call__(self, request: Request, call_next):
        # 1. 발신자 확인
        client_id = request.headers.get("X-Client-Id")
        if not self.verify_client(client_id):
            return JSONResponse(status_code=401)
        
        # 2. 토큰 검증
        token = request.headers.get("Authorization")
        if not await self.verify_token(token):
            return JSONResponse(status_code=401)
        
        # 3. 권한 확인
        if not self.check_permissions(request.url.path):
            return JSONResponse(status_code=403)
        
        return await call_next(request)
```

## 모니터링 및 추적

### 1. 분산 추적 (Distributed Tracing)

**OpenTelemetry 설정**
```python
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

# 추적 설정
tracer = trace.get_tracer(__name__)

# FastAPI 자동 계측
FastAPIInstrumentor.instrument_app(app)

# 커스텀 추적
@app.post("/api/v1/auth/login")
async def login(credentials: LoginRequest):
    with tracer.start_as_current_span("user_authentication"):
        # 추적 속성 추가
        span = trace.get_current_span()
        span.set_attribute("user.username", credentials.username)
        span.set_attribute("auth.method", "password")
        
        # 인증 로직
        user = await authenticate_user(credentials)
        
        span.set_attribute("auth.success", True)
        span.set_attribute("user.id", user.id)
        
        return create_tokens(user)
```

### 2. 메트릭 수집

```python
from prometheus_client import Counter, Histogram, Gauge

# 메트릭 정의
auth_requests = Counter(
    'auth_requests_total',
    'Total authentication requests',
    ['method', 'status']
)

auth_duration = Histogram(
    'auth_duration_seconds',
    'Authentication request duration'
)

active_sessions = Gauge(
    'active_sessions',
    'Number of active user sessions'
)

# 메트릭 사용
@auth_duration.time()
async def authenticate(credentials):
    try:
        user = await verify_credentials(credentials)
        auth_requests.labels(method='password', status='success').inc()
        active_sessions.inc()
        return user
    except Exception as e:
        auth_requests.labels(method='password', status='failure').inc()
        raise
```

### 3. 중앙 집중식 로깅

```python
import logging
from pythonjsonlogger import jsonlogger

# JSON 형식 로거 설정
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

# 상관 ID를 포함한 로깅
async def log_with_context(request: Request, message: str, **kwargs):
    context = {
        "correlation_id": request.headers.get("X-Correlation-ID"),
        "user_id": request.state.user_id,
        "service": "user-service",
        "timestamp": datetime.utcnow().isoformat(),
        **kwargs
    }
    logger.info(message, extra=context)
```

## 문제 해결

### 1. 일반적인 통합 문제

**문제: 토큰 검증 실패**
```python
# 디버깅 코드
@app.post("/debug/token")
async def debug_token(token: str):
    try:
        # 토큰 디코드 (검증 없이)
        import jwt
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # 시그니처 검증
        verified = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        
        return {
            "payload": payload,
            "verified": True,
            "expires_at": datetime.fromtimestamp(payload["exp"])
        }
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError as e:
        return {"error": str(e)}
```

**문제: 서비스 간 통신 실패**
```python
# 헬스 체크 엔드포인트
@app.get("/health/dependencies")
async def check_dependencies():
    checks = {}
    
    # User Service 연결 확인
    try:
        response = await httpx.get(f"{USER_SERVICE_URL}/health")
        checks["user_service"] = response.status_code == 200
    except:
        checks["user_service"] = False
    
    # Redis 연결 확인
    try:
        await redis_client.ping()
        checks["redis"] = True
    except:
        checks["redis"] = False
    
    # Database 연결 확인
    try:
        await db.execute("SELECT 1")
        checks["database"] = True
    except:
        checks["database"] = False
    
    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503
    
    return JSONResponse(
        status_code=status_code,
        content={"status": "healthy" if all_healthy else "unhealthy", "checks": checks}
    )
```

### 2. 성능 최적화

**토큰 캐싱**
```python
class TokenCache:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.ttl = 300  # 5분
    
    async def get_validated_token(self, token: str):
        # 캐시 확인
        cached = await self.redis.get(f"token:{token}")
        if cached:
            return json.loads(cached)
        
        # 검증 및 캐싱
        result = await validate_token(token)
        await self.redis.setex(
            f"token:{token}",
            self.ttl,
            json.dumps(result)
        )
        
        return result
```

### 3. 회로 차단기 패턴

```python
from circuit_breaker import CircuitBreaker

class UserServiceClient:
    def __init__(self):
        self.breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30,
            expected_exception=httpx.RequestError
        )
    
    @self.breaker
    async def validate_token(self, token: str):
        # 실패 시 자동으로 회로 차단
        response = await httpx.post(
            f"{USER_SERVICE_URL}/iam/validate-token",
            json={"token": token},
            timeout=5.0
        )
        return response.json()
```

## 마이그레이션 가이드

### 기존 모놀리스에서 마이그레이션

1. **단계별 분리**
   ```
   Phase 1: 인증 로직 추출
   Phase 2: 사용자 데이터 마이그레이션
   Phase 3: 권한 시스템 통합
   Phase 4: 레거시 코드 제거
   ```

2. **Strangler Fig 패턴**
   ```nginx
   # 점진적 라우팅
   location /api/v1/auth {
       proxy_pass http://user-service;  # 새 서비스
   }
   
   location /api/legacy/auth {
       proxy_pass http://monolith;       # 기존 시스템
   }
   ```

3. **데이터 동기화**
   ```python
   # 이중 쓰기 패턴
   async def create_user(user_data):
       # 새 시스템에 쓰기
       new_user = await new_db.create_user(user_data)
       
       # 레거시 시스템에도 쓰기
       await legacy_db.create_user(user_data)
       
       return new_user
   ```

## 참고 자료

- [User Service API 문서](/docs)
- [보안 가이드](SECURITY_IMPROVEMENTS.md)
- [아키텍처 문서](ARCHITECTURE.md)
- [OpenAPI 스펙](/openapi.json)