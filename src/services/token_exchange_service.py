"""
Token Exchange Service
서비스 간 인증을 위한 토큰 교환 서비스
"""
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update, select

from models.service_client import ServiceClient
from core.exceptions import AuthenticationError, ValidationError
from core.config import settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenExchangeService:
    """
    서비스 간 토큰 교환을 처리하는 서비스
    
    OAuth 2.0 Token Exchange (RFC 8693) 패턴을 단순화하여 구현
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        
        # JWT configuration
        self.jwt_algorithm = settings.JWT_ALGORITHM
        self.service_token_expire_minutes = 60  # 서비스 토큰은 60분 유효
        
        # Handle different algorithms
        if self.jwt_algorithm in ["RS256", "RS384", "RS512"]:
            # For RSA algorithms, use the private key for signing
            import base64
            private_key_b64 = os.environ.get("JWT_PRIVATE_KEY_BASE64")
            if private_key_b64:
                self.jwt_secret = base64.b64decode(private_key_b64).decode('utf-8')
            else:
                raise ValueError("JWT_PRIVATE_KEY_BASE64 is required for RSA algorithms")
        else:
            # For symmetric algorithms (HS256, etc.), use the shared secret
            self.jwt_secret = settings.JWT_SECRET
    
    async def verify_client_credentials(self, client_id: str, client_secret: str) -> ServiceClient:
        """
        서비스 클라이언트 자격증명 검증
        
        Args:
            client_id: 클라이언트 ID
            client_secret: 클라이언트 비밀키
            
        Returns:
            ServiceClient: 검증된 서비스 클라이언트
            
        Raises:
            AuthenticationError: 인증 실패 시
        """
        # 1. 클라이언트 조회
        result = await self.db.execute(
            select(ServiceClient).where(
                ServiceClient.client_id == client_id,
                ServiceClient.is_active == True
            )
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise AuthenticationError("Invalid client credentials")
        
        # 2. 비밀키 검증
        if not pwd_context.verify(client_secret, client.client_secret_hash):
            raise AuthenticationError("Invalid client credentials")
        
        # 3. client_credentials grant type 지원 확인
        if not client.has_grant_type("client_credentials"):
            raise AuthenticationError("Client credentials grant not allowed for this client")
        
        # 4. 마지막 사용 시간 업데이트
        await self.db.execute(
            update(ServiceClient)
            .where(ServiceClient.client_id == client_id)
            .values(last_used_at=datetime.utcnow())
        )
        await self.db.commit()
        
        return client
    
    def create_service_token(self, client: ServiceClient, requested_scopes: Optional[str] = None, audience: Optional[str] = None) -> str:
        """
        서비스용 JWT 토큰 생성
        
        Args:
            client: 검증된 서비스 클라이언트
            requested_scopes: 요청된 권한 범위 (공백으로 구분)
            audience: 토큰의 대상 audience (기본값: "oms")
            
        Returns:
            str: JWT 토큰
        """
        # 요청된 스코프 처리
        if requested_scopes:
            scopes = requested_scopes.split()
            # 허용된 스코프만 부여
            granted_scopes = [s for s in scopes if client.has_scope(s)]
        else:
            # 기본적으로 모든 허용된 스코프 부여
            granted_scopes = client.allowed_scopes or []
        
        # 토큰 페이로드 생성
        # 현재 시간을 UTC 기준으로 정확히 계산
        import calendar
        now = datetime.utcnow()
        now_timestamp = calendar.timegm(now.utctimetuple())
        exp_timestamp = now_timestamp + (self.service_token_expire_minutes * 60)
        
        payload = {
            # 표준 JWT claims
            "sub": f"service:{client.service_name}",
            "iat": now_timestamp,
            "exp": exp_timestamp,
            "aud": audience or "oms",  # audience (default to "oms" if not specified)
            "iss": "user-service",  # issuer
            
            # 서비스 관련 claims
            "client_id": client.client_id,
            "service_name": client.service_name,
            "is_service_account": True,
            "grant_type": "client_credentials",
            
            # 권한 관련
            "scopes": granted_scopes,
            "permissions": granted_scopes,  # 호환성을 위해 중복
            
            # 사용자 정보 (서비스 계정용)
            "user_id": f"service:{client.service_name}",
            "username": client.service_name,
            
            # 메타데이터
            "token_type": "service",
            "version": "1.0"
        }
        
        # JWT 토큰 생성
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        return token
    
    async def exchange_token(
        self, 
        client_id: str, 
        client_secret: str,
        requested_scopes: Optional[str] = None,
        audience: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        토큰 교환 수행
        
        Args:
            client_id: 서비스 클라이언트 ID
            client_secret: 서비스 클라이언트 비밀키
            requested_scopes: 요청할 권한 범위
            audience: 토큰의 대상 audience
            
        Returns:
            Dict: 토큰 응답 (access_token, token_type, expires_in, scope)
        """
        # 1. 클라이언트 검증
        client = await self.verify_client_credentials(client_id, client_secret)
        
        # 2. 서비스 토큰 생성
        access_token = self.create_service_token(client, requested_scopes, audience)
        
        # 3. 응답 생성
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.service_token_expire_minutes * 60,  # 초 단위
            "scope": " ".join(client.allowed_scopes or []),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": client.client_id,
            "service_name": client.service_name
        }
        
        return response
    
    def create_client_secret(self) -> tuple[str, str]:
        """
        새로운 클라이언트 비밀키 생성
        
        Returns:
            tuple: (평문 비밀키, 해시된 비밀키)
        """
        import secrets
        # 안전한 랜덤 비밀키 생성
        secret = secrets.token_urlsafe(32)
        hashed = pwd_context.hash(secret)
        return secret, hashed