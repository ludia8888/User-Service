"""
JWKS (JSON Web Key Set) Service
RFC 7517 준수 JWKS 엔드포인트 구현
"""
import os
import json
import uuid
from typing import Dict, List, Any
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import logging
import hashlib

logger = logging.getLogger(__name__)


class JWKSService:
    """
    JSON Web Key Set 관리 서비스
    RSA 키 쌍 생성, 관리 및 JWKS 형식으로 공개키 제공
    """
    
    def __init__(self):
        # 환경 변수에서 키 로드
        private_key_b64 = os.environ.get("JWT_PRIVATE_KEY_BASE64")
        public_key_b64 = os.environ.get("JWT_PUBLIC_KEY_BASE64")
        
        if not private_key_b64 or not public_key_b64:
            logger.error("❌ JWT 키가 환경 변수에 설정되지 않았습니다.")
            raise ValueError("JWT_PRIVATE_KEY_BASE64 and JWT_PUBLIC_KEY_BASE64 must be set")
        
        try:
            # Base64 디코드하여 키 로드
            private_key_pem = base64.b64decode(private_key_b64)
            public_key_pem = base64.b64decode(public_key_b64)
            
            # 키 객체로 변환
            self._private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            self._public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # PEM 바이트 저장 (기존 인터페이스 호환성)
            self._private_key_pem = private_key_pem
            self._public_key_pem = public_key_pem
            
            logger.info("✅ 환경 변수에서 JWT 키 로드 완료")
            
        except Exception as e:
            logger.error(f"❌ JWT 키 로드 실패: {e}")
            raise
        
        # JWKS 캐시
        self._jwks_cache = None
        self._cache_expiry = None
        self._cache_ttl = timedelta(hours=1)
        
        # 고정된 키 ID (환경 변수 기반 키는 변경되지 않음)
        # SHA256 해시의 첫 8자리 사용 (일관성 보장)
        key_hash = hashlib.sha256(private_key_b64[:50].encode()).hexdigest()[:8]
        self._key_id = f"key-env-{key_hash}"
    
    def _keys_exist(self) -> bool:
        """키가 로드되었는지 확인"""
        return self._private_key is not None and self._public_key is not None
    
    def _generate_keys(self) -> None:
        """RSA 키 쌍 생성"""
        try:
            logger.info("🔑 새로운 RSA 키 쌍 생성 중...")
            
            # RSA 키 쌍 생성 (2048비트)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # 개인키 저장
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(self.private_key_path, 'wb') as f:
                f.write(private_pem)
            
            # 공개키 저장
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(self.public_key_path, 'wb') as f:
                f.write(public_pem)
            
            # 파일 권한 설정 (개인키는 읽기 전용)
            os.chmod(self.private_key_path, 0o600)
            os.chmod(self.public_key_path, 0o644)
            
            logger.info("✅ RSA 키 쌍 생성 완료")
            
        except Exception as e:
            logger.error(f"❌ RSA 키 쌍 생성 실패: {e}")
            raise
    
    def get_private_key(self) -> bytes:
        """개인키 조회 (JWT 서명용)"""
        return self._private_key_pem
    
    def get_public_key(self) -> bytes:
        """공개키 조회"""
        return self._public_key_pem
    
    def _load_public_key_components(self) -> Dict[str, str]:
        """공개키에서 n, e 컴포넌트 추출"""
        try:
            public_key = self._public_key
            
            # RSA 공개키 숫자 추출
            public_numbers = public_key.public_numbers()
            
            # n (modulus)을 base64url로 인코딩
            n_bytes = public_numbers.n.to_bytes(
                (public_numbers.n.bit_length() + 7) // 8, 
                byteorder='big'
            )
            n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('ascii')
            
            # e (exponent)를 base64url로 인코딩
            e_bytes = public_numbers.e.to_bytes(
                (public_numbers.e.bit_length() + 7) // 8, 
                byteorder='big'
            )
            e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode('ascii')
            
            return {
                'n': n_b64,
                'e': e_b64
            }
            
        except Exception as e:
            logger.error(f"공개키 컴포넌트 추출 실패: {e}")
            raise
    
    def get_jwks(self) -> Dict[str, Any]:
        """
        JWKS (JSON Web Key Set) 반환
        RFC 7517 준수 형식
        """
        try:
            # 캐시 확인
            if (self._jwks_cache and self._cache_expiry and 
                datetime.utcnow() < self._cache_expiry):
                return self._jwks_cache
            
            logger.info("🔑 JWKS 생성 중...")
            
            # 공개키 컴포넌트 추출
            key_components = self._load_public_key_components()
            
            # 고정된 키 ID 사용
            key_id = self._key_id
            
            jwks = {
                "keys": [
                    {
                        # RFC 7517 필수 필드
                        "kty": "RSA",              # Key Type
                        "kid": key_id,             # Key ID
                        "use": "sig",              # Public Key Use
                        "alg": "RS256",            # Algorithm
                        
                        # RSA 공개키 컴포넌트
                        "n": key_components["n"],   # Modulus
                        "e": key_components["e"],   # Exponent
                        
                        # 선택적 메타데이터
                        "key_ops": ["verify"],      # Key Operations
                        "x5t": None,               # X.509 Thumbprint (사용 안함)
                        "x5c": None,               # X.509 Certificate Chain (사용 안함)
                    }
                ]
            }
            
            # 캐시 업데이트
            self._jwks_cache = jwks
            self._cache_expiry = datetime.utcnow() + self._cache_ttl
            
            logger.info(f"✅ JWKS 생성 완료 - Key ID: {key_id}")
            return jwks
            
        except Exception as e:
            logger.error(f"❌ JWKS 생성 실패: {e}")
            raise
    
    def rotate_keys(self) -> None:
        """
        키 회전 (보안 강화)
        기존 키를 백업하고 새 키 생성
        """
        try:
            logger.info("🔄 키 회전 시작...")
            
            # 기존 키 백업
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_private = f"{self.private_key_path}.backup_{timestamp}"
            backup_public = f"{self.public_key_path}.backup_{timestamp}"
            
            if self._keys_exist():
                os.rename(self.private_key_path, backup_private)
                os.rename(self.public_key_path, backup_public)
                logger.info(f"기존 키 백업 완료: {timestamp}")
            
            # 새 키 생성
            self._generate_keys()
            
            # 캐시 무효화
            self._jwks_cache = None
            self._cache_expiry = None
            
            logger.info("✅ 키 회전 완료")
            
        except Exception as e:
            logger.error(f"❌ 키 회전 실패: {e}")
            raise
    
    def get_kid(self) -> str:
        """현재 키의 Key ID 반환"""
        return self._key_id


# 전역 JWKS 서비스 인스턴스
jwks_service = JWKSService()