"""
JWKS (JSON Web Key Set) Router
RFC 7517 준수 JWKS 엔드포인트
"""
from fastapi import APIRouter, Response, HTTPException, status
from typing import Dict, Any
import logging

from services.jwks_service import jwks_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/.well-known/jwks.json")
async def get_jwks(response: Response) -> Dict[str, Any]:
    """
    JWKS (JSON Web Key Set) 엔드포인트
    
    RFC 7517 준수 JSON Web Key Set 반환
    다른 서비스들이 JWT 토큰 검증에 사용할 공개키 정보 제공
    
    Returns:
        Dict[str, Any]: JWKS 형식의 공개키 정보
        
    Example:
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "key-1234567890",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "...",
                    "e": "AQAB"
                }
            ]
        }
    """
    try:
        logger.info("🔑 JWKS 요청 처리 중...")
        
        # JWKS 생성
        jwks = jwks_service.get_jwks()
        
        # 캐시 헤더 설정 (5분 캐시)
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["Content-Type"] = "application/json"
        
        # CORS 헤더 (다른 서비스에서 접근 가능하도록)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET"
        response.headers["Access-Control-Max-Age"] = "3600"
        
        logger.info(f"✅ JWKS 반환 완료 - {len(jwks['keys'])}개 키")
        return jwks
        
    except Exception as e:
        logger.error(f"❌ JWKS 요청 처리 실패: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWKS generation failed"
        )


@router.post("/.well-known/rotate-keys")
async def rotate_keys() -> Dict[str, str]:
    """
    키 회전 엔드포인트 (관리자 전용)
    
    보안 강화를 위해 JWT 서명 키를 회전시킵니다.
    기존 키는 백업되고 새로운 키가 생성됩니다.
    
    Note:
        - 프로덕션에서는 적절한 인증/인가 미들웨어 필요
        - 키 회전 후 기존 토큰들은 무효화됨
    
    Returns:
        Dict[str, str]: 키 회전 결과 메시지
    """
    try:
        logger.warning("🔄 관리자 키 회전 요청...")
        
        # TODO: 프로덕션에서는 관리자 인증 필요
        # if not is_admin(request):
        #     raise HTTPException(403, "Admin access required")
        
        jwks_service.rotate_keys()
        
        logger.info("✅ 키 회전 완료")
        return {
            "message": "Keys rotated successfully",
            "timestamp": "2025-07-08T16:00:00Z",
            "warning": "All existing JWT tokens are now invalid"
        }
        
    except Exception as e:
        logger.error(f"❌ 키 회전 실패: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key rotation failed"
        )


@router.get("/.well-known/openid_configuration")
async def openid_configuration() -> Dict[str, Any]:
    """
    OpenID Connect Discovery 엔드포인트 (선택적)
    
    OAuth2/OIDC 호환성을 위한 메타데이터 제공
    표준 엔드포인트 URL들을 자동 발견 가능하게 함
    
    Returns:
        Dict[str, Any]: OpenID Connect 설정 정보
    """
    try:
        # 현재 서비스 기본 URL (환경 변수에서 가져오거나 기본값)
        import os
        base_url = os.getenv("USER_SERVICE_URL", "http://localhost:8000")
        
        config = {
            "issuer": base_url,
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "authorization_endpoint": f"{base_url}/auth/authorize",
            "token_endpoint": f"{base_url}/auth/token",
            "userinfo_endpoint": f"{base_url}/auth/account/userinfo",
            "end_session_endpoint": f"{base_url}/auth/logout",
            
            # 지원하는 알고리즘
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            
            # 지원하는 스코프
            "scopes_supported": [
                "openid", "profile", "email", 
                "api:branches:read", "api:branches:write",
                "api:ontologies:read", "api:ontologies:write"
            ],
            
            # 지원하는 응답 타입
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            
            # 클레임 정보
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time",
                "email", "username", "roles", "scope"
            ]
        }
        
        logger.info("🔍 OpenID Connect Discovery 정보 제공")
        return config
        
    except Exception as e:
        logger.error(f"❌ OpenID Connect 설정 생성 실패: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OpenID Connect configuration generation failed"
        )