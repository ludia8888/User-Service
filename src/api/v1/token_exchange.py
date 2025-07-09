"""
Token Exchange API Endpoints
서비스 간 인증을 위한 토큰 교환 엔드포인트
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel

from core.database import get_db
from services.token_exchange_service import TokenExchangeService
from core.exceptions import AuthenticationError

router = APIRouter(prefix="/token", tags=["Token Exchange"])
security = HTTPBasic()


class TokenResponse(BaseModel):
    """토큰 응답 모델"""
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    issued_token_type: str
    client_id: str
    service_name: str


@router.post("/exchange", response_model=TokenResponse)
async def exchange_token(
    credentials: HTTPBasicCredentials = Depends(security),
    scope: Optional[str] = Form(None, description="Requested scopes (space-separated)"),
    grant_type: str = Form(..., description="Must be 'client_credentials'"),
    audience: Optional[str] = Form(None, description="Target audience for the token"),
    db: Session = Depends(get_db)
):
    """
    서비스 클라이언트 토큰 교환
    
    OAuth 2.0 Client Credentials Grant 방식으로 서비스 토큰을 발급합니다.
    
    - **grant_type**: 반드시 'client_credentials' 여야 합니다
    - **scope**: 요청할 권한 범위 (옵션, 공백으로 구분)
    - **Authorization**: Basic Auth (client_id:client_secret)
    
    Returns:
        JWT 토큰 및 메타데이터
    """
    # Grant type 검증
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type. Use 'client_credentials'"
        )
    
    # 토큰 교환 서비스 사용
    service = TokenExchangeService(db)
    
    try:
        # 클라이언트 자격증명으로 토큰 교환
        token_data = await service.exchange_token(
            client_id=credentials.username,
            client_secret=credentials.password,
            requested_scopes=scope,
            audience=audience
        )
        
        return TokenResponse(**token_data)
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Basic"}
        )
    except Exception as e:
        import traceback
        print(f"Token exchange error: {type(e).__name__}: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token exchange failed: {str(e)}"
        )


@router.post("/validate")
async def validate_service_token(
    token: str = Form(..., description="JWT token to validate"),
    db: Session = Depends(get_db)
):
    """
    서비스 토큰 검증
    
    발급된 서비스 토큰이 유효한지 검증합니다.
    
    Returns:
        토큰 정보 (유효한 경우)
    """
    import jwt
    from core.config import settings
    
    try:
        # JWT 디코드 및 검증
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET, 
            algorithms=[settings.JWT_ALGORITHM],
            audience="oms",
            issuer="user-service"
        )
        
        # 서비스 토큰인지 확인
        if not payload.get("is_service_account"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Not a service token"
            )
        
        return {
            "valid": True,
            "client_id": payload.get("client_id"),
            "service_name": payload.get("service_name"),
            "scopes": payload.get("scopes", []),
            "expires_at": payload.get("exp")
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )