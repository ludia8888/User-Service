"""
Service Client Model for Service-to-Service Authentication
서비스 간 인증을 위한 서비스 클라이언트 모델
"""
from sqlalchemy import Column, String, ARRAY, DateTime, Boolean
from sqlalchemy.sql import func
from core.database import Base


class ServiceClient(Base):
    """
    서비스 클라이언트 모델
    
    다른 마이크로서비스(예: oms-monolith)가 user-service에
    인증할 수 있도록 자격증명을 저장합니다.
    """
    __tablename__ = "service_clients"
    
    # 기본 필드
    client_id = Column(String, primary_key=True, index=True)
    client_secret_hash = Column(String, nullable=False)
    service_name = Column(String, nullable=False, unique=True)
    
    # 권한 관련
    allowed_grant_types = Column(ARRAY(String), nullable=False, default=["token_exchange"])
    allowed_scopes = Column(ARRAY(String), default=["audit:write", "audit:read"])
    
    # 상태 및 메타데이터
    is_active = Column(Boolean, default=True, nullable=False)
    description = Column(String)
    
    # 시간 추적
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_used_at = Column(DateTime(timezone=True))
    
    def __repr__(self):
        return f"<ServiceClient(client_id='{self.client_id}', service_name='{self.service_name}')>"
    
    def has_grant_type(self, grant_type: str) -> bool:
        """특정 grant type이 허용되는지 확인"""
        return grant_type in (self.allowed_grant_types or [])
    
    def has_scope(self, scope: str) -> bool:
        """특정 scope가 허용되는지 확인"""
        return scope in (self.allowed_scopes or [])