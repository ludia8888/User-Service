"""
Audit event model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class AuditEvent(Base):
    """Audit event model"""
    __tablename__ = "audit_events"
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(String(36), index=True)
    username = Column(String(100), index=True)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)