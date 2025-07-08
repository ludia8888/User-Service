"""
Enhanced Audit Service with Circuit Breaker Pattern
Provides resilient audit logging with automatic failure recovery
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from enum import Enum
import httpx
from redis import asyncio as aioredis

from core.config import settings


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failures exceeded threshold, blocking calls
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker implementation for fault tolerance
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, requests blocked
    - HALF_OPEN: Testing recovery with limited requests
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout  # seconds
        self.success_threshold = success_threshold
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.logger = logging.getLogger(__name__)
    
    def call_succeeded(self):
        """Record successful call"""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitState.CLOSED
                self.success_count = 0
                self.logger.info("Circuit breaker closed - service recovered")
    
    def call_failed(self):
        """Record failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.logger.warning("Circuit breaker opened again - service still failing")
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.logger.error(f"Circuit breaker opened - {self.failure_count} consecutive failures")
    
    def can_execute(self) -> bool:
        """Check if request can be executed"""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            if self.last_failure_time and \
               datetime.utcnow() - self.last_failure_time > timedelta(seconds=self.recovery_timeout):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                self.logger.info("Circuit breaker half-open - testing recovery")
                return True
            return False
        
        # HALF_OPEN state
        return True
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state"""
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None
        }


class EnhancedAuditService:
    """
    Enhanced audit service with circuit breaker and improved resilience
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.http_client = None
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            success_threshold=2
        )
        self._initialized = False
        
        # Metrics
        self.metrics = {
            "events_sent": 0,
            "events_failed": 0,
            "events_queued": 0,
            "circuit_opens": 0
        }
    
    async def initialize(self):
        """Initialize connections"""
        if self._initialized:
            return
        
        try:
            # Initialize Redis
            self.redis_client = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            
            # Initialize HTTP client with connection pooling
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0),  # 5 second timeout
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
            )
            
            self._initialized = True
            self.logger.info("Enhanced audit service initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit service: {e}")
            raise
    
    async def close(self):
        """Close connections"""
        if self.http_client:
            await self.http_client.aclose()
        if self.redis_client:
            await self.redis_client.close()
        self._initialized = False
    
    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Log an audit event with circuit breaker protection
        
        Returns:
            bool: True if event was logged (directly or queued), False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        # Build event
        event = self._build_event(
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            self.logger.warning("Circuit breaker is OPEN - queueing event")
            return await self._queue_event(event)
        
        # Try to send event
        try:
            success = await self._send_event(event)
            if success:
                self.circuit_breaker.call_succeeded()
                self.metrics["events_sent"] += 1
                
                # Process any queued events if circuit is now closed
                if self.circuit_breaker.state == CircuitState.CLOSED:
                    asyncio.create_task(self._process_queue())
                
                return True
            else:
                self.circuit_breaker.call_failed()
                self.metrics["events_failed"] += 1
                return await self._queue_event(event)
                
        except Exception as e:
            self.logger.error(f"Unexpected error sending audit event: {e}")
            self.circuit_breaker.call_failed()
            self.metrics["events_failed"] += 1
            return await self._queue_event(event)
    
    async def _send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to audit service"""
        try:
            response = await self.http_client.post(
                f"{settings.AUDIT_SERVICE_URL}/api/v2/events",
                json=event,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.logger.debug(f"Audit event sent successfully: {event['event_type']}")
                return True
            else:
                self.logger.warning(f"Audit service returned {response.status_code}: {response.text}")
                return False
                
        except httpx.TimeoutException:
            self.logger.warning("Audit service request timed out")
            return False
        except httpx.ConnectError:
            self.logger.warning("Cannot connect to audit service")
            return False
        except Exception as e:
            self.logger.error(f"Error sending audit event: {e}")
            return False
    
    async def _queue_event(self, event: Dict[str, Any]) -> bool:
        """Queue event in Redis for retry"""
        try:
            queue_key = f"{settings.REDIS_PREFIX}:audit:retry_queue"
            await self.redis_client.lpush(queue_key, json.dumps(event))
            
            # Set expiration on queue (7 days)
            await self.redis_client.expire(queue_key, 7 * 24 * 3600)
            
            self.metrics["events_queued"] += 1
            self.logger.info(f"Queued audit event for retry: {event['event_type']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to queue audit event: {e}")
            return False
    
    async def _process_queue(self):
        """Process queued events when circuit is closed"""
        if self.circuit_breaker.state != CircuitState.CLOSED:
            return
        
        queue_key = f"{settings.REDIS_PREFIX}:audit:retry_queue"
        processed = 0
        max_batch = 10  # Process up to 10 events at a time
        
        try:
            while processed < max_batch:
                # Get event from queue (non-blocking)
                event_json = await self.redis_client.rpop(queue_key)
                if not event_json:
                    break
                
                try:
                    event = json.loads(event_json)
                    success = await self._send_event(event)
                    
                    if success:
                        processed += 1
                    else:
                        # Put it back at the end of queue
                        await self.redis_client.lpush(queue_key, event_json)
                        break  # Stop processing if we hit an error
                        
                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON in retry queue")
                    continue
            
            if processed > 0:
                self.logger.info(f"Processed {processed} queued audit events")
                
        except Exception as e:
            self.logger.error(f"Error processing audit queue: {e}")
    
    def _build_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Build audit event with standard format"""
        # Extract details from kwargs
        details = kwargs.pop("details", {})
        
        # Build event
        event = {
            "event_type": f"auth.{event_type}" if not event_type.startswith("auth.") else event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "service": "user-service",
            "action": event_type,
            "result": kwargs.pop("result", "success"),
            "details": details
        }
        
        # Add user information
        if user_id:
            event["user_id"] = user_id
        if username:
            event["username"] = username
        
        # Add request information
        if ip_address:
            event["ip_address"] = ip_address
        if user_agent:
            event["user_agent"] = user_agent
        
        # Add compliance tags
        event["compliance_tags"] = ["SOX", "GDPR"]
        event["data_classification"] = "internal"
        
        # Add any remaining kwargs to details
        event["details"].update(kwargs)
        
        return event
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get service metrics"""
        queue_key = f"{settings.REDIS_PREFIX}:audit:retry_queue"
        queue_length = await self.redis_client.llen(queue_key) if self.redis_client else 0
        
        return {
            **self.metrics,
            "queue_length": queue_length,
            "circuit_breaker": self.circuit_breaker.get_state()
        }
    
    # Convenience methods for common events
    
    async def log_login_success(self, user_id: str, username: str, ip_address: str, **kwargs):
        """Log successful login"""
        return await self.log_event(
            "login_success",
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            **kwargs
        )
    
    async def log_login_failed(self, username: str, ip_address: str, reason: str, **kwargs):
        """Log failed login attempt"""
        return await self.log_event(
            "login_failed",
            username=username,
            ip_address=ip_address,
            result="failure",
            details={"reason": reason},
            **kwargs
        )
    
    async def log_user_created(self, user_id: str, username: str, email: str, created_by: str, **kwargs):
        """Log user creation"""
        return await self.log_event(
            "user_created",
            user_id=user_id,
            username=username,
            details={
                "email": email,
                "created_by": created_by,
                **kwargs
            }
        )
    
    async def log_permission_change(self, user_id: str, username: str, action: str, **kwargs):
        """Log permission change"""
        return await self.log_event(
            f"permission_{action}",
            user_id=user_id,
            username=username,
            details=kwargs
        )


# Global instance
_audit_service = None


def get_audit_service() -> EnhancedAuditService:
    """Get or create audit service instance"""
    global _audit_service
    if _audit_service is None:
        _audit_service = EnhancedAuditService()
    return _audit_service


# Cleanup on shutdown
async def cleanup_audit_service():
    """Cleanup audit service connections"""
    global _audit_service
    if _audit_service:
        await _audit_service.close()
        _audit_service = None