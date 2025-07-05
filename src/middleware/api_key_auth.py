"""
API Key Authentication Middleware
For service-to-service communication
"""
import hashlib
import hmac
import secrets
from typing import Optional

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings


class APIKeyAuth(HTTPBearer):
    """
    API Key authentication for service-to-service communication
    """
    
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        # In production, this should be loaded from secure storage
        self.valid_api_keys = {
            "audit-service": self._hash_key("audit-service-api-key-change-in-production"),
            "oms-service": self._hash_key("oms-service-api-key-change-in-production"),
        }
    
    def _hash_key(self, key: str) -> str:
        """Hash API key for secure storage"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _verify_api_key(self, api_key: str, service_name: Optional[str] = None) -> bool:
        """Verify API key"""
        hashed_key = self._hash_key(api_key)
        
        if service_name:
            return self.valid_api_keys.get(service_name) == hashed_key
        
        # Check if key exists for any service
        return hashed_key in self.valid_api_keys.values()
    
    async def __call__(self, request: Request) -> Optional[str]:
        """
        Authenticate API key from request
        Returns service name if valid, None if no API key, raises HTTPException if invalid
        """
        # Check for API key in header
        auth_header = request.headers.get("X-API-Key")
        if not auth_header:
            # Check Authorization header
            credentials: HTTPAuthorizationCredentials = await super().__call__(request)
            if not credentials:
                return None
            auth_header = credentials.credentials
        
        if not auth_header:
            return None
        
        # Verify API key
        for service_name, hashed_key in self.valid_api_keys.items():
            if self._verify_api_key(auth_header, service_name):
                return service_name
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ServiceAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle service-to-service authentication
    """
    
    def __init__(self, app, protected_paths: list = None):
        super().__init__(app)
        self.protected_paths = protected_paths or ["/internal/"]
        self.api_key_auth = APIKeyAuth(auto_error=False)
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and check for service authentication on protected paths
        """
        # Check if path requires service authentication
        if any(request.url.path.startswith(path) for path in self.protected_paths):
            service_name = await self.api_key_auth(request)
            if not service_name:
                return HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Service authentication required"
                )
            
            # Add service context to request
            request.state.service_name = service_name
            request.state.is_service_request = True
        else:
            request.state.is_service_request = False
        
        response = await call_next(request)
        return response


def get_service_context(request: Request) -> Optional[str]:
    """
    Get service context from request
    """
    return getattr(request.state, 'service_name', None)


def require_service_auth(allowed_services: list = None):
    """
    Dependency to require service authentication
    """
    async def _require_service_auth(request: Request):
        service_name = get_service_context(request)
        
        if not service_name:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Service authentication required"
            )
        
        if allowed_services and service_name not in allowed_services:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Service '{service_name}' not authorized for this endpoint"
            )
        
        return service_name
    
    return _require_service_auth


# API Key generator utility
def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)


# Example usage for generating keys:
if __name__ == "__main__":
    print("Generated API keys:")
    print(f"audit-service: {generate_api_key()}")
    print(f"oms-service: {generate_api_key()}")