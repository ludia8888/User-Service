"""
Rate limiting implementation using Redis
"""
import time
from typing import Optional, Tuple, Callable
from functools import wraps
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .redis import get_redis_client
from .config import settings


class RateLimiter:
    """
    Redis-based rate limiter using sliding window algorithm
    """
    
    def __init__(
        self,
        requests: int = 60,
        window: int = 60,
        prefix: str = "rate_limit"
    ):
        self.requests = requests
        self.window = window
        self.prefix = prefix
    
    async def check_rate_limit(self, key: str) -> Tuple[bool, dict]:
        """
        Check if request is within rate limit
        
        Returns:
            Tuple of (allowed, headers_dict)
        """
        redis_client = get_redis_client()
        
        # Create Redis key
        redis_key = f"{settings.REDIS_PREFIX}:{self.prefix}:{key}"
        
        # Current timestamp
        now = time.time()
        window_start = now - self.window
        
        # Lua script for atomic rate limit check
        # This script performs all operations atomically to prevent race conditions
        lua_script = """
        local key = KEYS[1]
        local window_start = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local max_requests = tonumber(ARGV[3])
        local window = tonumber(ARGV[4])
        
        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
        
        -- Get current count
        local current_count = redis.call('ZCARD', key)
        
        -- Check if limit would be exceeded
        if current_count >= max_requests then
            return {0, current_count}  -- Not allowed
        end
        
        -- Add current request
        redis.call('ZADD', key, now, tostring(now))
        
        -- Set expiry
        redis.call('EXPIRE', key, window)
        
        -- Return allowed with new count
        return {1, current_count + 1}
        """
        
        try:
            # Execute Lua script atomically
            result = await redis_client.eval(
                lua_script,
                1,  # Number of keys
                redis_key,  # Key
                window_start, now, self.requests, self.window  # Args
            )
            
            allowed = result[0] == 1
            count = result[1]
            
        except Exception as e:
            # If Redis operation fails, deny the request for security (fail-closed)
            # Log the error at CRITICAL level
            import logging
            logger = logging.getLogger(__name__)
            logger.critical(f"Rate limit check failed - denying request: {e}")
            
            # Return rate limit exceeded to be safe
            headers = {
                "X-RateLimit-Limit": str(self.requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(now + self.window)),
                "Retry-After": str(self.window)
            }
            return False, headers
        
        # Calculate rate limit headers
        headers = {
            "X-RateLimit-Limit": str(self.requests),
            "X-RateLimit-Remaining": str(max(0, self.requests - count)),
            "X-RateLimit-Reset": str(int(now + self.window))
        }
        
        # Add Retry-After header if limit exceeded
        if not allowed:
            headers["Retry-After"] = str(self.window)
        
        return allowed, headers


def rate_limit(requests: int = 10, window: int = 60, key_func: Optional[callable] = None):
    """
    Decorator for rate limiting specific endpoints
    
    Args:
        requests: Number of requests allowed
        window: Time window in seconds
        key_func: Function to generate rate limit key from request
    """
    def decorator(func):
        limiter = RateLimiter(requests=requests, window=window, prefix="endpoint")
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find Request object in args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request and 'request' in kwargs:
                request = kwargs['request']
            
            if not request:
                # If no request object, call function directly
                return await func(*args, **kwargs)
            
            if not settings.RATE_LIMIT_ENABLED:
                return await func(*args, **kwargs)
            
            # Generate key
            if key_func:
                key = key_func(request)
            else:
                client_ip = request.client.host if request.client else "unknown"
                key = f"{request.url.path}:{client_ip}"
            
            # Check rate limit
            allowed, headers = await limiter.check_rate_limit(key)
            
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers=headers
                )
            
            # Call original function
            response = await func(*args, **kwargs)
            
            # Add headers if response supports it
            if hasattr(response, 'headers'):
                for header, value in headers.items():
                    response.headers[header] = value
            
            return response
        
        return wrapper
    return decorator


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global rate limiting middleware
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.limiter = RateLimiter(
            requests=settings.RATE_LIMIT_PER_MINUTE,
            window=60  # 1 minute window
        )
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Apply rate limiting to all requests
        """
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Skip rate limiting for health checks and docs
        if request.url.path in ["/health", "/docs", "/openapi.json", "/redoc"]:
            return await call_next(request)
        
        # Generate key based on client IP
        client_ip = request.client.host if request.client else "unknown"
        key = f"global:{client_ip}"
        
        # Check rate limit
        allowed, headers = await self.limiter.check_rate_limit(key)
        
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"},
                headers=headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        for header, value in headers.items():
            response.headers[header] = value
        
        return response