"""
Rate limiting implementation using Redis
"""
import time
from typing import Optional, Tuple
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

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
        
        # Use Redis pipeline for atomic operations
        pipe = redis_client.pipeline()
        
        # Remove old entries outside the window
        pipe.zremrangebyscore(redis_key, 0, window_start)
        
        # Count requests in current window
        pipe.zcard(redis_key)
        
        # Add current request
        pipe.zadd(redis_key, {str(now): now})
        
        # Set expiry
        pipe.expire(redis_key, self.window)
        
        # Execute pipeline
        results = await pipe.execute()
        
        # Get count (before adding current request)
        count = results[1]
        
        # Calculate rate limit headers
        headers = {
            "X-RateLimit-Limit": str(self.requests),
            "X-RateLimit-Remaining": str(max(0, self.requests - count - 1)),
            "X-RateLimit-Reset": str(int(now + self.window))
        }
        
        # Check if limit exceeded
        if count >= self.requests:
            headers["Retry-After"] = str(self.window)
            return False, headers
        
        return True, headers


class RateLimitMiddleware:
    """
    Middleware for rate limiting requests
    """
    
    def __init__(self, app):
        self.app = app
        self.limiter = RateLimiter(
            requests=settings.RATE_LIMIT_PER_MINUTE,
            window=60
        )
    
    async def __call__(self, request: Request, call_next):
        """
        Check rate limit for request
        """
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Skip rate limiting for health check and docs
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Generate rate limit key based on IP
        client_ip = request.client.host if request.client else "unknown"
        key = f"ip:{client_ip}"
        
        # Check rate limit
        try:
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
            
        except Exception as e:
            # If Redis is down, allow the request but log the error
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Rate limit check failed: {e}")
            return await call_next(request)


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
        
        # Copy function metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        
        return wrapper
    return decorator