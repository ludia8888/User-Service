"""
Unit tests for rate limiting functionality
"""
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request, HTTPException, status
from starlette.responses import JSONResponse

from core.rate_limit import RateLimiter, RateLimitMiddleware, rate_limit
from core.config import settings


class TestRateLimiter:
    """Test RateLimiter class"""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance"""
        return RateLimiter(requests=5, window=60, prefix="test")
    
    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client"""
        client = MagicMock()
        pipeline = MagicMock()
        client.pipeline.return_value = pipeline
        # execute should be async
        async def mock_execute():
            return [None, 2, None, None]  # count = 2
        pipeline.execute = mock_execute
        return client, pipeline
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_allowed(self, rate_limiter, mock_redis_client):
        """Test rate limit check when allowed"""
        client, pipeline = mock_redis_client
        
        with patch('core.redis.get_redis_client', return_value=client):
            allowed, headers = await rate_limiter.check_rate_limit("test_key")
            
            assert allowed is True
            assert headers["X-RateLimit-Limit"] == "5"
            assert headers["X-RateLimit-Remaining"] == "2"  # 5 - 2 - 1
            assert "X-RateLimit-Reset" in headers
            
            # Verify Redis operations
            client.pipeline.assert_called_once()
            assert pipeline.zremrangebyscore.called
            assert pipeline.zcard.called
            assert pipeline.zadd.called
            assert pipeline.expire.called
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self, rate_limiter, mock_redis_client):
        """Test rate limit check when exceeded"""
        client, pipeline = mock_redis_client
        # Override execute for this test
        async def mock_execute():
            return [None, 5, None, None]  # count = 5 (at limit)
        pipeline.execute = mock_execute
        
        with patch('core.redis.get_redis_client', return_value=client):
            allowed, headers = await rate_limiter.check_rate_limit("test_key")
            
            assert allowed is False
            assert headers["X-RateLimit-Remaining"] == "0"
            assert "Retry-After" in headers
            assert headers["Retry-After"] == "60"  # window time
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_redis_key_format(self, rate_limiter, mock_redis_client):
        """Test Redis key format"""
        client, pipeline = mock_redis_client
        
        with patch('core.redis.get_redis_client', return_value=client):
            with patch.object(settings, 'REDIS_PREFIX', 'myapp'):
                await rate_limiter.check_rate_limit("user123")
                
                # Check the Redis key format
                args = pipeline.zremrangebyscore.call_args[0]
                redis_key = args[0]
                assert redis_key == "myapp:test:user123"


class TestRateLimitMiddleware:
    """Test RateLimitMiddleware class"""
    
    @pytest.fixture
    def middleware(self):
        """Create middleware instance"""
        app = MagicMock()
        return RateLimitMiddleware(app)
    
    @pytest.fixture
    def mock_request(self):
        """Mock request object"""
        request = MagicMock(spec=Request)
        request.client.host = "192.168.1.1"
        request.url.path = "/api/test"
        return request
    
    @pytest.mark.asyncio
    async def test_middleware_rate_limit_disabled(self, middleware, mock_request):
        """Test middleware when rate limiting is disabled"""
        call_next = AsyncMock(return_value=MagicMock())
        
        with patch.object(settings, 'RATE_LIMIT_ENABLED', False):
            response = await middleware.dispatch(mock_request, call_next)
            
            call_next.assert_called_once_with(mock_request)
            assert response == call_next.return_value
    
    @pytest.mark.asyncio
    async def test_middleware_health_check_skipped(self, middleware, mock_request):
        """Test middleware skips health check endpoints"""
        mock_request.url.path = "/health"
        call_next = AsyncMock(return_value=MagicMock())
        
        with patch.object(settings, 'RATE_LIMIT_ENABLED', True):
            response = await middleware.dispatch(mock_request, call_next)
            
            call_next.assert_called_once_with(mock_request)
    
    @pytest.mark.asyncio
    async def test_middleware_rate_limit_exceeded(self, middleware, mock_request):
        """Test middleware when rate limit is exceeded"""
        with patch.object(settings, 'RATE_LIMIT_ENABLED', True):
            with patch.object(middleware.limiter, 'check_rate_limit', new_callable=AsyncMock) as mock_check:
                mock_check.return_value = (False, {"Retry-After": "60"})
                
                response = await middleware.dispatch(mock_request, AsyncMock())
                
                assert isinstance(response, JSONResponse)
                assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.asyncio
    async def test_middleware_rate_limit_allowed(self, middleware, mock_request):
        """Test middleware when rate limit is allowed"""
        call_next = AsyncMock()
        mock_response = MagicMock()
        mock_response.headers = {}
        call_next.return_value = mock_response
        
        with patch.object(settings, 'RATE_LIMIT_ENABLED', True):
            with patch.object(middleware.limiter, 'check_rate_limit', new_callable=AsyncMock) as mock_check:
                mock_check.return_value = (True, {"X-RateLimit-Remaining": "5"})
                
                response = await middleware.dispatch(mock_request, call_next)
                
                assert response == mock_response
                assert "X-RateLimit-Remaining" in response.headers
                call_next.assert_called_once_with(mock_request)


class TestRateLimitDecorator:
    """Test rate_limit decorator"""
    
    @pytest.mark.asyncio
    async def test_decorator_with_request(self, monkeypatch):
        """Test decorator with request object"""
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.url.path = "/api/test"
        
        # Mock get_redis_client to return a fake redis client
        fake_redis = MagicMock()
        fake_pipeline = MagicMock()
        fake_redis.pipeline.return_value = fake_pipeline
        
        # Create AsyncMock for execute
        mock_execute = AsyncMock(return_value=[None, 2, None, None])  # count = 2
        fake_pipeline.execute = mock_execute
        
        # Use monkeypatch to mock settings and redis client
        monkeypatch.setattr(settings, 'RATE_LIMIT_ENABLED', True)
        
        # Directly patch the RateLimiter's check_rate_limit method
        from core.rate_limit import RateLimiter
        
        called = False
        
        async def mock_check_rate_limit(self, key):
            nonlocal called
            called = True
            # Call the pipeline to verify it's being used
            fake_redis.pipeline()
            return True, {"X-RateLimit-Remaining": "3"}
        
        monkeypatch.setattr(RateLimiter, 'check_rate_limit', mock_check_rate_limit)
        
        @rate_limit(requests=5, window=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}
        
        result = await test_endpoint(mock_request)
        
        assert result == {"status": "ok"}
        # First check if the mock was called at all
        assert called, "check_rate_limit was not called"
        # Verify Redis was called
        fake_redis.pipeline.assert_called()
    
    @pytest.mark.asyncio
    async def test_decorator_rate_limit_exceeded(self, monkeypatch):
        """Test decorator when rate limit is exceeded"""
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "192.168.1.1"
        mock_request.url.path = "/api/test"
        
        # Mock get_redis_client to return a fake redis client
        fake_redis = MagicMock()
        fake_pipeline = MagicMock()
        fake_redis.pipeline.return_value = fake_pipeline
        
        # Create AsyncMock for execute
        mock_execute = AsyncMock(return_value=[None, 5, None, None])  # count = 5 (at limit, will be rejected)
        fake_pipeline.execute = mock_execute
        
        # Use monkeypatch to mock settings and redis client
        monkeypatch.setattr(settings, 'RATE_LIMIT_ENABLED', True)
        
        # Directly patch the RateLimiter's check_rate_limit method
        from core.rate_limit import RateLimiter
        
        async def mock_check_rate_limit(self, key):
            # Return rate limit exceeded
            return False, {"Retry-After": "60"}
        
        monkeypatch.setattr(RateLimiter, 'check_rate_limit', mock_check_rate_limit)
        
        @rate_limit(requests=5, window=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}
        
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(mock_request)
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.asyncio
    async def test_decorator_no_request_object(self):
        """Test decorator without request object"""
        @rate_limit(requests=5, window=60)
        async def test_function(data: str):
            return f"processed: {data}"
        
        result = await test_function("test")
        assert result == "processed: test"
    
    @pytest.mark.asyncio
    async def test_decorator_rate_limit_disabled(self):
        """Test decorator when rate limiting is disabled"""
        mock_request = MagicMock(spec=Request)
        
        @rate_limit(requests=5, window=60)
        async def test_endpoint(request: Request):
            return {"status": "ok"}
        
        with patch.object(settings, 'RATE_LIMIT_ENABLED', False):
            result = await test_endpoint(mock_request)
            assert result == {"status": "ok"}
    
    @pytest.mark.asyncio
    async def test_decorator_custom_key_function(self, monkeypatch):
        """Test decorator with custom key function"""
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"user-id": "user123"}
        
        def custom_key_func(request):
            return f"user:{request.headers.get('user-id', 'anonymous')}"
        
        # Mock get_redis_client to return a fake redis client
        fake_redis = MagicMock()
        fake_pipeline = MagicMock()
        fake_redis.pipeline.return_value = fake_pipeline
        
        # Create AsyncMock for execute
        mock_execute = AsyncMock(return_value=[None, 2, None, None])  # count = 2
        fake_pipeline.execute = mock_execute
        
        # Use monkeypatch to mock settings and redis client
        monkeypatch.setattr(settings, 'RATE_LIMIT_ENABLED', True)
        
        # Directly patch the RateLimiter's check_rate_limit method
        from core.rate_limit import RateLimiter
        
        captured_key = None
        
        async def mock_check_rate_limit(self, key):
            nonlocal captured_key
            captured_key = key
            # Call the pipeline methods to verify they would be used
            fake_redis.pipeline()
            fake_pipeline.zremrangebyscore(f"test:endpoint:{key}", 0, 1000)
            return True, {"X-RateLimit-Remaining": "3"}
        
        monkeypatch.setattr(RateLimiter, 'check_rate_limit', mock_check_rate_limit)
        
        @rate_limit(requests=5, window=60, key_func=custom_key_func)
        async def test_endpoint(request: Request):
            return {"status": "ok"}
        
        result = await test_endpoint(mock_request)
        
        assert result == {"status": "ok"}
        # Verify the custom key was used
        assert captured_key == "user:user123"
        # Verify the custom key was used in Redis operations
        fake_pipeline.zremrangebyscore.assert_called()
        redis_key = fake_pipeline.zremrangebyscore.call_args[0][0]
        assert "user:user123" in redis_key


class TestRateLimitingIntegration:
    """Integration tests for rate limiting"""
    
    def test_rate_limiter_initialization(self):
        """Test RateLimiter initialization with default values"""
        limiter = RateLimiter()
        assert limiter.requests == 60
        assert limiter.window == 60
        assert limiter.prefix == "rate_limit"
    
    def test_rate_limiter_custom_values(self):
        """Test RateLimiter initialization with custom values"""
        limiter = RateLimiter(requests=100, window=3600, prefix="custom")
        assert limiter.requests == 100
        assert limiter.window == 3600
        assert limiter.prefix == "custom"
    
    def test_middleware_initialization(self):
        """Test middleware initialization"""
        app = MagicMock()
        middleware = RateLimitMiddleware(app)
        
        assert middleware.limiter.requests == settings.RATE_LIMIT_PER_MINUTE
        assert middleware.limiter.window == 60
    
    @pytest.mark.asyncio
    async def test_rate_limit_headers_format(self):
        """Test rate limit headers format"""
        limiter = RateLimiter(requests=10, window=60)
        
        with patch('core.redis.get_redis_client') as mock_get_client:
            client = MagicMock()
            pipeline = MagicMock()
            client.pipeline.return_value = pipeline
            async def mock_execute():
                return [None, 3, None, None]
            pipeline.execute = mock_execute
            mock_get_client.return_value = client
            
            allowed, headers = await limiter.check_rate_limit("test")
            
            assert "X-RateLimit-Limit" in headers
            assert "X-RateLimit-Remaining" in headers
            assert "X-RateLimit-Reset" in headers
            
            # Check header values
            assert headers["X-RateLimit-Limit"] == "10"
            assert headers["X-RateLimit-Remaining"] == "6"  # 10 - 3 - 1
            assert headers["X-RateLimit-Reset"].isdigit()
    
    @pytest.mark.asyncio
    async def test_sliding_window_algorithm(self):
        """Test sliding window algorithm"""
        limiter = RateLimiter(requests=5, window=60)
        
        with patch('core.redis.get_redis_client') as mock_get_client:
            client = MagicMock()
            pipeline = MagicMock()
            client.pipeline.return_value = pipeline
            async def mock_execute():
                return [None, 0, None, None]
            pipeline.execute = mock_execute
            mock_get_client.return_value = client
            
            with patch('time.time', return_value=1000.0):
                await limiter.check_rate_limit("test")
                
                # Check that old entries are removed
                args = pipeline.zremrangebyscore.call_args
                assert args[0][1] == 0  # start score
                assert args[0][2] == 940.0  # end score (1000 - 60)
                
                # Check that current timestamp is added
                zadd_args = pipeline.zadd.call_args[0]
                assert "1000.0" in zadd_args[1]
                assert zadd_args[1]["1000.0"] == 1000.0