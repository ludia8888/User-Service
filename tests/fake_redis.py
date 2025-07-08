"""
Fake Redis implementation for testing without Redis server
"""
import time
from typing import Dict, Any, List, Union


class FakePipeline:
    """Fake Redis pipeline for testing"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.commands = []
    
    def zremrangebyscore(self, key: str, min_score: float, max_score: float):
        """Mock zremrangebyscore command"""
        self.commands.append(('zremrangebyscore', key, min_score, max_score))
        return self
    
    def zcard(self, key: str):
        """Mock zcard command"""
        self.commands.append(('zcard', key))
        return self
    
    def zadd(self, key: str, mapping: Dict[str, float]):
        """Mock zadd command"""
        self.commands.append(('zadd', key, mapping))
        return self
    
    def expire(self, key: str, seconds: int):
        """Mock expire command"""
        self.commands.append(('expire', key, seconds))
        return self
    
    async def execute(self) -> List[Any]:
        """Execute all queued commands and return results"""
        results = []
        for command in self.commands:
            if command[0] == 'zremrangebyscore':
                # Remove old entries
                key = command[1]
                min_score = command[2] 
                max_score = command[3]
                if key in self.redis_client.data:
                    zset = self.redis_client.data[key]
                    to_remove = [member for member, score in zset.items() if min_score <= score <= max_score]
                    for member in to_remove:
                        del zset[member]
                results.append(len(to_remove) if key in self.redis_client.data else 0)
                
            elif command[0] == 'zcard':
                # Count members in sorted set
                key = command[1]
                count = len(self.redis_client.data.get(key, {}))
                results.append(count)
                
            elif command[0] == 'zadd':
                # Add members to sorted set
                key = command[1]
                mapping = command[2]
                if key not in self.redis_client.data:
                    self.redis_client.data[key] = {}
                self.redis_client.data[key].update(mapping)
                results.append(len(mapping))
                
            elif command[0] == 'expire':
                # Set expiry (just mock it)
                results.append(True)
                
        self.commands.clear()
        return results


class FakeRedis:
    """Fake Redis client for testing"""
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.expirations: Dict[str, float] = {}
    
    def pipeline(self):
        """Create a fake pipeline"""
        return FakePipeline(self)
    
    async def get(self, key: str) -> Union[str, None]:
        """Get value by key"""
        if self._is_expired(key):
            return None
        return self.data.get(key)
    
    async def set(self, key: str, value: Any, ex: int = None) -> bool:
        """Set key-value pair"""
        self.data[key] = value
        if ex:
            self.expirations[key] = time.time() + ex
        return True
    
    async def delete(self, key: str) -> int:
        """Delete key"""
        if key in self.data:
            del self.data[key]
            if key in self.expirations:
                del self.expirations[key]
            return 1
        return 0
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        if self._is_expired(key):
            return False
        return key in self.data
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration for key"""
        if key in self.data:
            self.expirations[key] = time.time() + seconds
            return True
        return False
    
    async def ttl(self, key: str) -> int:
        """Get time to live for key"""
        if key not in self.data:
            return -2
        if key not in self.expirations:
            return -1
        remaining = self.expirations[key] - time.time()
        return int(remaining) if remaining > 0 else -2
    
    def _is_expired(self, key: str) -> bool:
        """Check if key is expired"""
        if key in self.expirations:
            if time.time() > self.expirations[key]:
                # Clean up expired key
                if key in self.data:
                    del self.data[key]
                del self.expirations[key]
                return True
        return False
    
    async def flushall(self) -> bool:
        """Clear all data"""
        self.data.clear()
        self.expirations.clear()
        return True
    
    async def lpush(self, key: str, *values) -> int:
        """Push values to the left of a list"""
        if key not in self.data:
            self.data[key] = []
        
        # Insert at the beginning of the list (left push)
        for value in reversed(values):
            self.data[key].insert(0, value)
        
        return len(self.data[key])
    
    async def rpop(self, key: str) -> Union[str, None]:
        """Pop a value from the right of a list"""
        if key not in self.data or not self.data[key]:
            return None
        return self.data[key].pop()
    
    async def llen(self, key: str) -> int:
        """Get the length of a list"""
        if key not in self.data:
            return 0
        return len(self.data[key])
    
    async def lrange(self, key: str, start: int, end: int) -> List[str]:
        """Get a range of elements from a list"""
        if key not in self.data:
            return []
        return self.data[key][start:end + 1 if end != -1 else None]


# Global fake Redis instance for tests
_fake_redis = FakeRedis()


def get_fake_redis():
    """Get the fake Redis instance"""
    return _fake_redis


def reset_fake_redis():
    """Reset the fake Redis instance"""
    global _fake_redis
    _fake_redis = FakeRedis()