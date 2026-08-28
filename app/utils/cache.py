"""
Advanced Caching System for SIATI
Multi-layer caching with Redis, memory, and disk caching
"""
import json
import pickle
import hashlib
import time
from typing import Any, Optional, Callable, TypeVar, Dict, List
from functools import wraps
from datetime import timedelta
import asyncio
from pathlib import Path

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

T = TypeVar('T')


class CacheBackend:
    """Base cache backend interface"""

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in cache with TTL"""
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        raise NotImplementedError

    def clear(self) -> bool:
        """Clear all cache entries"""
        raise NotImplementedError


class MemoryCache(CacheBackend):
    """In-memory cache implementation"""

    def __init__(self, max_size: int = 1000):
        """
        Initialize memory cache

        Args:
            max_size: Maximum number of items to store
        """
        self.cache: Dict[str, tuple] = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get value from memory cache"""
        if key in self.cache:
            value, expiry = self.cache[key]
            if expiry > time.time():
                self.hits += 1
                return value
            else:
                # Expired, remove it
                del self.cache[key]
        self.misses += 1
        return None

    def set(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in memory cache"""
        # Evict oldest if at capacity
        if len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]

        expiry = time.time() + ttl
        self.cache[key] = (value, expiry)
        return True

    def delete(self, key: str) -> bool:
        """Delete value from memory cache"""
        if key in self.cache:
            del self.cache[key]
            return True
        return False

    def exists(self, key: str) -> bool:
        """Check if key exists in memory cache"""
        if key in self.cache:
            value, expiry = self.cache[key]
            return expiry > time.time()
        return False

    def clear(self) -> bool:
        """Clear all memory cache entries"""
        self.cache.clear()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "size": len(self.cache),
            "max_size": self.max_size
        }


class RedisCache(CacheBackend):
    """Redis cache implementation"""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        """
        Initialize Redis cache

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
        """
        if not HAS_REDIS:
            raise ImportError("Redis package not installed")

        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.prefix = "siati_cache:"

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.prefix}{key}"

    def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache"""
        try:
            value = self.client.get(self._make_key(key))
            if value is not None:
                return pickle.loads(value)
            return None
        except Exception:
            return None

    def set(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in Redis cache"""
        try:
            serialized = pickle.dumps(value)
            return self.client.setex(self._make_key(key), ttl, serialized)
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        """Delete value from Redis cache"""
        try:
            return bool(self.client.delete(self._make_key(key)))
        except Exception:
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis cache"""
        try:
            return bool(self.client.exists(self._make_key(key)))
        except Exception:
            return False

    def clear(self) -> bool:
        """Clear all SIATI cache entries from Redis"""
        try:
            keys = self.client.keys(f"{self.prefix}*")
            if keys:
                return bool(self.client.delete(*keys))
            return True
        except Exception:
            return False


class DiskCache(CacheBackend):
    """Disk-based cache implementation"""

    def __init__(self, cache_dir: str = "cache"):
        """
        Initialize disk cache

        Args:
            cache_dir: Directory for cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key"""
        # Hash the key to create a safe filename
        hashed_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed_key}.cache"

    def _get_metadata_path(self, key: str) -> Path:
        """Get metadata file path for cache key"""
        hashed_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hashed_key}.meta"

    def get(self, key: str) -> Optional[Any]:
        """Get value from disk cache"""
        try:
            file_path = self._get_file_path(key)
            meta_path = self._get_metadata_path(key)

            if not file_path.exists() or not meta_path.exists():
                return None

            # Check expiry
            with open(meta_path, 'r') as f:
                metadata = json.load(f)

            if metadata['expiry'] < time.time():
                # Expired, clean up
                file_path.unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                return None

            # Load value
            with open(file_path, 'rb') as f:
                return pickle.load(f)

        except Exception:
            return None

    def set(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in disk cache"""
        try:
            file_path = self._get_file_path(key)
            meta_path = self._get_metadata_path(key)

            # Save value
            with open(file_path, 'wb') as f:
                pickle.dump(value, f)

            # Save metadata
            metadata = {
                'expiry': time.time() + ttl,
                'created': time.time(),
                'size': file_path.stat().st_size
            }
            with open(meta_path, 'w') as f:
                json.dump(metadata, f)

            return True

        except Exception:
            return False

    def delete(self, key: str) -> bool:
        """Delete value from disk cache"""
        try:
            file_path = self._get_file_path(key)
            meta_path = self._get_metadata_path(key)

            deleted = False
            if file_path.exists():
                file_path.unlink()
                deleted = True
            if meta_path.exists():
                meta_path.unlink()
                deleted = True

            return deleted

        except Exception:
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in disk cache"""
        try:
            file_path = self._get_file_path(key)
            meta_path = self._get_metadata_path(key)

            if not file_path.exists() or not meta_path.exists():
                return False

            # Check expiry
            with open(meta_path, 'r') as f:
                metadata = json.load(f)

            return metadata['expiry'] > time.time()

        except Exception:
            return False

    def clear(self) -> bool:
        """Clear all disk cache entries"""
        try:
            for file in self.cache_dir.glob("*.cache"):
                file.unlink(missing_ok=True)
            for file in self.cache_dir.glob("*.meta"):
                file.unlink(missing_ok=True)
            return True
        except Exception:
            return False


class MultiLevelCache:
    """Multi-level cache with automatic fallback"""

    def __init__(
        self,
        l1_cache: Optional[CacheBackend] = None,
        l2_cache: Optional[CacheBackend] = None,
        l3_cache: Optional[CacheBackend] = None
    ):
        """
        Initialize multi-level cache

        Args:
            l1_cache: Level 1 cache (fastest, typically memory)
            l2_cache: Level 2 cache (medium speed, typically Redis)
            l3_cache: Level 3 cache (slowest, typically disk)
        """
        self.l1 = l1_cache or MemoryCache()
        self.l2 = l2_cache
        self.l3 = l3_cache

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache with automatic promotion"""
        # Try L1 first
        value = self.l1.get(key)
        if value is not None:
            return value

        # Try L2
        if self.l2:
            value = self.l2.get(key)
            if value is not None:
                # Promote to L1
                self.l1.set(key, value, ttl=300)  # 5 minutes in L1
                return value

        # Try L3
        if self.l3:
            value = self.l3.get(key)
            if value is not None:
                # Promote to L2 and L1
                if self.l2:
                    self.l2.set(key, value, ttl=3600)  # 1 hour in L2
                self.l1.set(key, value, ttl=300)  # 5 minutes in L1
                return value

        return None

    def set(self, key: str, value: Any, ttl: int) -> bool:
        """Set value in all cache levels"""
        success = True

        # Set in L1
        if not self.l1.set(key, value, min(ttl, 300)):  # Max 5 min in L1
            success = False

        # Set in L2
        if self.l2 and not self.l2.set(key, value, min(ttl, 3600)):  # Max 1 hour in L2
            success = False

        # Set in L3
        if self.l3 and not self.l3.set(key, value, ttl):
            success = False

        return success

    def delete(self, key: str) -> bool:
        """Delete value from all cache levels"""
        success = True

        if not self.l1.delete(key):
            success = False
        if self.l2 and not self.l2.delete(key):
            success = False
        if self.l3 and not self.l3.delete(key):
            success = False

        return success

    def exists(self, key: str) -> bool:
        """Check if key exists in any cache level"""
        return (
            self.l1.exists(key) or
            (self.l2 and self.l2.exists(key)) or
            (self.l3 and self.l3.exists(key))
        )

    def clear(self) -> bool:
        """Clear all cache levels"""
        success = True

        if not self.l1.clear():
            success = False
        if self.l2 and not self.l2.clear():
            success = False
        if self.l3 and not self.l3.clear():
            success = False

        return success

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            "l1": self.l1.get_stats() if hasattr(self.l1, 'get_stats') else {},
            "l2_enabled": self.l2 is not None,
            "l3_enabled": self.l3 is not None
        }

        return stats


# ============================================================================
# CACHE DECORATORS
# ============================================================================

def cached(
    ttl: int = 3600,
    key_prefix: str = "",
    cache_instance: Optional[MultiLevelCache] = None
):
    """
    Cache decorator for functions

    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache keys
        cache_instance: Cache instance to use (creates default if None)
    """
    if cache_instance is None:
        cache_instance = MultiLevelCache()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Generate cache key
            cache_key = _generate_cache_key(
                key_prefix,
                func.__name__,
                args,
                kwargs
            )

            # Try to get from cache
            cached_value = cache_instance.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_instance.set(cache_key, result, ttl)

            return result

        return wrapper
    return decorator


def async_cached(
    ttl: int = 3600,
    key_prefix: str = "",
    cache_instance: Optional[MultiLevelCache] = None
):
    """
    Async cache decorator for async functions

    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache keys
        cache_instance: Cache instance to use (creates default if None)
    """
    if cache_instance is None:
        cache_instance = MultiLevelCache()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Generate cache key
            cache_key = _generate_cache_key(
                key_prefix,
                func.__name__,
                args,
                kwargs
            )

            # Try to get from cache
            cached_value = cache_instance.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache_instance.set(cache_key, result, ttl)

            return result

        return wrapper
    return decorator


def _generate_cache_key(prefix: str, func_name: str, args: tuple, kwargs: dict) -> str:
    """Generate a cache key from function arguments"""
    # Create a string representation of arguments
    args_str = str(args) + str(sorted(kwargs.items()))

    # Hash to create a consistent key
    args_hash = hashlib.md5(args_str.encode()).hexdigest()

    return f"{prefix}:{func_name}:{args_hash}"


# ============================================================================
# CACHE MANAGER
# ============================================================================

class CacheManager:
    """Central cache manager for SIATI"""

    _instance = None

    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize cache manager"""
        if self._initialized:
            return

        # Initialize cache levels
        l1 = MemoryCache(max_size=1000)

        l2 = None
        if HAS_REDIS:
            try:
                l2 = RedisCache(host="localhost", port=6379, db=0)
            except Exception:
                pass

        l3 = DiskCache(cache_dir="cache")

        self.cache = MultiLevelCache(l1, l2, l3)
        self._initialized = True

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.cache.get(key)

    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Set value in cache"""
        return self.cache.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        return self.cache.delete(key)

    def clear(self) -> bool:
        """Clear all cache"""
        return self.cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()

    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate cache entries matching pattern

        Args:
            pattern: Pattern to match (e.g., "vuln:*")

        Returns:
            Number of entries invalidated
        """
        # This would require pattern matching implementation
        # For now, return 0
        return 0


# Global cache manager instance
cache_manager = CacheManager()