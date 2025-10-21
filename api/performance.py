"""
Performance Enhancements for Azure Audit Platform

Features:
- Async/concurrent evaluation execution
- Caching of Azure API responses
- Query result pagination
- Connection pooling
- Batch processing
- Resource usage optimization
"""

import asyncio
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from functools import lru_cache, wraps
import time
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


class CacheManager:
    """In-memory cache with TTL"""
    
    def __init__(self, default_ttl: int = 300):
        """
        Initialize cache manager
        
        Args:
            default_ttl: Default TTL in seconds (default: 5 minutes)
        """
        self.cache = {}
        self.default_ttl = default_ttl
        self.enabled = os.getenv('ENABLE_CACHING', 'true').lower() == 'true'
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = json.dumps({'args': args, 'kwargs': kwargs}, sort_keys=True)
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.enabled:
            return None
        
        if key in self.cache:
            value, expiry = self.cache[key]
            if datetime.utcnow() < expiry:
                return value
            else:
                # Expired, remove
                del self.cache[key]
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        if not self.enabled:
            return
        
        ttl = ttl or self.default_ttl
        expiry = datetime.utcnow() + timedelta(seconds=ttl)
        self.cache[key] = (value, expiry)
    
    def invalidate(self, pattern: Optional[str] = None):
        """
        Invalidate cache entries
        
        Args:
            pattern: Pattern to match keys (None = clear all)
        """
        if pattern is None:
            self.cache.clear()
        else:
            keys_to_delete = [k for k in self.cache.keys() if pattern in k]
            for key in keys_to_delete:
                del self.cache[key]


# Global cache instance
cache = CacheManager(default_ttl=int(os.getenv('CACHE_TTL', 300)))


def cached(ttl: Optional[int] = None):
    """
    Decorator for caching function results
    
    Args:
        ttl: Cache TTL in seconds
        
    Example:
        @cached(ttl=300)
        async def get_resources(subscription_id):
            # Expensive operation
            return resources
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{func.__name__}:{cache._generate_key(*args, **kwargs)}"
            
            # Check cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            cache.set(cache_key, result, ttl)
            
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{func.__name__}:{cache._generate_key(*args, **kwargs)}"
            
            # Check cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            cache.set(cache_key, result, ttl)
            
            return result
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class AsyncEvaluationPool:
    """Manage concurrent evaluation execution"""
    
    def __init__(self, max_concurrent: int = 5):
        """
        Initialize evaluation pool
        
        Args:
            max_concurrent: Maximum concurrent evaluations
        """
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def run_evaluation(self, evaluator_func: Callable, *args, **kwargs) -> Dict:
        """
        Run single evaluation with concurrency control
        
        Args:
            evaluator_func: Async evaluator function
            *args, **kwargs: Arguments to pass to evaluator
            
        Returns:
            Evaluation results
        """
        async with self.semaphore:
            start_time = time.time()
            
            try:
                result = await evaluator_func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                return {
                    'status': 'success',
                    'result': result,
                    'execution_time': execution_time
                }
            
            except Exception as e:
                execution_time = time.time() - start_time
                
                return {
                    'status': 'error',
                    'error': str(e),
                    'execution_time': execution_time
                }
    
    async def run_batch(
        self,
        evaluators: List[tuple]
    ) -> List[Dict]:
        """
        Run multiple evaluations concurrently
        
        Args:
            evaluators: List of (evaluator_func, args, kwargs) tuples
            
        Returns:
            List of results
        """
        tasks = [
            self.run_evaluation(func, *args, **kwargs)
            for func, args, kwargs in evaluators
        ]
        
        return await asyncio.gather(*tasks)


class BatchProcessor:
    """Process items in batches for efficiency"""
    
    @staticmethod
    async def process_in_batches(
        items: List[Any],
        processor_func: Callable,
        batch_size: int = 50,
        max_concurrent: int = 5
    ) -> List[Any]:
        """
        Process items in batches with concurrency control
        
        Args:
            items: Items to process
            processor_func: Async function to process each batch
            batch_size: Items per batch
            max_concurrent: Maximum concurrent batches
            
        Returns:
            Processed results
        """
        # Split into batches
        batches = [
            items[i:i + batch_size]
            for i in range(0, len(items), batch_size)
        ]
        
        # Process batches concurrently
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def process_batch(batch):
            async with semaphore:
                return await processor_func(batch)
        
        tasks = [process_batch(batch) for batch in batches]
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        return [item for batch_result in results for item in batch_result]


class QueryPaginator:
    """Paginate large query results"""
    
    @staticmethod
    def paginate(
        items: List[Any],
        page: int = 1,
        page_size: int = 100
    ) -> Dict[str, Any]:
        """
        Paginate items
        
        Args:
            items: Items to paginate
            page: Page number (1-indexed)
            page_size: Items per page
            
        Returns:
            Paginated response with metadata
        """
        total_items = len(items)
        total_pages = (total_items + page_size - 1) // page_size
        
        # Validate page
        if page < 1:
            page = 1
        if page > total_pages and total_pages > 0:
            page = total_pages
        
        # Calculate slice
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        page_items = items[start_idx:end_idx]
        
        return {
            'items': page_items,
            'page': page,
            'page_size': page_size,
            'total_items': total_items,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }


class PerformanceMonitor:
    """Monitor and track performance metrics"""
    
    def __init__(self):
        self.metrics = {}
    
    def record_metric(self, metric_name: str, value: float, tags: Optional[Dict] = None):
        """Record performance metric"""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = []
        
        self.metrics[metric_name].append({
            'value': value,
            'timestamp': datetime.utcnow(),
            'tags': tags or {}
        })
    
    def get_stats(self, metric_name: str) -> Dict[str, float]:
        """Get statistics for metric"""
        if metric_name not in self.metrics or not self.metrics[metric_name]:
            return {}
        
        values = [m['value'] for m in self.metrics[metric_name]]
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'latest': values[-1]
        }


def performance_tracked(metric_name: str):
    """
    Decorator to track function performance
    
    Args:
        metric_name: Name of metric to track
    """
    monitor = PerformanceMonitor()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            monitor.record_metric(metric_name, execution_time)
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            monitor.record_metric(metric_name, execution_time)
            return result
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class ResourcePoolManager:
    """Manage connection pools and resource reuse"""
    
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.pools = {}
    
    async def get_or_create_pool(self, pool_key: str, factory: Callable):
        """
        Get existing pool or create new one
        
        Args:
            pool_key: Unique pool identifier
            factory: Function to create pool
            
        Returns:
            Pool instance
        """
        if pool_key not in self.pools:
            self.pools[pool_key] = await factory(self.max_connections)
        
        return self.pools[pool_key]
    
    async def close_all(self):
        """Close all pools"""
        for pool in self.pools.values():
            if hasattr(pool, 'close'):
                await pool.close()
        
        self.pools.clear()


# Performance configuration
PERFORMANCE_CONFIG = {
    'max_concurrent_evaluations': int(os.getenv('MAX_CONCURRENT_EVALUATIONS', 5)),
    'batch_size': int(os.getenv('BATCH_SIZE', 50)),
    'query_page_size': int(os.getenv('QUERY_PAGE_SIZE', 100)),
    'enable_caching': os.getenv('ENABLE_CACHING', 'true').lower() == 'true',
    'cache_ttl': int(os.getenv('CACHE_TTL', 300)),
}
