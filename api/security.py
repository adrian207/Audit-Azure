"""
Security Enhancements for Azure Audit Platform

Features:
- Rate limiting to prevent abuse
- Request authentication and API key validation
- Input validation and sanitization
- Audit logging for all operations
- Secure credential storage
- RBAC for multi-user scenarios
"""

from functools import wraps
from typing import Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict
import os
import hashlib
import hmac
import logging
from fastapi import HTTPException, Request, Header
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import json

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Audit log handler
if os.getenv('ENABLE_AUDIT_LOG', 'true').lower() == 'true':
    audit_handler = logging.FileHandler('logs/audit.log')
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    security_logger.addHandler(audit_handler)


class RateLimiter:
    """Rate limiting to prevent API abuse"""
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed
        
        Args:
            identifier: Client identifier (IP, API key, user ID)
            
        Returns:
            True if request is allowed
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[identifier].append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting"""
    
    def __init__(self, app, rate_limiter: RateLimiter):
        super().__init__(app)
        self.rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next):
        # Get client identifier (prefer API key, fallback to IP)
        # request.client may be None in some ASGI servers; guard access
        client_host = getattr(request.client, 'host', None) if request.client is not None else None
        identifier = request.headers.get('X-API-Key') or client_host or request.headers.get('X-Forwarded-For') or 'unknown'
        
        if not self.rate_limiter.is_allowed(identifier):
            security_logger.warning(
                f"Rate limit exceeded for {identifier} on {request.url.path}"
            )
            return Response(
                content=json.dumps({"error": "Rate limit exceeded. Try again later."}),
                status_code=429,
                media_type="application/json"
            )
        
        response = await call_next(request)
        return response


class APIKeyAuth:
    """API Key authentication"""
    
    def __init__(self):
        # Load API keys from environment or database
        self.api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> dict:
        """Load API keys from configuration"""
        # In production, load from secure key store (Azure Key Vault)
        keys = {}
        
        # Example: Load from environment
        master_key = os.getenv('API_MASTER_KEY')
        if master_key:
            keys['master'] = {
                'key_hash': self._hash_key(master_key),
                'permissions': ['read', 'write', 'admin'],
                'description': 'Master API key'
            }
        
        return keys
    
    def _hash_key(self, key: str) -> str:
        """Hash API key for secure storage"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def validate_key(self, api_key: str) -> Optional[dict]:
        """
        Validate API key
        
        Args:
            api_key: API key to validate
            
        Returns:
            Key metadata if valid, None otherwise
        """
        key_hash = self._hash_key(api_key)
        
        for key_id, key_data in self.api_keys.items():
            if hmac.compare_digest(key_data['key_hash'], key_hash):
                return {
                    'key_id': key_id,
                    'permissions': key_data['permissions']
                }
        
        return None


def require_api_key(
    required_permissions: Optional[list] = None
) -> Callable:
    """
    Decorator to require API key authentication
    
    Args:
        required_permissions: List of required permissions
        
    Example:
        @require_api_key(required_permissions=['write'])
        async def create_resource():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from kwargs
            request = kwargs.get('request')
            if not request:
                raise HTTPException(status_code=500, detail="Request object not found")
            
            # Get API key from header
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                security_logger.warning(f"Missing API key for {request.url.path}")
                raise HTTPException(status_code=401, detail="API key required")
            
            # Validate key
            auth = APIKeyAuth()
            key_data = auth.validate_key(api_key)
            
            if not key_data:
                security_logger.warning(f"Invalid API key for {request.url.path}")
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Check permissions
            if required_permissions:
                if not all(perm in key_data['permissions'] for perm in required_permissions):
                    security_logger.warning(
                        f"Insufficient permissions for {request.url.path} "
                        f"(required: {required_permissions}, has: {key_data['permissions']})"
                    )
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            # Add key data to request state
            request.state.api_key_data = key_data
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


class AuditLogger:
    """Audit logging for security events"""
    
    @staticmethod
    def log_event(
        event_type: str,
        user: str,
        resource: str,
        action: str,
        success: bool,
        details: Optional[dict] = None
    ):
        """
        Log security event
        
        Args:
            event_type: Event type (auth, access, modification)
            user: User identifier
            resource: Resource accessed
            action: Action performed
            success: Whether action succeeded
            details: Additional details
        """
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user': user,
            'resource': resource,
            'action': action,
            'success': success,
            'details': details or {}
        }
        
        security_logger.info(json.dumps(event))


class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_subscription_id(sub_id: str) -> bool:
        """Validate Azure subscription ID format"""
        import re
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(pattern, sub_id.lower()))
    
    @staticmethod
    def validate_resource_id(resource_id: str) -> bool:
        """Validate Azure resource ID format"""
        # Basic validation - starts with /subscriptions/
        return resource_id.startswith('/subscriptions/')
    
    @staticmethod
    def sanitize_query(query: str, max_length: int = 10000) -> str:
        """
        Sanitize KQL query
        
        Args:
            query: Query string
            max_length: Maximum allowed length
            
        Returns:
            Sanitized query
        """
        # Truncate to max length
        query = query[:max_length]
        
        # Remove potentially dangerous commands (basic protection)
        dangerous_keywords = [
            'externaldata',
            'evaluate',
            'invoke',
            '.execute'
        ]
        
        query_lower = query.lower()
        for keyword in dangerous_keywords:
            if keyword in query_lower:
                raise ValueError(f"Query contains prohibited keyword: {keyword}")
        
        return query


class SecureCredentialStore:
    """Secure credential storage using encryption"""
    
    def __init__(self):
        self.encryption_key = self._get_encryption_key()
    
    def _get_encryption_key(self) -> bytes:
        """Get or generate encryption key"""
        # In production, use Azure Key Vault
        key = os.getenv('SECRET_KEY', 'default-insecure-key-change-me')
        return hashlib.sha256(key.encode()).digest()
    
    def encrypt_credential(self, credential: str) -> str:
        """
        Encrypt credential
        
        Args:
            credential: Plaintext credential
            
        Returns:
            Encrypted credential (base64 encoded)
        """
        from cryptography.fernet import Fernet
        import base64
        
        # Use Fernet symmetric encryption
        key = base64.urlsafe_b64encode(self.encryption_key)
        fernet = Fernet(key)
        
        encrypted = fernet.encrypt(credential.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_credential(self, encrypted_credential: str) -> str:
        """
        Decrypt credential
        
        Args:
            encrypted_credential: Encrypted credential
            
        Returns:
            Plaintext credential
        """
        from cryptography.fernet import Fernet
        import base64
        
        key = base64.urlsafe_b64encode(self.encryption_key)
        fernet = Fernet(key)
        
        encrypted = base64.b64decode(encrypted_credential.encode())
        return fernet.decrypt(encrypted).decode()


# Security middleware configuration
def configure_security(app):
    """
    Configure security middleware for FastAPI app
    
    Args:
        app: FastAPI application instance
    """
    # Enable rate limiting if configured
    if os.getenv('ENABLE_RATE_LIMITING', 'true').lower() == 'true':
        rate_limiter = RateLimiter(
            max_requests=int(os.getenv('RATE_LIMIT_REQUESTS', 100)),
            window_seconds=int(os.getenv('RATE_LIMIT_WINDOW', 60))
        )
        app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)
    
    # Add security headers
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    return app
