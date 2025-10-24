"""
User Authentication and Role-Based Access Control (RBAC)
Provides secure user authentication and authorization
"""

import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from persistence.models import Base
from persistence.db import SessionLocal
from sqlalchemy import Column, String, DateTime, Boolean, Text, Integer


class UserRole(Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    REMEDIATOR = "remediator"


class Permission(Enum):
    VIEW_FINDINGS = "view_findings"
    CREATE_FINDINGS = "create_findings"
    UPDATE_FINDINGS = "update_findings"
    DELETE_FINDINGS = "delete_findings"
    VIEW_REPORTS = "view_reports"
    CREATE_REPORTS = "create_reports"
    EXECUTE_REMEDIATION = "execute_remediation"
    MANAGE_SCHEDULES = "manage_schedules"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_HISTORY = "view_audit_history"


# Role-Permission mappings
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [p for p in Permission],  # Admin has all permissions
    UserRole.AUDITOR: [
        Permission.VIEW_FINDINGS,
        Permission.CREATE_FINDINGS,
        Permission.UPDATE_FINDINGS,
        Permission.VIEW_REPORTS,
        Permission.CREATE_REPORTS,
        Permission.MANAGE_SCHEDULES,
        Permission.VIEW_AUDIT_HISTORY
    ],
    UserRole.REMEDIATOR: [
        Permission.VIEW_FINDINGS,
        Permission.UPDATE_FINDINGS,
        Permission.EXECUTE_REMEDIATION,
        Permission.VIEW_REPORTS
    ],
    UserRole.VIEWER: [
        Permission.VIEW_FINDINGS,
        Permission.VIEW_REPORTS
    ]
}


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"
    
    UserId = Column(String(36), primary_key=True)
    Username = Column(String(100), unique=True, nullable=False)
    Email = Column(String(255), unique=True, nullable=False)
    PasswordHash = Column(String(255), nullable=False)
    Role = Column(String(50), nullable=False, default=UserRole.VIEWER.value)
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    LastLogin = Column(DateTime)
    FailedLoginAttempts = Column(Integer, default=0)
    LockedUntil = Column(DateTime)


class UserSession(Base):
    """User session tracking"""
    __tablename__ = "user_sessions"
    
    SessionId = Column(String(36), primary_key=True)
    UserId = Column(String(36), nullable=False)
    Token = Column(String(500), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    ExpiresAt = Column(DateTime, nullable=False)
    IsActive = Column(Boolean, default=True)
    IpAddress = Column(String(45))
    UserAgent = Column(Text)


@dataclass
class AuthConfig:
    """Authentication configuration"""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30


class AuthManager:
    """Manages user authentication and authorization"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.security = HTTPBearer()
    
    def hash_password(self, password: str) -> str:
        """Hash password using PBKDF2"""
        salt = secrets.token_hex(16)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}:{pwdhash.hex()}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_part = password_hash.split(':')
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return pwdhash.hex() == hash_part
        except:
            return False
    
    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        """Create JWT access token"""
        expire = datetime.utcnow() + timedelta(minutes=self.config.access_token_expire_minutes)
        payload = {
            "sub": user_id,
            "username": username,
            "role": role,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token"""
        expire = datetime.utcnow() + timedelta(days=self.config.refresh_token_expire_days)
        payload = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=[self.config.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except jwt.JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.Username == username).first()
            
            if not user:
                return None
            
            # Check if account is locked
            if user.LockedUntil and user.LockedUntil > datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is locked due to too many failed login attempts"
                )
            
            # Check if account is active
            if not user.IsActive:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is deactivated"
                )
            
            # Verify password
            if not self.verify_password(password, user.PasswordHash):
                # Increment failed login attempts
                user.FailedLoginAttempts += 1
                
                if user.FailedLoginAttempts >= self.config.max_failed_attempts:
                    user.LockedUntil = datetime.utcnow() + timedelta(minutes=self.config.lockout_duration_minutes)
                
                db.commit()
                return None
            
            # Reset failed login attempts on successful login
            user.FailedLoginAttempts = 0
            user.LockedUntil = None
            user.LastLogin = datetime.utcnow()
            db.commit()
            
            return user
            
        finally:
            db.close()
    
    async def create_user(self, username: str, email: str, password: str, role: UserRole = UserRole.VIEWER) -> User:
        """Create a new user"""
        db = SessionLocal()
        try:
            # Check if user already exists
            existing_user = db.query(User).filter(
                (User.Username == username) | (User.Email == email)
            ).first()
            
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username or email already exists"
                )
            
            # Create new user
            user = User(
                UserId=str(uuid.uuid4()),
                Username=username,
                Email=email,
                PasswordHash=self.hash_password(password),
                Role=role.value,
                IsActive=True
            )
            
            db.add(user)
            db.commit()
            db.refresh(user)
            
            return user
            
        finally:
            db.close()
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> User:
        """Get current authenticated user"""
        token = credentials.credentials
        payload = self.verify_token(token)
        
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.UserId == payload["sub"]).first()
            
            if not user or not user.IsActive:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            return user
            
        finally:
            db.close()
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has specific permission"""
        user_role = UserRole(user.Role)
        return permission in ROLE_PERMISSIONS.get(user_role, [])
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        def permission_checker(current_user: User = Depends(self.get_current_user)):
            if not self.check_permission(current_user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission required: {permission.value}"
                )
            return current_user
        return permission_checker
    
    async def create_session(self, user: User, ip_address: str = None, user_agent: str = None) -> str:
        """Create user session"""
        session_id = str(uuid.uuid4())
        access_token = self.create_access_token(user.UserId, user.Username, user.Role)
        refresh_token = self.create_refresh_token(user.UserId)
        
        db = SessionLocal()
        try:
            session = UserSession(
                SessionId=session_id,
                UserId=user.UserId,
                Token=refresh_token,
                ExpiresAt=datetime.utcnow() + timedelta(days=self.config.refresh_token_expire_days),
                IpAddress=ip_address,
                UserAgent=user_agent
            )
            
            db.add(session)
            db.commit()
            
            return access_token
            
        finally:
            db.close()
    
    async def revoke_session(self, session_id: str):
        """Revoke user session"""
        db = SessionLocal()
        try:
            session = db.query(UserSession).filter(UserSession.SessionId == session_id).first()
            if session:
                session.IsActive = False
                db.commit()
        finally:
            db.close()
    
    async def get_user_sessions(self, user_id: str) -> List[UserSession]:
        """Get active sessions for user"""
        db = SessionLocal()
        try:
            sessions = db.query(UserSession).filter(
                UserSession.UserId == user_id,
                UserSession.IsActive == True,
                UserSession.ExpiresAt > datetime.utcnow()
            ).all()
            return sessions
        finally:
            db.close()


# Default auth configuration
DEFAULT_AUTH_CONFIG = AuthConfig(
    secret_key="your-secret-key-change-in-production",  # Change this in production!
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    max_failed_attempts=5,
    lockout_duration_minutes=30
)

# Global auth manager instance
auth_manager = AuthManager(DEFAULT_AUTH_CONFIG)


# Convenience functions for common permission checks
def require_admin():
    """Require admin role"""
    return auth_manager.require_permission(Permission.MANAGE_USERS)

def require_auditor():
    """Require auditor or admin role"""
    def checker(current_user: User = Depends(auth_manager.get_current_user)):
        if not (auth_manager.check_permission(current_user, Permission.CREATE_FINDINGS) or 
                auth_manager.check_permission(current_user, Permission.MANAGE_USERS)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Auditor or admin role required"
            )
        return current_user
    return checker

def require_remediator():
    """Require remediator or higher role"""
    def checker(current_user: User = Depends(auth_manager.get_current_user)):
        if not (auth_manager.check_permission(current_user, Permission.EXECUTE_REMEDIATION) or 
                auth_manager.check_permission(current_user, Permission.MANAGE_USERS)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Remediator or higher role required"
            )
        return current_user
    return checker
