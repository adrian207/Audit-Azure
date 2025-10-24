"""
Audit Trail and Logging System
Provides comprehensive activity tracking and security logging
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
from persistence.models import Base
from persistence.db import SessionLocal
from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, JSON


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ActivityType(Enum):
    # Authentication activities
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"
    PASSWORD_CHANGED = "password_changed"
    
    # Audit activities
    AUDIT_STARTED = "audit_started"
    AUDIT_COMPLETED = "audit_completed"
    AUDIT_FAILED = "audit_failed"
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_UPDATED = "schedule_updated"
    SCHEDULE_DELETED = "schedule_deleted"
    
    # Finding activities
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_SUPPRESSED = "finding_suppressed"
    
    # Remediation activities
    REMEDIATION_PREVIEW = "remediation_preview"
    REMEDIATION_EXECUTED = "remediation_executed"
    REMEDIATION_FAILED = "remediation_failed"
    
    # Report activities
    REPORT_GENERATED = "report_generated"
    REPORT_EXPORTED = "report_exported"
    
    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DEACTIVATED = "user_deactivated"
    ROLE_CHANGED = "role_changed"
    
    # System activities
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGED = "configuration_changed"
    ERROR_OCCURRED = "error_occurred"


class AuditLog(Base):
    """Audit log entry"""
    __tablename__ = "audit_logs"
    
    LogId = Column(String(36), primary_key=True)
    Timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    Level = Column(String(20), nullable=False)
    ActivityType = Column(String(50), nullable=False)
    UserId = Column(String(36))  # Nullable for system events
    Username = Column(String(100))
    SessionId = Column(String(36))
    IpAddress = Column(String(45))
    UserAgent = Column(Text)
    ResourceType = Column(String(50))  # finding, user, schedule, etc.
    ResourceId = Column(String(36))
    Action = Column(String(100))
    Description = Column(Text)
    Details = Column(JSON)  # Additional structured data
    Success = Column(Boolean, default=True)
    ErrorMessage = Column(Text)


class SecurityEvent(Base):
    """Security-specific events"""
    __tablename__ = "security_events"
    
    EventId = Column(String(36), primary_key=True)
    Timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    EventType = Column(String(50), nullable=False)
    Severity = Column(String(20), nullable=False)
    Source = Column(String(100))  # IP address, user, system component
    Target = Column(String(100))  # Resource being accessed
    Action = Column(String(100))
    Result = Column(String(50))  # success, failure, blocked
    Details = Column(JSON)
    RiskScore = Column(Integer, default=0)


@dataclass
class AuditContext:
    """Context for audit logging"""
    user_id: Optional[str] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class AuditLogger:
    """Comprehensive audit logging system"""
    
    def __init__(self):
        self.context: Optional[AuditContext] = None
    
    def set_context(self, context: AuditContext):
        """Set audit context for current operation"""
        self.context = context
    
    def clear_context(self):
        """Clear audit context"""
        self.context = None
    
    async def log_activity(
        self,
        activity_type: ActivityType,
        description: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        level: LogLevel = LogLevel.INFO
    ):
        """Log an activity"""
        db = SessionLocal()
        try:
            log_entry = AuditLog(
                LogId=str(uuid.uuid4()),
                Level=level.value,
                ActivityType=activity_type.value,
                UserId=self.context.user_id if self.context else None,
                Username=self.context.username if self.context else None,
                SessionId=self.context.session_id if self.context else None,
                IpAddress=self.context.ip_address if self.context else None,
                UserAgent=self.context.user_agent if self.context else None,
                ResourceType=resource_type,
                ResourceId=resource_id,
                Action=action,
                Description=description,
                Details=details or {},
                Success=success,
                ErrorMessage=error_message
            )
            
            db.add(log_entry)
            db.commit()
            
        except Exception as e:
            print(f"Failed to log activity: {e}")
        finally:
            db.close()
    
    async def log_security_event(
        self,
        event_type: str,
        severity: str,
        source: Optional[str] = None,
        target: Optional[str] = None,
        action: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        risk_score: int = 0
    ):
        """Log a security event"""
        db = SessionLocal()
        try:
            security_event = SecurityEvent(
                EventId=str(uuid.uuid4()),
                EventType=event_type,
                Severity=severity,
                Source=source,
                Target=target,
                Action=action,
                Result=result,
                Details=details or {},
                RiskScore=risk_score
            )
            
            db.add(security_event)
            db.commit()
            
        except Exception as e:
            print(f"Failed to log security event: {e}")
        finally:
            db.close()
    
    async def log_authentication_event(
        self,
        username: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """Log authentication events"""
        activity_type = ActivityType.LOGIN if success else ActivityType.LOGIN_FAILED
        
        await self.log_activity(
            activity_type=activity_type,
            description=f"User {'successfully logged in' if success else 'failed to log in'}: {username}",
            resource_type="user",
            resource_id=username,
            action="authenticate",
            details={
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.utcnow().isoformat()
            },
            success=success,
            error_message=error_message,
            level=LogLevel.WARNING if not success else LogLevel.INFO
        )
        
        # Also log as security event
        await self.log_security_event(
            event_type="authentication",
            severity="high" if not success else "low",
            source=ip_address,
            target=username,
            action="login",
            result="success" if success else "failure",
            details={"username": username, "ip_address": ip_address},
            risk_score=50 if not success else 0
        )
    
    async def log_audit_execution(
        self,
        audit_id: str,
        schedule_id: Optional[str] = None,
        controls: List[str] = None,
        findings_count: int = 0,
        success: bool = True,
        error_message: Optional[str] = None
    ):
        """Log audit execution"""
        activity_type = ActivityType.AUDIT_COMPLETED if success else ActivityType.AUDIT_FAILED
        
        await self.log_activity(
            activity_type=activity_type,
            description=f"Audit {'completed' if success else 'failed'}: {audit_id}",
            resource_type="audit",
            resource_id=audit_id,
            action="execute",
            details={
                "schedule_id": schedule_id,
                "controls": controls or [],
                "findings_count": findings_count,
                "timestamp": datetime.utcnow().isoformat()
            },
            success=success,
            error_message=error_message,
            level=LogLevel.ERROR if not success else LogLevel.INFO
        )
    
    async def log_remediation_event(
        self,
        finding_id: str,
        action: str,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ):
        """Log remediation events"""
        activity_type = ActivityType.REMEDIATION_EXECUTED if success else ActivityType.REMEDIATION_FAILED
        
        await self.log_activity(
            activity_type=activity_type,
            description=f"Remediation {'executed' if success else 'failed'} for finding: {finding_id}",
            resource_type="finding",
            resource_id=finding_id,
            action=action,
            details=details or {},
            success=success,
            error_message=error_message,
            level=LogLevel.ERROR if not success else LogLevel.INFO
        )
        
        # Also log as security event
        await self.log_security_event(
            event_type="remediation",
            severity="medium",
            source=self.context.username if self.context else "system",
            target=finding_id,
            action=action,
            result="success" if success else "failure",
            details=details or {},
            risk_score=25 if not success else 0
        )
    
    async def log_user_management(
        self,
        target_user_id: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ):
        """Log user management activities"""
        activity_type_map = {
            "create": ActivityType.USER_CREATED,
            "update": ActivityType.USER_UPDATED,
            "deactivate": ActivityType.USER_DEACTIVATED,
            "role_change": ActivityType.ROLE_CHANGED
        }
        
        activity_type = activity_type_map.get(action, ActivityType.USER_UPDATED)
        
        await self.log_activity(
            activity_type=activity_type,
            description=f"User {action}: {target_user_id}",
            resource_type="user",
            resource_id=target_user_id,
            action=action,
            details=details or {},
            success=success,
            error_message=error_message,
            level=LogLevel.INFO
        )
    
    async def get_audit_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_id: Optional[str] = None,
        activity_type: Optional[ActivityType] = None,
        resource_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve audit logs with filtering"""
        db = SessionLocal()
        try:
            query = db.query(AuditLog)
            
            if start_date:
                query = query.filter(AuditLog.Timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.Timestamp <= end_date)
            if user_id:
                query = query.filter(AuditLog.UserId == user_id)
            if activity_type:
                query = query.filter(AuditLog.ActivityType == activity_type.value)
            if resource_type:
                query = query.filter(AuditLog.ResourceType == resource_type)
            
            logs = query.order_by(AuditLog.Timestamp.desc()).offset(offset).limit(limit).all()
            
            return [
                {
                    "log_id": log.LogId,
                    "timestamp": log.Timestamp.isoformat(),
                    "level": log.Level,
                    "activity_type": log.ActivityType,
                    "user_id": log.UserId,
                    "username": log.Username,
                    "session_id": log.SessionId,
                    "ip_address": log.IpAddress,
                    "resource_type": log.ResourceType,
                    "resource_id": log.ResourceId,
                    "action": log.Action,
                    "description": log.Description,
                    "details": log.Details,
                    "success": log.Success,
                    "error_message": log.ErrorMessage
                }
                for log in logs
            ]
        finally:
            db.close()
    
    async def get_security_events(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve security events with filtering"""
        db = SessionLocal()
        try:
            query = db.query(SecurityEvent)
            
            if start_date:
                query = query.filter(SecurityEvent.Timestamp >= start_date)
            if end_date:
                query = query.filter(SecurityEvent.Timestamp <= end_date)
            if severity:
                query = query.filter(SecurityEvent.Severity == severity)
            if event_type:
                query = query.filter(SecurityEvent.EventType == event_type)
            
            events = query.order_by(SecurityEvent.Timestamp.desc()).offset(offset).limit(limit).all()
            
            return [
                {
                    "event_id": event.EventId,
                    "timestamp": event.Timestamp.isoformat(),
                    "event_type": event.EventType,
                    "severity": event.Severity,
                    "source": event.Source,
                    "target": event.Target,
                    "action": event.Action,
                    "result": event.Result,
                    "details": event.Details,
                    "risk_score": event.RiskScore
                }
                for event in events
            ]
        finally:
            db.close()
    
    async def get_audit_summary(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get audit activity summary"""
        db = SessionLocal()
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Total activities
            total_activities = db.query(AuditLog).filter(
                AuditLog.Timestamp >= start_date
            ).count()
            
            # Activities by type
            activities_by_type = {}
            activity_types = db.query(AuditLog.ActivityType).filter(
                AuditLog.Timestamp >= start_date
            ).distinct().all()
            
            for activity_type in activity_types:
                count = db.query(AuditLog).filter(
                    AuditLog.ActivityType == activity_type[0],
                    AuditLog.Timestamp >= start_date
                ).count()
                activities_by_type[activity_type[0]] = count
            
            # Failed activities
            failed_activities = db.query(AuditLog).filter(
                AuditLog.Timestamp >= start_date,
                AuditLog.Success == False
            ).count()
            
            # Security events
            security_events = db.query(SecurityEvent).filter(
                SecurityEvent.Timestamp >= start_date
            ).count()
            
            # High-risk events
            high_risk_events = db.query(SecurityEvent).filter(
                SecurityEvent.Timestamp >= start_date,
                SecurityEvent.RiskScore >= 50
            ).count()
            
            return {
                "period_days": days,
                "total_activities": total_activities,
                "activities_by_type": activities_by_type,
                "failed_activities": failed_activities,
                "security_events": security_events,
                "high_risk_events": high_risk_events,
                "success_rate": ((total_activities - failed_activities) / total_activities * 100) if total_activities > 0 else 0
            }
        finally:
            db.close()


# Global audit logger instance
audit_logger = AuditLogger()


# Convenience functions for common logging scenarios
async def log_user_action(user_id: str, username: str, action: str, details: Dict[str, Any] = None):
    """Log user action with context"""
    context = AuditContext(user_id=user_id, username=username)
    audit_logger.set_context(context)
    
    await audit_logger.log_activity(
        activity_type=ActivityType.USER_UPDATED,
        description=f"User action: {action}",
        action=action,
        details=details
    )
    
    audit_logger.clear_context()


async def log_system_event(event_type: str, description: str, details: Dict[str, Any] = None):
    """Log system event"""
    await audit_logger.log_activity(
        activity_type=ActivityType.SYSTEM_STARTUP,
        description=description,
        details=details
    )


async def log_error(error_type: str, description: str, details: Dict[str, Any] = None):
    """Log error event"""
    await audit_logger.log_activity(
        activity_type=ActivityType.ERROR_OCCURRED,
        description=description,
        details=details,
        success=False,
        level=LogLevel.ERROR
    )
