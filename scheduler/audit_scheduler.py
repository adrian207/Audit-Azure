"""
Scheduled Audit System
Provides automated scheduling and execution of security audits
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
from persistence.models import Base, AuditRun, Finding
from persistence.db import SessionLocal
from evaluators.registry import get_evaluator_by_control


class ScheduleFrequency(Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    CUSTOM = "custom"


class AuditStatus(Enum):
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditSchedule:
    """Audit schedule configuration"""
    schedule_id: str
    name: str
    description: str
    frequency: ScheduleFrequency
    controls: List[str]  # List of control IDs to evaluate
    subscriptions: List[str]  # Azure subscription IDs
    enabled: bool = True
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    created_at: datetime = None
    created_by: str = "system"


class AuditScheduler:
    """Manages scheduled security audits"""
    
    def __init__(self):
        self.schedules: Dict[str, AuditSchedule] = {}
        self.running_audits: Dict[str, str] = {}  # audit_id -> schedule_id
        self._load_schedules()
    
    def _load_schedules(self):
        """Load schedules from database"""
        db = SessionLocal()
        try:
            # In a real implementation, you'd load from a schedules table
            # For now, we'll create some default schedules
            self._create_default_schedules()
        finally:
            db.close()
    
    def _create_default_schedules(self):
        """Create default audit schedules"""
        default_schedules = [
            AuditSchedule(
                schedule_id="daily-critical",
                name="Daily Critical Controls",
                description="Daily audit of critical security controls",
                frequency=ScheduleFrequency.DAILY,
                controls=["IM-2", "IM-3", "NS-1", "NS-2", "DP-1"],
                subscriptions=[],
                next_run=datetime.now() + timedelta(hours=1)
            ),
            AuditSchedule(
                schedule_id="weekly-comprehensive",
                name="Weekly Comprehensive Audit",
                description="Weekly comprehensive security audit",
                frequency=ScheduleFrequency.WEEKLY,
                controls=["IM-2", "IM-3", "IM-4", "IM-5", "IM-6", "NS-1", "NS-2", "NS-3", "NS-4", "DP-1", "DP-2", "DP-3"],
                subscriptions=[],
                next_run=datetime.now() + timedelta(days=1)
            ),
            AuditSchedule(
                schedule_id="monthly-full",
                name="Monthly Full Audit",
                description="Monthly full security audit of all controls",
                frequency=ScheduleFrequency.MONTHLY,
                controls=[],  # Empty means all controls
                subscriptions=[],
                next_run=datetime.now() + timedelta(days=7)
            )
        ]
        
        for schedule in default_schedules:
            self.schedules[schedule.schedule_id] = schedule
    
    async def create_schedule(self, schedule: AuditSchedule) -> str:
        """Create a new audit schedule"""
        schedule.schedule_id = str(uuid.uuid4())
        schedule.created_at = datetime.now()
        self.schedules[schedule.schedule_id] = schedule
        
        # Calculate next run time
        schedule.next_run = self._calculate_next_run(schedule)
        
        return schedule.schedule_id
    
    def _calculate_next_run(self, schedule: AuditSchedule) -> datetime:
        """Calculate next run time based on frequency"""
        now = datetime.now()
        
        if schedule.frequency == ScheduleFrequency.DAILY:
            return now + timedelta(days=1)
        elif schedule.frequency == ScheduleFrequency.WEEKLY:
            return now + timedelta(weeks=1)
        elif schedule.frequency == ScheduleFrequency.MONTHLY:
            return now + timedelta(days=30)
        elif schedule.frequency == ScheduleFrequency.QUARTERLY:
            return now + timedelta(days=90)
        else:
            return now + timedelta(days=1)  # Default to daily
    
    async def get_schedules(self) -> List[AuditSchedule]:
        """Get all audit schedules"""
        return list(self.schedules.values())
    
    async def get_schedule(self, schedule_id: str) -> Optional[AuditSchedule]:
        """Get a specific audit schedule"""
        return self.schedules.get(schedule_id)
    
    async def update_schedule(self, schedule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an audit schedule"""
        if schedule_id not in self.schedules:
            return False
        
        schedule = self.schedules[schedule_id]
        for key, value in updates.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)
        
        # Recalculate next run if frequency changed
        if 'frequency' in updates:
            schedule.next_run = self._calculate_next_run(schedule)
        
        return True
    
    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete an audit schedule"""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            return True
        return False
    
    async def get_due_schedules(self) -> List[AuditSchedule]:
        """Get schedules that are due to run"""
        now = datetime.now()
        due_schedules = []
        
        for schedule in self.schedules.values():
            if schedule.enabled and schedule.next_run and schedule.next_run <= now:
                due_schedules.append(schedule)
        
        return due_schedules
    
    async def execute_schedule(self, schedule: AuditSchedule) -> str:
        """Execute a scheduled audit"""
        audit_id = str(uuid.uuid4())
        
        # Create audit run record
        db = SessionLocal()
        try:
            audit_run = AuditRun(
                RunId=audit_id,
                TriggerType="scheduled",
                Scope=json.dumps({
                    "schedule_id": schedule.schedule_id,
                    "controls": schedule.controls,
                    "subscriptions": schedule.subscriptions
                }),
                StartTime=datetime.now(),
                Status=AuditStatus.RUNNING.value,
                FindingsCount=0
            )
            db.add(audit_run)
            db.commit()
        finally:
            db.close()
        
        # Mark as running
        self.running_audits[audit_id] = schedule.schedule_id
        
        # Execute audit in background
        asyncio.create_task(self._execute_audit_async(audit_id, schedule))
        
        return audit_id
    
    async def _execute_audit_async(self, audit_id: str, schedule: AuditSchedule):
        """Execute audit asynchronously"""
        try:
            findings_count = 0
            
            # Get controls to evaluate
            controls_to_evaluate = schedule.controls
            if not controls_to_evaluate:
                # If no specific controls, evaluate all available
                controls_to_evaluate = [
                    "IM-2", "IM-3", "IM-4", "IM-5", "IM-6",
                    "NS-1", "NS-2", "NS-3", "NS-4", "NS-5", "NS-6", "NS-7",
                    "DP-1", "DP-2", "DP-3", "DP-4", "DP-5", "DP-6", "DP-7",
                    "GS-1", "GS-2", "GS-3", "GS-4", "GS-5", "GS-6",
                    "PV-1", "PV-2", "PV-3", "PV-4", "PV-5", "PV-6", "PV-7",
                    "LT-1", "LT-2", "LT-3", "LT-4", "LT-5", "LT-6"
                ]
            
            # Evaluate each control
            for control_id in controls_to_evaluate:
                try:
                    evaluator = get_evaluator_by_control(control_id)
                    if evaluator:
                        if hasattr(evaluator, 'evaluate_all'):
                            findings = await evaluator.evaluate_all()
                        else:
                            findings = evaluator({})
                        
                        if findings:
                            findings_count += len(findings) if isinstance(findings, list) else 1
                except Exception as e:
                    print(f"Error evaluating control {control_id}: {e}")
                    continue
            
            # Update audit run status
            db = SessionLocal()
            try:
                audit_run = db.query(AuditRun).filter(AuditRun.RunId == audit_id).first()
                if audit_run:
                    audit_run.Status = AuditStatus.COMPLETED.value
                    audit_run.EndTime = datetime.now()
                    audit_run.FindingsCount = findings_count
                    db.commit()
            finally:
                db.close()
            
            # Update schedule
            schedule.last_run = datetime.now()
            schedule.next_run = self._calculate_next_run(schedule)
            
        except Exception as e:
            # Update audit run status to failed
            db = SessionLocal()
            try:
                audit_run = db.query(AuditRun).filter(AuditRun.RunId == audit_id).first()
                if audit_run:
                    audit_run.Status = AuditStatus.FAILED.value
                    audit_run.EndTime = datetime.now()
                    db.commit()
            finally:
                db.close()
            
            print(f"Audit execution failed: {e}")
        
        finally:
            # Remove from running audits
            if audit_id in self.running_audits:
                del self.running_audits[audit_id]
    
    async def get_audit_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audit execution history"""
        db = SessionLocal()
        try:
            audit_runs = db.query(AuditRun).order_by(AuditRun.StartTime.desc()).limit(limit).all()
            
            history = []
            for run in audit_runs:
                history.append({
                    "audit_id": run.RunId,
                    "trigger_type": run.TriggerType,
                    "status": run.Status,
                    "start_time": run.StartTime.isoformat() if run.StartTime else None,
                    "end_time": run.EndTime.isoformat() if run.EndTime else None,
                    "findings_count": run.FindingsCount,
                    "scope": json.loads(run.Scope) if run.Scope else {}
                })
            
            return history
        finally:
            db.close()
    
    async def get_audit_status(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific audit"""
        db = SessionLocal()
        try:
            audit_run = db.query(AuditRun).filter(AuditRun.RunId == audit_id).first()
            if not audit_run:
                return None
            
            return {
                "audit_id": audit_run.RunId,
                "status": audit_run.Status,
                "start_time": audit_run.StartTime.isoformat() if audit_run.StartTime else None,
                "end_time": audit_run.EndTime.isoformat() if audit_run.EndTime else None,
                "findings_count": audit_run.FindingsCount,
                "scope": json.loads(audit_run.Scope) if audit_run.Scope else {}
            }
        finally:
            db.close()


# Global scheduler instance
scheduler = AuditScheduler()


async def run_scheduled_audits():
    """Background task to run scheduled audits"""
    while True:
        try:
            due_schedules = await scheduler.get_due_schedules()
            
            for schedule in due_schedules:
                print(f"Executing scheduled audit: {schedule.name}")
                audit_id = await scheduler.execute_schedule(schedule)
                print(f"Started audit {audit_id}")
            
            # Wait 5 minutes before checking again
            await asyncio.sleep(300)
            
        except Exception as e:
            print(f"Error in scheduled audit runner: {e}")
            await asyncio.sleep(60)  # Wait 1 minute on error
