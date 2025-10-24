"""
Executive Dashboard System
Provides high-level management views and KPIs for executives
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from persistence.models import Finding, ControlCatalog, AuditRun
from persistence.db import SessionLocal
from audit.audit_logger import audit_logger


@dataclass
class SecurityKPI:
    """Security Key Performance Indicator"""
    name: str
    value: float
    target: float
    unit: str
    trend: str  # "up", "down", "stable"
    status: str  # "good", "warning", "critical"


@dataclass
class RiskMetric:
    """Risk assessment metric"""
    category: str
    risk_level: str  # "low", "medium", "high", "critical"
    count: int
    trend: str
    last_updated: datetime


class ExecutiveDashboard:
    """Executive dashboard data provider"""
    
    def __init__(self):
        pass
    
    async def get_executive_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get executive summary dashboard data"""
        db = SessionLocal()
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get findings data
            total_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date
            ).count()
            
            open_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Status == "Open"
            ).count()
            
            critical_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "Critical",
                Finding.Status == "Open"
            ).count()
            
            high_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "High",
                Finding.Status == "Open"
            ).count()
            
            # Get audit runs
            total_audits = db.query(AuditRun).filter(
                AuditRun.StartTime >= start_date
            ).count()
            
            successful_audits = db.query(AuditRun).filter(
                AuditRun.StartTime >= start_date,
                AuditRun.Status == "completed"
            ).count()
            
            # Calculate compliance score
            total_controls = db.query(ControlCatalog).count()
            compliance_score = ((total_controls - open_findings) / total_controls * 100) if total_controls > 0 else 0
            
            # Get audit activity summary
            audit_summary = await audit_logger.get_audit_summary(days)
            
            return {
                "period_days": days,
                "compliance_score": round(compliance_score, 2),
                "total_findings": total_findings,
                "open_findings": open_findings,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "total_audits": total_audits,
                "successful_audits": successful_audits,
                "audit_success_rate": (successful_audits / total_audits * 100) if total_audits > 0 else 0,
                "total_controls": total_controls,
                "audit_activities": audit_summary.get("total_activities", 0),
                "security_events": audit_summary.get("security_events", 0),
                "high_risk_events": audit_summary.get("high_risk_events", 0),
                "last_updated": datetime.utcnow().isoformat()
            }
        finally:
            db.close()
    
    async def get_security_kpis(self, days: int = 30) -> List[SecurityKPI]:
        """Get security KPIs"""
        db = SessionLocal()
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Compliance Score KPI
            total_controls = db.query(ControlCatalog).count()
            open_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Status == "Open"
            ).count()
            compliance_score = ((total_controls - open_findings) / total_controls * 100) if total_controls > 0 else 0
            
            # Mean Time to Resolution (MTTR) KPI
            resolved_findings = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Status == "Resolved"
            ).all()
            
            mttr_hours = 0
            if resolved_findings:
                total_resolution_time = 0
                for finding in resolved_findings:
                    if finding.GeneratedAt:
                        # Simulate resolution time (in real implementation, track actual resolution time)
                        resolution_time = (datetime.utcnow() - finding.GeneratedAt).total_seconds() / 3600
                        total_resolution_time += resolution_time
                mttr_hours = total_resolution_time / len(resolved_findings)
            
            # Audit Success Rate KPI
            total_audits = db.query(AuditRun).filter(
                AuditRun.StartTime >= start_date
            ).count()
            successful_audits = db.query(AuditRun).filter(
                AuditRun.StartTime >= start_date,
                AuditRun.Status == "completed"
            ).count()
            audit_success_rate = (successful_audits / total_audits * 100) if total_audits > 0 else 0
            
            # Security Event Rate KPI
            audit_summary = await audit_logger.get_audit_summary(days)
            security_event_rate = audit_summary.get("security_events", 0) / days if days > 0 else 0
            
            kpis = [
                SecurityKPI(
                    name="Compliance Score",
                    value=compliance_score,
                    target=95.0,
                    unit="%",
                    trend="stable",
                    status="good" if compliance_score >= 90 else "warning" if compliance_score >= 75 else "critical"
                ),
                SecurityKPI(
                    name="Mean Time to Resolution",
                    value=mttr_hours,
                    target=24.0,
                    unit="hours",
                    trend="down",
                    status="good" if mttr_hours <= 24 else "warning" if mttr_hours <= 72 else "critical"
                ),
                SecurityKPI(
                    name="Audit Success Rate",
                    value=audit_success_rate,
                    target=95.0,
                    unit="%",
                    trend="stable",
                    status="good" if audit_success_rate >= 90 else "warning" if audit_success_rate >= 75 else "critical"
                ),
                SecurityKPI(
                    name="Security Event Rate",
                    value=security_event_rate,
                    target=5.0,
                    unit="events/day",
                    trend="stable",
                    status="good" if security_event_rate <= 5 else "warning" if security_event_rate <= 10 else "critical"
                )
            ]
            
            return kpis
        finally:
            db.close()
    
    async def get_risk_metrics(self, days: int = 30) -> List[RiskMetric]:
        """Get risk assessment metrics"""
        db = SessionLocal()
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Count findings by severity
            critical_count = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "Critical",
                Finding.Status == "Open"
            ).count()
            
            high_count = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "High",
                Finding.Status == "Open"
            ).count()
            
            medium_count = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "Medium",
                Finding.Status == "Open"
            ).count()
            
            low_count = db.query(Finding).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Severity == "Low",
                Finding.Status == "Open"
            ).count()
            
            # Count by domain
            domain_counts = {}
            findings_by_domain = db.query(Finding.Domain, Finding.Severity).filter(
                Finding.GeneratedAt >= start_date,
                Finding.Status == "Open"
            ).all()
            
            for domain, severity in findings_by_domain:
                if domain not in domain_counts:
                    domain_counts[domain] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                domain_counts[domain][severity.value] = domain_counts[domain].get(severity.value, 0) + 1
            
            risk_metrics = [
                RiskMetric(
                    category="Critical Findings",
                    risk_level="critical",
                    count=critical_count,
                    trend="stable",
                    last_updated=datetime.utcnow()
                ),
                RiskMetric(
                    category="High Findings",
                    risk_level="high",
                    count=high_count,
                    trend="stable",
                    last_updated=datetime.utcnow()
                ),
                RiskMetric(
                    category="Medium Findings",
                    risk_level="medium",
                    count=medium_count,
                    trend="stable",
                    last_updated=datetime.utcnow()
                ),
                RiskMetric(
                    category="Low Findings",
                    risk_level="low",
                    count=low_count,
                    trend="stable",
                    last_updated=datetime.utcnow()
                )
            ]
            
            # Add domain-specific risk metrics
            for domain, counts in domain_counts.items():
                total_domain_findings = sum(counts.values())
                if total_domain_findings > 0:
                    # Determine risk level based on critical/high findings
                    critical_high_count = counts.get("Critical", 0) + counts.get("High", 0)
                    risk_level = "critical" if critical_high_count > 5 else "high" if critical_high_count > 2 else "medium" if critical_high_count > 0 else "low"
                    
                    risk_metrics.append(RiskMetric(
                        category=f"{domain} Domain",
                        risk_level=risk_level,
                        count=total_domain_findings,
                        trend="stable",
                        last_updated=datetime.utcnow()
                    ))
            
            return risk_metrics
        finally:
            db.close()
    
    async def get_trend_data(self, days: int = 30) -> Dict[str, Any]:
        """Get trend data for charts"""
        db = SessionLocal()
        try:
            # Get daily findings data
            daily_findings = []
            daily_resolved = []
            daily_audits = []
            
            for i in range(days):
                date = datetime.utcnow() - timedelta(days=i)
                start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)
                
                # Count findings created on this day
                findings_count = db.query(Finding).filter(
                    Finding.GeneratedAt >= start_of_day,
                    Finding.GeneratedAt <= end_of_day
                ).count()
                
                # Count findings resolved on this day
                resolved_count = db.query(Finding).filter(
                    Finding.Status == "Resolved",
                    Finding.GeneratedAt >= start_of_day,
                    Finding.GeneratedAt <= end_of_day
                ).count()
                
                # Count audits run on this day
                audits_count = db.query(AuditRun).filter(
                    AuditRun.StartTime >= start_of_day,
                    AuditRun.StartTime <= end_of_day
                ).count()
                
                daily_findings.append({
                    "date": start_of_day.strftime("%Y-%m-%d"),
                    "count": findings_count
                })
                
                daily_resolved.append({
                    "date": start_of_day.strftime("%Y-%m-%d"),
                    "count": resolved_count
                })
                
                daily_audits.append({
                    "date": start_of_day.strftime("%Y-%m-%d"),
                    "count": audits_count
                })
            
            # Reverse to get chronological order
            daily_findings.reverse()
            daily_resolved.reverse()
            daily_audits.reverse()
            
            return {
                "findings_trend": daily_findings,
                "resolved_trend": daily_resolved,
                "audits_trend": daily_audits,
                "period_days": days
            }
        finally:
            db.close()
    
    async def get_top_risks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top security risks"""
        db = SessionLocal()
        try:
            # Get findings with highest risk scores
            top_findings = db.query(Finding).filter(
                Finding.Status == "Open"
            ).order_by(Finding.RiskScore.desc()).limit(limit).all()
            
            risks = []
            for finding in top_findings:
                risks.append({
                    "finding_id": finding.FindingId,
                    "control_id": finding.ControlId,
                    "domain": finding.Domain,
                    "severity": finding.Severity.value if finding.Severity else "Unknown",
                    "risk_score": finding.RiskScore,
                    "summary": finding.Summary,
                    "generated_at": finding.GeneratedAt.isoformat() if finding.GeneratedAt else None,
                    "recommendation": finding.Recommendation
                })
            
            return risks
        finally:
            db.close()
    
    async def get_compliance_by_domain(self) -> Dict[str, Any]:
        """Get compliance breakdown by domain"""
        db = SessionLocal()
        try:
            # Get all domains
            domains = db.query(ControlCatalog.Domain).distinct().all()
            
            domain_compliance = {}
            for domain_tuple in domains:
                domain = domain_tuple[0]
                
                # Count total controls in domain
                total_controls = db.query(ControlCatalog).filter(
                    ControlCatalog.Domain == domain
                ).count()
                
                # Count open findings in domain
                open_findings = db.query(Finding).filter(
                    Finding.Domain == domain,
                    Finding.Status == "Open"
                ).count()
                
                # Calculate compliance percentage
                compliance_percentage = ((total_controls - open_findings) / total_controls * 100) if total_controls > 0 else 0
                
                domain_compliance[domain] = {
                    "total_controls": total_controls,
                    "open_findings": open_findings,
                    "compliance_percentage": round(compliance_percentage, 2),
                    "status": "good" if compliance_percentage >= 90 else "warning" if compliance_percentage >= 75 else "critical"
                }
            
            return domain_compliance
        finally:
            db.close()


# Global executive dashboard instance
executive_dashboard = ExecutiveDashboard()
