"""
Trend Analysis and Risk Scoring System
Provides advanced analytics, trend analysis, and dynamic risk scoring
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from persistence.models import Finding, ControlCatalog, AuditRun
from persistence.db import SessionLocal
from sqlalchemy import func, desc
import statistics


class TrendDirection(Enum):
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    VOLATILE = "volatile"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrendDataPoint:
    """Data point for trend analysis"""
    date: datetime
    value: float
    metadata: Dict[str, Any]


@dataclass
class TrendAnalysis:
    """Trend analysis result"""
    metric_name: str
    period_days: int
    data_points: List[TrendDataPoint]
    trend_direction: TrendDirection
    trend_strength: float  # -1 to 1, where 1 is strong upward trend
    average_value: float
    volatility: float
    prediction_next_period: Optional[float]
    confidence_score: float


@dataclass
class RiskScore:
    """Dynamic risk score calculation"""
    resource_id: str
    resource_type: str
    base_score: float
    trend_adjustment: float
    severity_adjustment: float
    age_adjustment: float
    frequency_adjustment: float
    final_score: float
    risk_level: RiskLevel
    factors: Dict[str, float]
    last_updated: datetime


class TrendAnalyzer:
    """Advanced trend analysis and risk scoring"""
    
    def __init__(self):
        pass
    
    async def analyze_compliance_trend(
        self,
        days: int = 90,
        granularity: str = "daily"
    ) -> TrendAnalysis:
        """Analyze compliance score trend over time"""
        db = SessionLocal()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Get total controls count
            total_controls = db.query(ControlCatalog).count()
            
            # Calculate compliance score for each period
            data_points = []
            
            if granularity == "daily":
                period_delta = timedelta(days=1)
            elif granularity == "weekly":
                period_delta = timedelta(weeks=1)
            else:  # monthly
                period_delta = timedelta(days=30)
            
            current_date = start_date
            while current_date <= end_date:
                period_end = current_date + period_delta
                
                # Count open findings at this point in time
                open_findings = db.query(Finding).filter(
                    Finding.GeneratedAt <= period_end,
                    Finding.Status == "Open"
                ).count()
                
                # Calculate compliance score
                compliance_score = ((total_controls - open_findings) / total_controls * 100) if total_controls > 0 else 0
                
                data_points.append(TrendDataPoint(
                    date=current_date,
                    value=compliance_score,
                    metadata={
                        "open_findings": open_findings,
                        "total_controls": total_controls
                    }
                ))
                
                current_date += period_delta
            
            # Analyze trend
            trend_direction, trend_strength = self._calculate_trend(data_points)
            volatility = self._calculate_volatility(data_points)
            average_value = statistics.mean([dp.value for dp in data_points])
            
            # Predict next period
            prediction, confidence = self._predict_next_value(data_points)
            
            return TrendAnalysis(
                metric_name="Compliance Score",
                period_days=days,
                data_points=data_points,
                trend_direction=trend_direction,
                trend_strength=trend_strength,
                average_value=average_value,
                volatility=volatility,
                prediction_next_period=prediction,
                confidence_score=confidence
            )
            
        finally:
            db.close()
    
    async def analyze_finding_trends(
        self,
        days: int = 90,
        granularity: str = "daily"
    ) -> Dict[str, TrendAnalysis]:
        """Analyze finding trends by severity and domain"""
        db = SessionLocal()
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            trends = {}
            
            # Analyze by severity
            severities = ["Critical", "High", "Medium", "Low"]
            for severity in severities:
                trend_data = await self._analyze_finding_trend_by_filter(
                    db, start_date, end_date, granularity,
                    {"severity": severity}
                )
                trends[f"findings_{severity.lower()}"] = trend_data
            
            # Analyze by domain
            domains = db.query(Finding.Domain).distinct().all()
            for domain_tuple in domains:
                domain = domain_tuple[0]
                trend_data = await self._analyze_finding_trend_by_filter(
                    db, start_date, end_date, granularity,
                    {"domain": domain}
                )
                trends[f"findings_{domain.lower().replace(' ', '_')}"] = trend_data
            
            return trends
            
        finally:
            db.close()
    
    async def _analyze_finding_trend_by_filter(
        self,
        db,
        start_date: datetime,
        end_date: datetime,
        granularity: str,
        filter_criteria: Dict[str, str]
    ) -> TrendAnalysis:
        """Analyze finding trend with specific filter criteria"""
        if granularity == "daily":
            period_delta = timedelta(days=1)
        elif granularity == "weekly":
            period_delta = timedelta(weeks=1)
        else:
            period_delta = timedelta(days=30)
        
        data_points = []
        current_date = start_date
        
        while current_date <= end_date:
            period_end = current_date + period_delta
            
            # Build query with filter criteria
            query = db.query(Finding).filter(
                Finding.GeneratedAt <= period_end,
                Finding.Status == "Open"
            )
            
            if "severity" in filter_criteria:
                query = query.filter(Finding.Severity == filter_criteria["severity"])
            if "domain" in filter_criteria:
                query = query.filter(Finding.Domain == filter_criteria["domain"])
            
            count = query.count()
            
            data_points.append(TrendDataPoint(
                date=current_date,
                value=float(count),
                metadata={"count": count}
            ))
            
            current_date += period_delta
        
        # Analyze trend
        trend_direction, trend_strength = self._calculate_trend(data_points)
        volatility = self._calculate_volatility(data_points)
        average_value = statistics.mean([dp.value for dp in data_points])
        
        # Predict next period
        prediction, confidence = self._predict_next_value(data_points)
        
        metric_name = f"Findings ({filter_criteria.get('severity', filter_criteria.get('domain', 'All'))})"
        
        return TrendAnalysis(
            metric_name=metric_name,
            period_days=(end_date - start_date).days,
            data_points=data_points,
            trend_direction=trend_direction,
            trend_strength=trend_strength,
            average_value=average_value,
            volatility=volatility,
            prediction_next_period=prediction,
            confidence_score=confidence
        )
    
    def _calculate_trend(self, data_points: List[TrendDataPoint]) -> Tuple[TrendDirection, float]:
        """Calculate trend direction and strength"""
        if len(data_points) < 2:
            return TrendDirection.STABLE, 0.0
        
        values = [dp.value for dp in data_points]
        
        # Calculate linear regression slope
        n = len(values)
        x_mean = n / 2
        y_mean = statistics.mean(values)
        
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
        
        # Normalize slope to -1 to 1 range
        trend_strength = max(-1, min(1, slope / (max(values) - min(values)) * n))
        
        # Determine trend direction
        if abs(trend_strength) < 0.1:
            trend_direction = TrendDirection.STABLE
        elif trend_strength > 0.3:
            trend_direction = TrendDirection.IMPROVING
        elif trend_strength < -0.3:
            trend_direction = TrendDirection.DECLINING
        else:
            trend_direction = TrendDirection.VOLATILE
        
        return trend_direction, trend_strength
    
    def _calculate_volatility(self, data_points: List[TrendDataPoint]) -> float:
        """Calculate volatility (standard deviation)"""
        if len(data_points) < 2:
            return 0.0
        
        values = [dp.value for dp in data_points]
        return statistics.stdev(values)
    
    def _predict_next_value(self, data_points: List[TrendDataPoint]) -> Tuple[Optional[float], float]:
        """Predict next value using simple linear regression"""
        if len(data_points) < 3:
            return None, 0.0
        
        values = [dp.value for dp in data_points]
        n = len(values)
        
        # Simple linear regression
        x_mean = n / 2
        y_mean = statistics.mean(values)
        
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return y_mean, 0.5
        
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        
        # Predict next value
        next_x = n
        prediction = slope * next_x + intercept
        
        # Calculate confidence based on R-squared
        y_pred = [slope * i + intercept for i in range(n)]
        ss_res = sum((values[i] - y_pred[i]) ** 2 for i in range(n))
        ss_tot = sum((values[i] - y_mean) ** 2 for i in range(n))
        
        if ss_tot == 0:
            confidence = 0.0
        else:
            r_squared = 1 - (ss_res / ss_tot)
            confidence = max(0, min(1, r_squared))
        
        return prediction, confidence


class RiskScorer:
    """Dynamic risk scoring system"""
    
    def __init__(self):
        pass
    
    async def calculate_resource_risk_score(
        self,
        resource_id: str,
        resource_type: str
    ) -> RiskScore:
        """Calculate dynamic risk score for a resource"""
        db = SessionLocal()
        try:
            # Get all findings for this resource
            findings = db.query(Finding).filter(
                Finding.ImpactedResources.contains(resource_id),
                Finding.Status == "Open"
            ).all()
            
            if not findings:
                return RiskScore(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    base_score=0.0,
                    trend_adjustment=0.0,
                    severity_adjustment=0.0,
                    age_adjustment=0.0,
                    frequency_adjustment=0.0,
                    final_score=0.0,
                    risk_level=RiskLevel.LOW,
                    factors={},
                    last_updated=datetime.utcnow()
                )
            
            # Calculate base score from severity
            severity_scores = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
            base_score = sum(severity_scores.get(f.Severity.value, 0) for f in findings)
            
            # Calculate trend adjustment
            trend_adjustment = await self._calculate_trend_adjustment(db, resource_id)
            
            # Calculate severity adjustment
            severity_adjustment = self._calculate_severity_adjustment(findings)
            
            # Calculate age adjustment (older findings = higher risk)
            age_adjustment = self._calculate_age_adjustment(findings)
            
            # Calculate frequency adjustment (more findings = higher risk)
            frequency_adjustment = self._calculate_frequency_adjustment(len(findings))
            
            # Calculate final score
            final_score = base_score + trend_adjustment + severity_adjustment + age_adjustment + frequency_adjustment
            
            # Determine risk level
            if final_score >= 20:
                risk_level = RiskLevel.CRITICAL
            elif final_score >= 15:
                risk_level = RiskLevel.HIGH
            elif final_score >= 8:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
            
            return RiskScore(
                resource_id=resource_id,
                resource_type=resource_type,
                base_score=base_score,
                trend_adjustment=trend_adjustment,
                severity_adjustment=severity_adjustment,
                age_adjustment=age_adjustment,
                frequency_adjustment=frequency_adjustment,
                final_score=final_score,
                risk_level=risk_level,
                factors={
                    "total_findings": len(findings),
                    "critical_count": len([f for f in findings if f.Severity.value == "Critical"]),
                    "high_count": len([f for f in findings if f.Severity.value == "High"]),
                    "medium_count": len([f for f in findings if f.Severity.value == "Medium"]),
                    "low_count": len([f for f in findings if f.Severity.value == "Low"])
                },
                last_updated=datetime.utcnow()
            )
            
        finally:
            db.close()
    
    async def _calculate_trend_adjustment(self, db, resource_id: str) -> float:
        """Calculate trend adjustment based on recent finding activity"""
        # Get findings from last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_findings = db.query(Finding).filter(
            Finding.ImpactedResources.contains(resource_id),
            Finding.GeneratedAt >= thirty_days_ago
        ).count()
        
        # Get findings from previous 30 days
        sixty_days_ago = datetime.utcnow() - timedelta(days=60)
        older_findings = db.query(Finding).filter(
            Finding.ImpactedResources.contains(resource_id),
            Finding.GeneratedAt >= sixty_days_ago,
            Finding.GeneratedAt < thirty_days_ago
        ).count()
        
        # Calculate trend
        if older_findings == 0:
            return recent_findings * 0.5  # New findings
        else:
            trend_ratio = recent_findings / older_findings
            if trend_ratio > 1.5:
                return 2.0  # Increasing trend
            elif trend_ratio < 0.5:
                return -1.0  # Decreasing trend
            else:
                return 0.0  # Stable trend
    
    def _calculate_severity_adjustment(self, findings: List[Finding]) -> float:
        """Calculate adjustment based on severity distribution"""
        if not findings:
            return 0.0
        
        critical_count = len([f for f in findings if f.Severity.value == "Critical"])
        high_count = len([f for f in findings if f.Severity.value == "High"])
        
        # Higher adjustment for more critical findings
        return (critical_count * 2.0) + (high_count * 1.0)
    
    def _calculate_age_adjustment(self, findings: List[Finding]) -> float:
        """Calculate adjustment based on age of findings"""
        if not findings:
            return 0.0
        
        now = datetime.utcnow()
        total_age_days = 0
        
        for finding in findings:
            if finding.GeneratedAt:
                age_days = (now - finding.GeneratedAt).days
                total_age_days += age_days
        
        average_age_days = total_age_days / len(findings)
        
        # Older findings get higher adjustment
        if average_age_days > 90:
            return 3.0
        elif average_age_days > 30:
            return 1.5
        elif average_age_days > 7:
            return 0.5
        else:
            return 0.0
    
    def _calculate_frequency_adjustment(self, finding_count: int) -> float:
        """Calculate adjustment based on number of findings"""
        if finding_count >= 10:
            return 3.0
        elif finding_count >= 5:
            return 2.0
        elif finding_count >= 3:
            return 1.0
        else:
            return 0.0
    
    async def get_top_risk_resources(self, limit: int = 20) -> List[RiskScore]:
        """Get top risk resources across the environment"""
        db = SessionLocal()
        try:
            # Get all unique resources from findings
            findings = db.query(Finding).filter(Finding.Status == "Open").all()
            
            resource_map = {}
            for finding in findings:
                try:
                    impacted_resources = json.loads(finding.ImpactedResources)
                    for resource in impacted_resources:
                        resource_id = resource.get("id")
                        if resource_id:
                            if resource_id not in resource_map:
                                resource_map[resource_id] = {
                                    "type": resource.get("type", "unknown"),
                                    "name": resource.get("name", "unknown")
                                }
                except:
                    continue
            
            # Calculate risk scores for each resource
            risk_scores = []
            for resource_id, resource_info in resource_map.items():
                risk_score = await self.calculate_resource_risk_score(
                    resource_id, resource_info["type"]
                )
                risk_scores.append(risk_score)
            
            # Sort by final score and return top N
            risk_scores.sort(key=lambda x: x.final_score, reverse=True)
            return risk_scores[:limit]
            
        finally:
            db.close()
    
    async def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary"""
        db = SessionLocal()
        try:
            # Get all open findings
            open_findings = db.query(Finding).filter(Finding.Status == "Open").all()
            
            # Calculate risk distribution
            risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            total_risk_score = 0
            
            for finding in open_findings:
                severity = finding.Severity.value if finding.Severity else "Low"
                risk_distribution[severity] += 1
                
                # Add to total risk score
                severity_scores = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
                total_risk_score += severity_scores.get(severity, 1)
            
            # Calculate average risk score
            average_risk_score = total_risk_score / len(open_findings) if open_findings else 0
            
            # Determine overall risk level
            if average_risk_score >= 7:
                overall_risk_level = RiskLevel.CRITICAL
            elif average_risk_score >= 5:
                overall_risk_level = RiskLevel.HIGH
            elif average_risk_score >= 3:
                overall_risk_level = RiskLevel.MEDIUM
            else:
                overall_risk_level = RiskLevel.LOW
            
            return {
                "total_findings": len(open_findings),
                "risk_distribution": risk_distribution,
                "total_risk_score": total_risk_score,
                "average_risk_score": round(average_risk_score, 2),
                "overall_risk_level": overall_risk_level.value,
                "last_updated": datetime.utcnow().isoformat()
            }
            
        finally:
            db.close()


# Global instances
trend_analyzer = TrendAnalyzer()
risk_scorer = RiskScorer()
