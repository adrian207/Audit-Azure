"""
Azure Secure Score Calculation Engine

Calculates security posture score based on findings and control compliance.
Aligned with Microsoft Defender for Cloud Secure Score methodology.
"""

from __future__ import annotations
from typing import List, Dict, Optional, TYPE_CHECKING
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

if TYPE_CHECKING:
    from controls.asb_controls import ASBControl


class FindingSeverity(Enum):
    """Finding severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ControlStatus(Enum):
    """Control compliance status"""
    PASS = "Pass"
    FAIL = "Fail"
    PARTIAL = "Partial"
    NOT_APPLICABLE = "Not Applicable"
    NOT_ASSESSED = "Not Assessed"


@dataclass
class Finding:
    """Security finding from evaluation"""
    finding_id: str
    control_id: str
    severity: FindingSeverity
    resource_id: str
    status: str = "Open"


@dataclass
class ControlScore:
    """Individual control score details"""
    control_id: str
    domain: str
    weight: int
    max_points: int
    earned_points: int
    status: ControlStatus
    findings_count: int
    affected_resources: int
    compliance_percentage: float


@dataclass
class DomainScore:
    """Security domain aggregate score"""
    domain: str
    max_points: int
    earned_points: int
    compliance_percentage: float
    controls_assessed: int
    controls_passed: int
    controls_failed: int


@dataclass
class SecureScore:
    """Overall secure score"""
    total_score: float  # 0-100
    max_points: int
    earned_points: int
    score_date: datetime
    domain_scores: List[DomainScore]
    control_scores: List[ControlScore]
    findings_summary: Dict[str, int]
    improvement_recommendations: List[str]


class SecureScoreCalculator:
    """Calculate secure score from findings and controls"""
    
    # Severity weights for point deduction
    SEVERITY_WEIGHTS = {
        FindingSeverity.CRITICAL: 1.0,
        FindingSeverity.HIGH: 0.7,
        FindingSeverity.MEDIUM: 0.4,
        FindingSeverity.LOW: 0.2,
        FindingSeverity.INFORMATIONAL: 0.0,
    }
    
    def __init__(self, controls: List, findings: List[Finding]):
        """
        Initialize calculator
        
        Args:
            controls: List of ASBControl objects
            findings: List of Finding objects
        """
        self.controls = controls
        self.findings = findings
        self.controls_by_id = {c.control_id: c for c in controls}
        
    def calculate_score(self) -> SecureScore:
        """Calculate overall secure score"""
        
        # Group findings by control
        findings_by_control = self._group_findings_by_control()
        
        # Calculate control scores
        control_scores = []
        for control in self.controls:
            control_findings = findings_by_control.get(control.control_id, [])
            score = self._calculate_control_score(control, control_findings)
            control_scores.append(score)
        
        # Calculate domain scores
        domain_scores = self._calculate_domain_scores(control_scores)
        
        # Calculate overall score
        total_max = sum(cs.max_points for cs in control_scores)
        total_earned = sum(cs.earned_points for cs in control_scores)
        overall_score = (total_earned / total_max * 100) if total_max > 0 else 0
        
        # Generate findings summary
        findings_summary = self._generate_findings_summary()
        
        # Generate improvement recommendations
        recommendations = self._generate_recommendations(control_scores)
        
        return SecureScore(
            total_score=round(overall_score, 2),
            max_points=total_max,
            earned_points=total_earned,
            score_date=datetime.utcnow(),
            domain_scores=domain_scores,
            control_scores=control_scores,
            findings_summary=findings_summary,
            improvement_recommendations=recommendations
        )
    
    def _group_findings_by_control(self) -> Dict[str, List[Finding]]:
        """Group findings by control ID"""
        grouped = {}
        for finding in self.findings:
            if finding.control_id not in grouped:
                grouped[finding.control_id] = []
            grouped[finding.control_id].append(finding)
        return grouped
    
    def _calculate_control_score(self, control, findings: List[Finding]) -> ControlScore:
        """
        Calculate score for individual control
        
        Scoring methodology:
        - Base points = control.weight * 100
        - Deduct points for each finding based on severity
        - Control with 0 findings = 100% score
        - Multiple findings = cumulative point deduction (max 100%)
        """
        base_points = control.weight * 100
        max_points = base_points
        
        if not findings:
            # No findings = perfect score
            return ControlScore(
                control_id=control.control_id,
                domain=control.domain,
                weight=control.weight,
                max_points=max_points,
                earned_points=max_points,
                status=ControlStatus.PASS,
                findings_count=0,
                affected_resources=0,
                compliance_percentage=100.0
            )
        
        # Calculate point deduction based on findings
        total_deduction = 0
        affected_resources = set()
        
        for finding in findings:
            if finding.status == "Open":
                severity_weight = self.SEVERITY_WEIGHTS.get(finding.severity, 0.5)
                # Each finding deducts points proportional to severity
                deduction = base_points * severity_weight * 0.15  # Max 15% per finding
                total_deduction += deduction
                affected_resources.add(finding.resource_id)
        
        # Cap deduction at max points
        total_deduction = min(total_deduction, max_points)
        earned_points = max(0, max_points - total_deduction)
        
        compliance_pct = (earned_points / max_points * 100) if max_points > 0 else 0
        
        # Determine status
        if compliance_pct >= 100:
            status = ControlStatus.PASS
        elif compliance_pct >= 70:
            status = ControlStatus.PARTIAL
        else:
            status = ControlStatus.FAIL
        
        return ControlScore(
            control_id=control.control_id,
            domain=control.domain,
            weight=control.weight,
            max_points=max_points,
            earned_points=int(earned_points),
            status=status,
            findings_count=len(findings),
            affected_resources=len(affected_resources),
            compliance_percentage=round(compliance_pct, 2)
        )
    
    def _calculate_domain_scores(self, control_scores: List[ControlScore]) -> List[DomainScore]:
        """Aggregate control scores by domain"""
        domains = {}
        
        for cs in control_scores:
            if cs.domain not in domains:
                domains[cs.domain] = {
                    'max_points': 0,
                    'earned_points': 0,
                    'total': 0,
                    'passed': 0,
                    'failed': 0
                }
            
            domains[cs.domain]['max_points'] += cs.max_points
            domains[cs.domain]['earned_points'] += cs.earned_points
            domains[cs.domain]['total'] += 1
            
            if cs.status == ControlStatus.PASS:
                domains[cs.domain]['passed'] += 1
            elif cs.status == ControlStatus.FAIL:
                domains[cs.domain]['failed'] += 1
        
        domain_scores = []
        for domain, stats in domains.items():
            compliance_pct = (stats['earned_points'] / stats['max_points'] * 100) if stats['max_points'] > 0 else 0
            
            domain_scores.append(DomainScore(
                domain=domain,
                max_points=stats['max_points'],
                earned_points=stats['earned_points'],
                compliance_percentage=round(compliance_pct, 2),
                controls_assessed=stats['total'],
                controls_passed=stats['passed'],
                controls_failed=stats['failed']
            ))
        
        return sorted(domain_scores, key=lambda x: x.compliance_percentage)
    
    def _generate_findings_summary(self) -> Dict[str, int]:
        """Generate summary of findings by severity"""
        summary = {
            "total": len(self.findings),
            "open": len([f for f in self.findings if f.status == "Open"]),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for finding in self.findings:
            if finding.status == "Open":
                severity_key = finding.severity.value.lower()
                if severity_key in summary:
                    summary[severity_key] += 1
        
        return summary
    
    def _generate_recommendations(self, control_scores: List[ControlScore]) -> List[str]:
        """Generate top improvement recommendations"""
        recommendations = []
        
        # Find controls with lowest scores (highest impact)
        failed_controls = [cs for cs in control_scores if cs.status == ControlStatus.FAIL]
        failed_controls.sort(key=lambda x: (x.compliance_percentage, -x.weight))
        
        for cs in failed_controls[:10]:  # Top 10 recommendations
            control = self.controls_by_id.get(cs.control_id)
            if control:
                rec = (
                    f"{control.control_id}: {control.title} - "
                    f"{cs.findings_count} findings affecting {cs.affected_resources} resources. "
                    f"Current compliance: {cs.compliance_percentage}%"
                )
                recommendations.append(rec)
        
        return recommendations


class ScoreTracker:
    """Track secure score over time"""
    
    def __init__(self):
        self.history: List[SecureScore] = []
    
    def add_score(self, score: SecureScore):
        """Add a score snapshot"""
        self.history.append(score)
    
    def get_trend(self, days: int = 30) -> Dict:
        """Get score trend over time"""
        if not self.history:
            return {"scores": [], "dates": []}
        
        # Sort by date
        sorted_history = sorted(self.history, key=lambda x: x.score_date)
        
        return {
            "scores": [s.total_score for s in sorted_history[-days:]],
            "dates": [s.score_date.isoformat() for s in sorted_history[-days:]],
            "current": sorted_history[-1].total_score if sorted_history else 0,
            "previous": sorted_history[-2].total_score if len(sorted_history) > 1 else 0,
            "change": sorted_history[-1].total_score - sorted_history[-2].total_score if len(sorted_history) > 1 else 0
        }
    
    def get_domain_trends(self, domain: str, days: int = 30) -> Dict:
        """Get trend for specific domain"""
        if not self.history:
            return {"scores": [], "dates": []}
        
        sorted_history = sorted(self.history, key=lambda x: x.score_date)
        
        domain_scores = []
        dates = []
        
        for score in sorted_history[-days:]:
            domain_score = next((ds for ds in score.domain_scores if ds.domain == domain), None)
            if domain_score:
                domain_scores.append(domain_score.compliance_percentage)
                dates.append(score.score_date.isoformat())
        
        return {
            "scores": domain_scores,
            "dates": dates,
            "current": domain_scores[-1] if domain_scores else 0,
            "previous": domain_scores[-2] if len(domain_scores) > 1 else 0,
            "change": domain_scores[-1] - domain_scores[-2] if len(domain_scores) > 1 else 0
        }


def calculate_improvement_impact(control: 'ASBControl', findings: List[Finding]) -> Dict:
    """
    Calculate potential score improvement if control findings are remediated
    
    Returns:
        Dict with point_gain, new_score_estimate, priority
    """
    calculator = SecureScoreCalculator([control], findings)
    current_score = calculator.calculate_score()
    
    # Calculate score if all findings resolved
    resolved_score = SecureScoreCalculator([control], []).calculate_score()
    
    point_gain = resolved_score.earned_points - current_score.earned_points
    
    # Priority based on point gain and severity
    critical_count = len([f for f in findings if f.severity == FindingSeverity.CRITICAL])
    high_count = len([f for f in findings if f.severity == FindingSeverity.HIGH])
    
    if critical_count > 0 or point_gain > 50:
        priority = "Critical"
    elif high_count > 0 or point_gain > 20:
        priority = "High"
    elif point_gain > 10:
        priority = "Medium"
    else:
        priority = "Low"
    
    return {
        "control_id": control.control_id,
        "current_points": current_score.earned_points,
        "potential_points": resolved_score.earned_points,
        "point_gain": point_gain,
        "priority": priority,
        "findings_to_remediate": len(findings),
        "affected_resources": len(set(f.resource_id for f in findings))
    }
