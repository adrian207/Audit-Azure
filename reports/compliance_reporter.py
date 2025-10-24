"""
Compliance Reporting System
Generates comprehensive compliance reports for various frameworks
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
from persistence.models import Finding, ControlCatalog, AuditRun
from persistence.db import SessionLocal


class ComplianceFramework(Enum):
    ASB = "asb"  # Azure Security Benchmark
    CIS = "cis"  # CIS Controls
    NIST = "nist"  # NIST Cybersecurity Framework
    SOC2 = "soc2"  # SOC 2 Type II
    ISO27001 = "iso27001"  # ISO 27001
    PCI_DSS = "pci_dss"  # PCI DSS
    CUSTOM = "custom"  # Custom framework


class ReportFormat(Enum):
    JSON = "json"
    PDF = "pdf"
    EXCEL = "excel"
    HTML = "html"


@dataclass
class ComplianceReport:
    """Compliance report configuration"""
    report_id: str
    name: str
    framework: ComplianceFramework
    format: ReportFormat
    scope: Dict[str, Any]  # Controls, subscriptions, time range
    generated_at: datetime
    generated_by: str
    status: str = "generating"
    findings_count: int = 0
    compliance_score: float = 0.0


class ComplianceReporter:
    """Generates compliance reports"""
    
    def __init__(self):
        self.framework_mappings = self._load_framework_mappings()
    
    def _load_framework_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance framework mappings"""
        return {
            ComplianceFramework.ASB.value: {
                "name": "Azure Security Benchmark",
                "version": "v3.0",
                "controls": {
                    "IM": "Identity Management",
                    "NS": "Network Security", 
                    "DP": "Data Protection",
                    "GS": "Governance & Strategy",
                    "PV": "Posture & Vulnerability Management",
                    "LT": "Logging & Threat Detection"
                },
                "scoring": {
                    "Critical": 4,
                    "High": 3,
                    "Medium": 2,
                    "Low": 1
                }
            },
            ComplianceFramework.CIS.value: {
                "name": "CIS Controls",
                "version": "v8",
                "controls": {
                    "CIS-1": "Inventory and Control of Enterprise Assets",
                    "CIS-2": "Inventory and Control of Software Assets",
                    "CIS-3": "Data Protection",
                    "CIS-4": "Secure Configuration of Enterprise Assets",
                    "CIS-5": "Account Management",
                    "CIS-6": "Access Control Management"
                },
                "scoring": {
                    "Critical": 4,
                    "High": 3,
                    "Medium": 2,
                    "Low": 1
                }
            },
            ComplianceFramework.NIST.value: {
                "name": "NIST Cybersecurity Framework",
                "version": "1.1",
                "functions": {
                    "ID": "Identify",
                    "PR": "Protect",
                    "DE": "Detect",
                    "RS": "Respond",
                    "RC": "Recover"
                },
                "scoring": {
                    "Critical": 4,
                    "High": 3,
                    "Medium": 2,
                    "Low": 1
                }
            }
        }
    
    async def generate_report(
        self,
        framework: ComplianceFramework,
        format: ReportFormat,
        scope: Dict[str, Any],
        generated_by: str = "system"
    ) -> str:
        """Generate a compliance report"""
        report_id = str(uuid.uuid4())
        
        report = ComplianceReport(
            report_id=report_id,
            name=f"{framework.value.upper()} Compliance Report",
            framework=framework,
            format=format,
            scope=scope,
            generated_at=datetime.now(),
            generated_by=generated_by
        )
        
        # Generate report content
        report_data = await self._generate_report_content(report)
        
        # Calculate compliance score
        report.compliance_score = self._calculate_compliance_score(report_data)
        report.findings_count = len(report_data.get("findings", []))
        report.status = "completed"
        
        return report_id
    
    async def _generate_report_content(self, report: ComplianceReport) -> Dict[str, Any]:
        """Generate the actual report content"""
        db = SessionLocal()
        try:
            # Get findings based on scope
            findings_query = db.query(Finding)
            
            # Apply time filter if specified
            if "time_range" in report.scope:
                time_range = report.scope["time_range"]
                if "start_date" in time_range:
                    findings_query = findings_query.filter(
                        Finding.GeneratedAt >= datetime.fromisoformat(time_range["start_date"])
                    )
                if "end_date" in time_range:
                    findings_query = findings_query.filter(
                        Finding.GeneratedAt <= datetime.fromisoformat(time_range["end_date"])
                    )
            
            # Apply control filter if specified
            if "controls" in report.scope and report.scope["controls"]:
                findings_query = findings_query.filter(
                    Finding.ControlId.in_(report.scope["controls"])
                )
            
            findings = findings_query.all()
            
            # Get control catalog
            controls_query = db.query(ControlCatalog)
            if "controls" in report.scope and report.scope["controls"]:
                controls_query = controls_query.filter(
                    ControlCatalog.ControlId.in_(report.scope["controls"])
                )
            
            controls = controls_query.all()
            
            # Generate framework-specific content
            framework_data = self.framework_mappings.get(report.framework.value, {})
            
            report_content = {
                "report_id": report.report_id,
                "framework": {
                    "name": framework_data.get("name", report.framework.value),
                    "version": framework_data.get("version", "1.0")
                },
                "generated_at": report.generated_at.isoformat(),
                "generated_by": report.generated_by,
                "scope": report.scope,
                "summary": self._generate_summary(findings, controls),
                "findings": self._format_findings(findings),
                "controls": self._format_controls(controls),
                "recommendations": self._generate_recommendations(findings, controls),
                "compliance_score": report.compliance_score
            }
            
            return report_content
            
        finally:
            db.close()
    
    def _generate_summary(self, findings: List[Finding], controls: List[ControlCatalog]) -> Dict[str, Any]:
        """Generate report summary"""
        total_findings = len(findings)
        open_findings = len([f for f in findings if f.Status == "Open"])
        resolved_findings = len([f for f in findings if f.Status == "Resolved"])
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.Severity.value if finding.Severity else "Unknown"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by domain
        domain_counts = {}
        for control in controls:
            domain = control.Domain
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        return {
            "total_findings": total_findings,
            "open_findings": open_findings,
            "resolved_findings": resolved_findings,
            "severity_breakdown": severity_counts,
            "domain_breakdown": domain_counts,
            "total_controls": len(controls),
            "compliance_percentage": ((len(controls) - open_findings) / len(controls) * 100) if controls else 0
        }
    
    def _format_findings(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Format findings for report"""
        formatted_findings = []
        
        for finding in findings:
            formatted_findings.append({
                "finding_id": finding.FindingId,
                "control_id": finding.ControlId,
                "domain": finding.Domain,
                "severity": finding.Severity.value if finding.Severity else "Unknown",
                "risk_score": finding.RiskScore,
                "summary": finding.Summary,
                "description": finding.Description,
                "status": finding.Status.value if finding.Status else "Unknown",
                "generated_at": finding.GeneratedAt.isoformat() if finding.GeneratedAt else None,
                "recommendation": finding.Recommendation,
                "impacted_resources": json.loads(finding.ImpactedResources) if finding.ImpactedResources else []
            })
        
        return formatted_findings
    
    def _format_controls(self, controls: List[ControlCatalog]) -> List[Dict[str, Any]]:
        """Format controls for report"""
        formatted_controls = []
        
        for control in controls:
            formatted_controls.append({
                "control_id": control.ControlId,
                "title": control.Title,
                "domain": control.Domain,
                "benchmark_mappings": json.loads(control.BenchmarkMappings) if control.BenchmarkMappings else {},
                "recommendation": control.Recommendation,
                "remediation_type": control.RemediationType
            })
        
        return formatted_controls
    
    def _generate_recommendations(self, findings: List[Finding], controls: List[ControlCatalog]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Group findings by control
        findings_by_control = {}
        for finding in findings:
            control_id = finding.ControlId
            if control_id not in findings_by_control:
                findings_by_control[control_id] = []
            findings_by_control[control_id].append(finding)
        
        # Generate recommendations for each control with findings
        for control_id, control_findings in findings_by_control.items():
            open_findings = [f for f in control_findings if f.Status == "Open"]
            
            if open_findings:
                # Find the control definition
                control_def = next((c for c in controls if c.ControlId == control_id), None)
                
                if control_def:
                    recommendations.append({
                        "control_id": control_id,
                        "title": control_def.Title,
                        "priority": "High" if any(f.Severity.value == "Critical" for f in open_findings) else "Medium",
                        "open_findings_count": len(open_findings),
                        "recommendation": control_def.Recommendation,
                        "remediation_type": control_def.RemediationType,
                        "estimated_effort": self._estimate_effort(open_findings)
                    })
        
        # Sort by priority
        priority_order = {"High": 1, "Medium": 2, "Low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return recommendations
    
    def _estimate_effort(self, findings: List[Finding]) -> str:
        """Estimate remediation effort"""
        total_findings = len(findings)
        
        if total_findings == 0:
            return "None"
        elif total_findings <= 5:
            return "Low (1-2 hours)"
        elif total_findings <= 15:
            return "Medium (4-8 hours)"
        else:
            return "High (1-2 days)"
    
    def _calculate_compliance_score(self, report_data: Dict[str, Any]) -> float:
        """Calculate overall compliance score"""
        summary = report_data.get("summary", {})
        total_controls = summary.get("total_controls", 0)
        open_findings = summary.get("open_findings", 0)
        
        if total_controls == 0:
            return 0.0
        
        compliance_percentage = ((total_controls - open_findings) / total_controls) * 100
        return round(compliance_percentage, 2)
    
    async def get_report_templates(self) -> List[Dict[str, Any]]:
        """Get available report templates"""
        templates = []
        
        for framework_key, framework_data in self.framework_mappings.items():
            templates.append({
                "framework": framework_key,
                "name": framework_data["name"],
                "version": framework_data["version"],
                "description": f"Compliance report for {framework_data['name']}",
                "available_formats": [fmt.value for fmt in ReportFormat]
            })
        
        return templates
    
    async def export_report(self, report_id: str, format: ReportFormat) -> Dict[str, Any]:
        """Export report in specified format"""
        # This would integrate with actual export libraries
        # For now, return a placeholder
        return {
            "report_id": report_id,
            "format": format.value,
            "download_url": f"/reports/{report_id}/download/{format.value}",
            "status": "ready"
        }


# Global reporter instance
reporter = ComplianceReporter()
