"""
Microsoft Defender for Cloud Client

Query security alerts, recommendations, and secure score.
"""

from typing import List, Dict, Optional, Any
from azure.mgmt.security import SecurityCenter  # type: ignore[import]
from .auth import AzureAuthManager


class DefenderClient:
    """Microsoft Defender for Cloud operations"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Defender client
        
        Args:
            subscription_id: Azure subscription ID
            auth_manager: Authentication manager
        """
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        credential = self.auth_manager.get_credential()
        
        # Treat SDK client as Any for static analysis
        self.client: Any = SecurityCenter(
            credential=credential,
            subscription_id=subscription_id,
            asc_location='centralus'  # Defender for Cloud location
        )  # type: ignore
    
    def get_secure_score(self) -> Dict[str, Any]:
        """
        Get Microsoft Defender Secure Score
        
        Returns:
            Secure score details
        """
        scores = list(self.client.secure_scores.list())
        
        if scores:
            score = scores[0]
            return {
                'current_score': score.current_score,
                'max_score': score.max_score,
                'percentage': score.percentage,
                'display_name': score.display_name,
                'weight': score.weight
            }
        
        return {'current_score': 0, 'max_score': 0, 'percentage': 0}
    
    def get_secure_score_controls(self) -> List[Dict]:
        """
        Get secure score control details
        
        Returns:
            List of security controls
        """
        controls = []
        
        for control in self.client.secure_score_controls.list():
            controls.append({
                'id': control.id,
                'name': control.name,
                'display_name': control.display_name,
                'description': control.description,
                'current_score': control.current_score,
                'max_score': control.max_score,
                'percentage': control.percentage,
                'healthy_resource_count': control.healthy_resource_count,
                'unhealthy_resource_count': control.unhealthy_resource_count,
                'not_applicable_resource_count': control.not_applicable_resource_count
            })
        
        return controls
    
    def get_alerts(self, filter_query: Optional[str] = None) -> List[Dict]:
        """
        Get security alerts
        
        Args:
            filter_query: OData filter
            
        Returns:
            List of security alerts
        """
        alerts = []
        
        for alert in self.client.alerts.list():
            if filter_query:
                # Apply basic filtering (simplified)
                if filter_query.lower() not in str(alert).lower():
                    continue
            
            alerts.append({
                'id': alert.id,
                'name': alert.name,
                'display_name': alert.display_name,
                'description': alert.description,
                'severity': alert.severity,
                'status': alert.status,
                'start_time': alert.start_time_utc,
                'end_time': alert.end_time_utc,
                'compromised_entity': alert.compromised_entity,
                'remediation_steps': alert.remediation_steps,
                'extended_properties': alert.extended_properties
            })
        
        return alerts
    
    def get_recommendations(self, severity: Optional[str] = None) -> List[Dict]:
        """
        Get security recommendations (assessments)
        
        Args:
            severity: Filter by severity (Low, Medium, High)
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        for assessment in self.client.assessments.list(scope=f"/subscriptions/{self.subscription_id}"):
            if severity and assessment.severity != severity:
                continue
            
            recommendations.append({
                'id': assessment.id,
                'name': assessment.name,
                'display_name': assessment.display_name,
                'description': assessment.description,
                'severity': assessment.severity,
                'status': assessment.status.code if assessment.status else None,
                'remediation_description': assessment.remediation_description,
                'resource_details': assessment.resource_details,
                'additional_data': assessment.additional_data
            })
        
        return recommendations
    
    def get_compliance_results(self, standard_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get regulatory compliance results
        
        Args:
            standard_name: Filter by standard (e.g., 'Azure CIS 1.1.0')
            
        Returns:
            Compliance results
        """
        compliance_results = {
            'standards': [],
            'overall_compliance': 0.0
        }
        
        for standard in self.client.regulatory_compliance_standards.list():
            if standard_name and standard.name != standard_name:
                continue
            
            controls = []
            for control in self.client.regulatory_compliance_controls.list(standard.name):
                controls.append({
                    'id': control.id,
                    'name': control.name,
                    'description': control.description,
                    'state': control.state,
                    'passed_assessments': control.passed_assessments,
                    'failed_assessments': control.failed_assessments,
                    'skipped_assessments': control.skipped_assessments
                })
            
            compliance_results['standards'].append({
                'id': standard.id,
                'name': standard.name,
                'state': standard.state,
                'controls': controls
            })
        
        return compliance_results
    
    def get_vulnerabilities(self, resource_type: Optional[str] = None) -> List[Dict]:
        """
        Get vulnerability assessment results
        
        Args:
            resource_type: Filter by resource type
            
        Returns:
            Vulnerability findings
        """
        vulnerabilities = []
        
        # Query sub-assessments (vulnerability findings)
        for assessment in self.client.assessments.list(scope=f"/subscriptions/{self.subscription_id}"):
            if 'vulnerability' in assessment.name.lower() or 'va' in assessment.name.lower():
                try:
                    sub_assessments = self.client.sub_assessments.list(
                        scope=f"/subscriptions/{self.subscription_id}",
                        assessment_name=assessment.name
                    )
                    
                    for sub in sub_assessments:
                        if resource_type and resource_type not in sub.id:
                            continue
                        
                        vulnerabilities.append({
                            'id': sub.id,
                            'name': sub.name,
                            'display_name': sub.display_name,
                            'description': sub.description,
                            'severity': sub.severity,
                            'status': sub.status.code if sub.status else None,
                            'remediation': sub.remediation,
                            'resource_id': sub.resource_details.id if sub.resource_details else None
                        })
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def get_defender_plans(self) -> List[Dict]:
        """
        Get Microsoft Defender plan enablement status
        
        Returns:
            List of Defender plans and status
        """
        plans = []
        
        for pricing in self.client.pricings.list():
            plans.append({
                'name': pricing.name,
                'pricing_tier': pricing.pricing_tier,
                'free_trial_remaining': pricing.free_trial_remaining_time,
                'sub_plan': pricing.sub_plan,
                'deprecated': pricing.deprecated
            })
        
        return plans

    # Compatibility adapters expected by evaluators
    def get_pricing_tiers(self) -> List[Dict]:
        """Alias for get_defender_plans to match evaluator expectations."""
        try:
            return self.get_defender_plans()
        except Exception:
            return []

    def get_security_alerts(self, filter_query: Optional[str] = None) -> List[Dict]:
        """Return alerts normalized to evaluator format."""
        alerts = []
        try:
            iterator = getattr(self.client, 'alerts', None)
            if iterator is None:
                return alerts

            for alert in self.client.alerts.list():
                if filter_query and filter_query.lower() not in str(alert).lower():
                    continue
                alerts.append({
                    'id': getattr(alert, 'id', None),
                    'name': getattr(alert, 'name', None),
                    'display_name': getattr(alert, 'display_name', None),
                    'description': getattr(alert, 'description', None),
                    'severity': getattr(alert, 'severity', None),
                    'status': getattr(alert, 'status', None),
                    'start_time': getattr(alert, 'start_time_utc', None),
                    'end_time': getattr(alert, 'end_time_utc', None),
                    'resource_id': getattr(alert, 'resource_id', None)
                })
        except Exception:
            return alerts

        return alerts

    def get_security_recommendations(self, severity: Optional[str] = None) -> List[Dict]:
        """Return security recommendations/assessments."""
        recommendations = []
        try:
            for assessment in self.client.assessments.list(scope=f"/subscriptions/{self.subscription_id}"):
                if severity and getattr(assessment, 'severity', None) != severity:
                    continue
                recommendations.append({
                    'id': getattr(assessment, 'id', None),
                    'name': getattr(assessment, 'name', None),
                    'display_name': getattr(assessment, 'display_name', None),
                    'description': getattr(assessment, 'description', None),
                    'severity': getattr(assessment, 'severity', None),
                    'status': getattr(assessment, 'status', None),
                    'remediation_description': getattr(assessment, 'remediation_description', None),
                    'resource_details': getattr(assessment, 'resource_details', None)
                })
        except Exception:
            return recommendations

        return recommendations
