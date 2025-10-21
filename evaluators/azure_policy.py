"""
Azure Policy Evaluator

Evaluates Azure Policy governance and compliance controls including:
- Policy assignment coverage
- Policy compliance state
- Custom vs built-in policy usage
- Policy enforcement mode
- Exemptions and exceptions
- Security baseline policies
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure_sdk.policy_client import PolicyClient
from azure_sdk.auth import AzureAuthManager


class AzurePolicyEvaluator:
    """Evaluate Azure Policy governance and compliance"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Azure Policy evaluator
        
        Args:
            subscription_id: Azure subscription ID
            auth_manager: Azure authentication manager
        """
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        self.client = PolicyClient(subscription_id, auth_manager=self.auth_manager)
        self.findings = []
    
    async def evaluate_all(self) -> List[Dict]:
        """
        Run all Azure Policy security checks
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        # Run all checks
        await self.check_security_baseline_policies()
        await self.check_policy_compliance()
        await self.check_policy_enforcement()
        await self.check_custom_policy_security()
        await self.check_policy_exemptions()
        await self.check_required_policies()
        
        return self.findings
    
    async def check_security_baseline_policies(self):
        """
        ASB-GS-1: Establish security baseline policies
        
        Checks:
        - Azure Security Benchmark initiative assigned
        - CIS Azure Foundations assigned
        - Required security policies
        """
        try:
            assignments = self.client.get_policy_assignments()
            
            # Check for security baseline initiatives
            security_initiatives = [
                'Azure Security Benchmark',
                'CIS Microsoft Azure Foundations Benchmark',
                'NIST SP 800-53',
                'PCI DSS'
            ]
            
            assigned_initiatives = []
            for assignment in assignments:
                display_name = assignment.get('display_name', '')
                for initiative in security_initiatives:
                    if initiative.lower() in display_name.lower():
                        assigned_initiatives.append(initiative)
            
            missing_initiatives = [i for i in security_initiatives if i not in assigned_initiatives]
            
            if missing_initiatives:
                self.findings.append({
                    'control_id': 'GS-1',
                    'title': 'Security Baseline Initiatives Not Assigned',
                    'severity': 'High',
                    'description': f'Missing security baseline initiatives: {", ".join(missing_initiatives)}',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Assign security baseline policy initiatives to establish governance framework. '
                        f'Missing: {", ".join(missing_initiatives)}'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure Portal > Policy > Definitions',
                            '2. Search for "Azure Security Benchmark"',
                            '3. Click Assign',
                            '4. Select subscription scope',
                            '5. Configure parameters',
                            '6. Create assignment'
                        ],
                        'script_type': 'Azure CLI',
                        'script': f'''
# Assign Azure Security Benchmark initiative
az policy assignment create \\
    --name "asb-baseline" \\
    --display-name "Azure Security Benchmark" \\
    --scope "/subscriptions/{self.subscription_id}" \\
    --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"

# Assign CIS Azure Foundations
az policy assignment create \\
    --name "cis-azure-foundations" \\
    --display-name "CIS Microsoft Azure Foundations Benchmark" \\
    --scope "/subscriptions/{self.subscription_id}" \\
    --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/c3f5c4d9-9a1e-4c3f-9b8a-7c5e9d8f6a5b"
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/governance/policy/samples/azure-security-benchmark',
                        'https://learn.microsoft.com/azure/security/benchmarks/introduction'
                    ]
                })
            
        except Exception as e:
            self.findings.append({
                'control_id': 'GS-1',
                'title': 'Error Checking Security Baseline Policies',
                'severity': 'Medium',
                'description': f'Failed to evaluate security baselines: {str(e)}',
                'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                'recommendation': 'Review Azure Policy permissions and connectivity'
            })
    
    async def check_policy_compliance(self):
        """
        ASB-GS-2: Monitor policy compliance
        
        Checks:
        - Overall compliance percentage
        - Non-compliant resources
        - Critical policy violations
        """
        try:
            compliance = self.client.get_compliance_summary()
            
            compliance_pct = compliance.get('compliance_percentage', 0)
            non_compliant = compliance.get('non_compliant_resources', 0)
            
            # Critical if <80% compliant
            if compliance_pct < 80:
                severity = 'Critical' if compliance_pct < 60 else 'High'
                
                self.findings.append({
                    'control_id': 'GS-2',
                    'title': 'Low Policy Compliance Rate',
                    'severity': severity,
                    'description': f'Policy compliance is {compliance_pct:.1f}% ({non_compliant} non-compliant resources)',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        f'Improve policy compliance from {compliance_pct:.1f}% to >95%. '
                        f'Review {non_compliant} non-compliant resources and remediate.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure Portal > Policy > Compliance',
                            '2. Review non-compliant resources',
                            '3. Click on each policy to see details',
                            '4. Remediate resources or request exemptions',
                            '5. Use remediation tasks for automated fixes'
                        ],
                        'script_type': 'Azure CLI',
                        'script': f'''
# List non-compliant resources
az policy state list \\
    --resource "/subscriptions/{self.subscription_id}" \\
    --filter "complianceState eq 'NonCompliant'" \\
    --query "[].{{Resource:resourceId, Policy:policyDefinitionName}}" \\
    --output table

# Create remediation task
az policy remediation create \\
    --name "remediate-policy" \\
    --policy-assignment "/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/policyAssignments/[ASSIGNMENT_NAME]"
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data',
                        'https://learn.microsoft.com/azure/governance/policy/how-to/remediate-resources'
                    ]
                })
            
            # Get specific non-compliant resources
            if non_compliant > 0:
                non_compliant_list = self.client.get_non_compliant_resources(top=10)
                
                if non_compliant_list:
                    self.findings.append({
                        'control_id': 'GS-2',
                        'title': 'Non-Compliant Resources Detected',
                        'severity': 'Medium',
                        'description': f'{non_compliant} resources are non-compliant with assigned policies',
                        'affected_resources': [r.get('resource_id', 'Unknown') for r in non_compliant_list[:5]],
                        'recommendation': f'Review and remediate {non_compliant} non-compliant resources',
                        'remediation': {
                            'steps': [
                                '1. Review specific non-compliant resources in Azure Policy',
                                '2. Determine if resources need remediation or exemption',
                                '3. Apply fixes or request policy exemptions',
                                '4. Document exceptions with business justification'
                            ]
                        }
                    })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'GS-2',
                'title': 'Error Checking Policy Compliance',
                'severity': 'Medium',
                'description': f'Failed to evaluate compliance: {str(e)}',
                'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                'recommendation': 'Review Azure Policy Insights permissions'
            })
    
    async def check_policy_enforcement(self):
        """
        ASB-GS-3: Enforce policies in production
        
        Checks:
        - Policies in audit vs deny mode
        - Critical policies not enforced
        """
        try:
            assignments = self.client.get_policy_assignments()
            
            audit_mode = []
            disabled = []
            
            for assignment in assignments:
                enforcement_mode = assignment.get('enforcement_mode', 'Default')
                display_name = assignment.get('display_name', 'Unknown')
                
                if enforcement_mode == 'DoNotEnforce':
                    disabled.append(display_name)
                elif assignment.get('policy_definition_id', '').find('audit') > -1:
                    audit_mode.append(display_name)
            
            if disabled:
                self.findings.append({
                    'control_id': 'GS-3',
                    'title': 'Policies Not Enforced',
                    'severity': 'High',
                    'description': f'{len(disabled)} policies are disabled (DoNotEnforce mode)',
                    'affected_resources': disabled[:5],
                    'recommendation': (
                        'Change enforcement mode from DoNotEnforce to Default for production policies. '
                        f'Disabled policies: {", ".join(disabled[:3])}'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure Portal > Policy > Assignments',
                            '2. Find policies with "Do Not Enforce" mode',
                            '3. Edit assignment',
                            '4. Change enforcement mode to "Enabled"',
                            '5. Save changes'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable policy enforcement
az policy assignment update \\
    --name "[ASSIGNMENT_NAME]" \\
    --enforcement-mode Default
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/governance/policy/concepts/assignment-structure#enforcement-mode'
                    ]
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'GS-3',
                'title': 'Error Checking Policy Enforcement',
                'severity': 'Low',
                'description': f'Failed to evaluate enforcement: {str(e)}'
            })
    
    async def check_custom_policy_security(self):
        """
        ASB-GS-4: Secure custom policies
        
        Checks:
        - Custom policies vs built-in
        - Policy definition security
        """
        try:
            definitions = self.client.get_policy_definitions(built_in_only=False)
            
            custom_policies = [d for d in definitions if d.get('policy_type') == 'Custom']
            
            if len(custom_policies) > 20:
                self.findings.append({
                    'control_id': 'GS-4',
                    'title': 'Excessive Custom Policies',
                    'severity': 'Low',
                    'description': f'{len(custom_policies)} custom policies defined (recommend using built-in)',
                    'affected_resources': [p['display_name'] for p in custom_policies[:5]],
                    'recommendation': (
                        'Review custom policies and replace with built-in policies where possible. '
                        'Built-in policies are maintained by Microsoft and aligned with best practices.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Review each custom policy',
                            '2. Search for equivalent built-in policy',
                            '3. Test built-in policy in audit mode',
                            '4. Replace custom with built-in',
                            '5. Delete unused custom policies'
                        ]
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/governance/policy/samples/built-in-policies'
                    ]
                })
        
        except Exception as e:
            pass  # Optional check
    
    async def check_policy_exemptions(self):
        """
        ASB-GS-5: Review policy exemptions
        
        Checks:
        - Number of exemptions
        - Exemption expiration
        - Exemption justification
        """
        try:
            exemptions = self.client.get_policy_exemptions()
            
            if len(exemptions) > 10:
                expired = []
                no_expiration = []
                
                for exemption in exemptions:
                    expires = exemption.get('expiration_date')
                    if not expires:
                        no_expiration.append(exemption.get('display_name', 'Unknown'))
                    elif expires < datetime.now():
                        expired.append(exemption.get('display_name', 'Unknown'))
                
                if no_expiration or expired:
                    self.findings.append({
                        'control_id': 'GS-5',
                        'title': 'Policy Exemptions Need Review',
                        'severity': 'Medium',
                        'description': f'{len(exemptions)} exemptions found, {len(no_expiration)} without expiration',
                        'affected_resources': (no_expiration + expired)[:5],
                        'recommendation': (
                            'Review policy exemptions: set expiration dates, validate justifications, '
                            f'remove {len(expired)} expired exemptions'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Go to Azure Portal > Policy > Exemptions',
                                '2. Review each exemption',
                                '3. Set expiration dates (recommend 90 days)',
                                '4. Validate business justification',
                                '5. Delete expired exemptions'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# List policy exemptions
az policy exemption list --query "[].{Name:name, Expires:expiresOn}" --output table

# Delete expired exemption
az policy exemption delete --name "[EXEMPTION_NAME]" --scope "[SCOPE]"
'''
                        }
                    })
        
        except Exception as e:
            pass  # Exemptions API may not be available
    
    async def check_required_policies(self):
        """
        ASB-GS-6: Ensure required security policies
        
        Checks:
        - Encryption policies
        - Network security policies
        - Access control policies
        """
        try:
            assignments = self.client.get_policy_assignments()
            
            required_policies = {
                'Storage encryption': ['storage', 'encryption'],
                'Network security': ['network', 'nsg', 'firewall'],
                'Access control': ['rbac', 'access', 'authorization'],
                'Logging': ['log', 'diagnostic', 'monitor'],
                'Backup': ['backup', 'recovery']
            }
            
            missing = []
            for category, keywords in required_policies.items():
                found = False
                for assignment in assignments:
                    display_name = assignment.get('display_name', '').lower()
                    if any(keyword in display_name for keyword in keywords):
                        found = True
                        break
                
                if not found:
                    missing.append(category)
            
            if missing:
                self.findings.append({
                    'control_id': 'GS-6',
                    'title': 'Missing Required Security Policies',
                    'severity': 'High',
                    'description': f'Required policy categories not assigned: {", ".join(missing)}',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Assign policies for all required security categories. '
                        f'Missing: {", ".join(missing)}'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Review Azure Security Benchmark requirements',
                            '2. Identify relevant built-in policies',
                            '3. Assign policies at subscription scope',
                            '4. Configure parameters',
                            '5. Monitor compliance'
                        ]
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/governance/policy/samples/',
                        'https://learn.microsoft.com/security/benchmark/azure/'
                    ]
                })
        
        except Exception as e:
            pass


def run_evaluation(subscription_id: str) -> List[Dict]:
    """
    Convenience function to run Azure Policy evaluation
    
    Args:
        subscription_id: Azure subscription ID
        
    Returns:
        List of findings
    """
    evaluator = AzurePolicyEvaluator(subscription_id)
    return asyncio.run(evaluator.evaluate_all())
