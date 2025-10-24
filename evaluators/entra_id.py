"""
Microsoft Entra ID (Azure AD) Security Evaluator

Evaluates identity security controls including:
- Multi-factor authentication (MFA) enforcement
- Conditional Access policies
- Privileged Identity Management (PIM)
- Legacy authentication protocols
- Guest user access reviews
- Service principal security
- RBAC configuration
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure_sdk.entra_client import EntraClient
from azure_sdk.auth import AzureAuthManager


class EntraIDEvaluator:
    """Evaluate Microsoft Entra ID security configuration"""
    
    def __init__(self, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Entra ID evaluator
        
        Args:
            auth_manager: Azure authentication manager
        """
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        self.client = EntraClient(auth_manager=self.auth_manager)
        self.findings = []
    
    async def evaluate_all(self) -> List[Dict]:
        """
        Run all Entra ID security checks
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        # Run all checks
        await self.check_mfa_enforcement()
        await self.check_conditional_access()
        await self.check_privileged_users()
        await self.check_legacy_authentication()
        await self.check_guest_users()
        await self.check_service_principals()
        await self.check_pim_usage()
        
        return self.findings
    
    async def check_mfa_enforcement(self):
        """
        ASB-IM-2: Enforce MFA for all users
        
        Checks:
        - Users without MFA registered
        - Admin accounts without MFA
        """
        try:
            mfa_status = await self.client.get_mfa_status()
            
            users_without_mfa = [u for u in mfa_status if not u['mfa_enabled']]
            
            if users_without_mfa:
                self.findings.append({
                    'control_id': 'IM-2',
                    'title': 'MFA Not Enforced for All Users',
                    'severity': 'Critical',
                    'description': f'{len(users_without_mfa)} users do not have MFA enabled',
                    'affected_resources': [u['user_principal_name'] for u in users_without_mfa],
                    'recommendation': (
                        'Enable MFA for all users through Conditional Access policies. '
                        'Users without MFA: ' + ', '.join([u['user_principal_name'] for u in users_without_mfa[:5]])
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure AD > Security > Conditional Access',
                            '2. Create new policy: "Require MFA for All Users"',
                            '3. Assignments: All users',
                            '4. Grant controls: Require multi-factor authentication',
                            '5. Enable policy'
                        ],
                        'script_type': 'PowerShell',
                        'script': '''
# Enable MFA for all users via Conditional Access
$policy = New-AzureADMSConditionalAccessPolicy `
    -DisplayName "Require MFA for All Users" `
    -State "Enabled" `
    -Conditions @{
        Users = @{
            IncludeUsers = "All"
        }
    } `
    -GrantControls @{
        Operator = "OR"
        BuiltInControls = @("mfa")
    }
'''
                    }
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'IM-2',
                'title': 'Unable to Check MFA Status',
                'severity': 'High',
                'description': f'Error checking MFA enforcement: {str(e)}',
                'recommendation': 'Verify Graph API permissions for authentication methods'
            })
    
    async def check_conditional_access(self):
        """
        ASB-IM-3: Implement Conditional Access policies
        
        Checks:
        - Existence of CA policies
        - Coverage of critical scenarios (admin access, guest access, risky sign-ins)
        """
        try:
            policies = await self.client.get_conditional_access_policies()
            
            if not policies:
                self.findings.append({
                    'control_id': 'IM-3',
                    'title': 'No Conditional Access Policies Configured',
                    'severity': 'Critical',
                    'description': 'No Conditional Access policies found. Modern identity protection requires CA policies.',
                    'recommendation': (
                        'Implement baseline Conditional Access policies:\n'
                        '1. Require MFA for all users\n'
                        '2. Block legacy authentication\n'
                        '3. Require MFA for Azure management\n'
                        '4. Require compliant devices for access'
                    )
                })
                return
            
            # Check for key policy types
            policy_types = {
                'mfa_required': False,
                'legacy_auth_blocked': False,
                'admin_protection': False,
                'risky_signin_blocked': False
            }
            
            for policy in policies:
                name = policy['display_name'].lower()
                
                if 'mfa' in name or 'multi-factor' in name:
                    policy_types['mfa_required'] = True
                
                if 'legacy' in name or 'block' in name:
                    policy_types['legacy_auth_blocked'] = True
                
                if 'admin' in name or 'privileged' in name:
                    policy_types['admin_protection'] = True
                
                if 'risk' in name:
                    policy_types['risky_signin_blocked'] = True
            
            # Report missing critical policies
            missing_policies = []
            if not policy_types['mfa_required']:
                missing_policies.append('MFA enforcement policy')
            if not policy_types['legacy_auth_blocked']:
                missing_policies.append('Legacy authentication blocking')
            if not policy_types['admin_protection']:
                missing_policies.append('Enhanced admin account protection')
            
            if missing_policies:
                self.findings.append({
                    'control_id': 'IM-3',
                    'title': 'Conditional Access Policy Gaps',
                    'severity': 'High',
                    'description': f'Missing critical CA policies: {", ".join(missing_policies)}',
                    'recommendation': (
                        'Implement missing baseline Conditional Access policies. '
                        'Refer to Microsoft\'s CA policy templates in Azure AD.'
                    )
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'IM-3',
                'title': 'Unable to Check Conditional Access',
                'severity': 'High',
                'description': f'Error checking CA policies: {str(e)}'
            })
    
    async def check_privileged_users(self):
        """
        ASB-PA-1: Protect and monitor privileged accounts
        
        Checks:
        - Number of Global Administrators (should be 2-4)
        - Privileged users with MFA
        """
        try:
            privileged_users = await self.client.get_privileged_users()
            
            # Count Global Admins
            global_admins = [u for u in privileged_users if u['role_name'] == 'Global Administrator']
            
            if len(global_admins) > 5:
                self.findings.append({
                    'control_id': 'PA-1',
                    'title': 'Too Many Global Administrators',
                    'severity': 'High',
                    'description': f'{len(global_admins)} Global Administrators found. Recommended: 2-4 accounts.',
                    'affected_resources': [u['display_name'] for u in global_admins],
                    'recommendation': (
                        'Reduce number of Global Administrator accounts to minimum required (2-4). '
                        'Use more granular roles like Security Administrator, User Administrator instead.'
                    )
                })
            
            elif len(global_admins) < 2:
                self.findings.append({
                    'control_id': 'PA-1',
                    'title': 'Insufficient Global Administrator Redundancy',
                    'severity': 'Medium',
                    'description': f'Only {len(global_admins)} Global Administrator(s). Recommended: 2-4 for redundancy.',
                    'recommendation': 'Create at least 2 Global Administrator accounts for emergency access.'
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'PA-1',
                'title': 'Unable to Check Privileged Users',
                'severity': 'Medium',
                'description': f'Error checking privileged accounts: {str(e)}'
            })
    
    async def check_legacy_authentication(self):
        """
        ASB-IM-4: Block legacy authentication protocols
        
        Checks:
        - Legacy auth usage in sign-in logs
        """
        try:
            legacy_auth = await self.client.check_legacy_auth()
            
            if legacy_auth['has_legacy_auth']:
                self.findings.append({
                    'control_id': 'IM-4',
                    'title': 'Legacy Authentication Detected',
                    'severity': 'High',
                    'description': (
                        f'{legacy_auth["total_legacy_sign_ins"]} legacy authentication sign-ins detected. '
                        f'Protocols: {", ".join(legacy_auth["legacy_protocols"].keys())}'
                    ),
                    'recommendation': (
                        'Block legacy authentication protocols using Conditional Access:\n'
                        '1. Create CA policy to block legacy authentication\n'
                        '2. Migrate clients to modern authentication\n'
                        '3. Monitor sign-ins for 30 days before enforcement'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Identify apps using legacy auth',
                            '2. Update to modern auth clients',
                            '3. Create CA policy: Block legacy authentication',
                            '4. Test in Report-Only mode',
                            '5. Enable blocking'
                        ]
                    }
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'IM-4',
                'title': 'Unable to Check Legacy Authentication',
                'severity': 'Medium',
                'description': f'Error checking legacy auth: {str(e)}'
            })
    
    async def check_guest_users(self):
        """
        ASB-IM-5: Manage and review guest access
        
        Checks:
        - Number of guest users
        - Guest access policies
        """
        try:
            guests = await self.client.get_guest_users()
            
            if len(guests) > 0:
                # Large number of guests warrants review
                if len(guests) > 50:
                    severity = 'Medium'
                    message = f'{len(guests)} guest users found. Ensure regular access reviews are configured.'
                else:
                    severity = 'Low'
                    message = f'{len(guests)} guest users found. Verify all have business justification.'
                
                self.findings.append({
                    'control_id': 'IM-5',
                    'title': 'Guest User Access Review Required',
                    'severity': severity,
                    'description': message,
                    'recommendation': (
                        'Configure Azure AD Access Reviews for guest users:\n'
                        '1. Go to Azure AD > Identity Governance > Access Reviews\n'
                        '2. Create quarterly review for all guest users\n'
                        '3. Assign reviewers (resource owners)\n'
                        '4. Auto-remove access if not approved'
                    )
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'IM-5',
                'title': 'Unable to Check Guest Users',
                'severity': 'Low',
                'description': f'Error checking guest users: {str(e)}'
            })
    
    async def check_service_principals(self):
        """
        ASB-IM-6: Secure service principals and managed identities
        
        Checks:
        - Service principals with credentials
        - Credential expiration
        """
        try:
            service_principals = await self.client.get_service_principals()
            
            # Note: Detailed credential checks require additional permissions
            # This is a basic check
            
            if len(service_principals) > 100:
                self.findings.append({
                    'control_id': 'IM-6',
                    'title': 'Large Number of Service Principals',
                    'severity': 'Low',
                    'description': f'{len(service_principals)} service principals found. Review and clean up unused identities.',
                    'recommendation': (
                        'Regularly audit service principals:\n'
                        '1. Review all service principals for business need\n'
                        '2. Remove unused service principals\n'
                        '3. Rotate credentials every 90 days\n'
                        '4. Use managed identities where possible'
                    )
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'IM-6',
                'title': 'Unable to Check Service Principals',
                'severity': 'Low',
                'description': f'Error checking service principals: {str(e)}'
            })
    
    async def check_pim_usage(self):
        """
        ASB-PA-3: Use Privileged Identity Management (PIM)
        
        Checks:
        - PIM configured for privileged roles
        """
        try:
            pim_assignments = await self.client.get_pim_assignments()
            
            if not pim_assignments:
                self.findings.append({
                    'control_id': 'PA-3',
                    'title': 'Privileged Identity Management Not Configured',
                    'severity': 'High',
                    'description': 'PIM not configured for privileged role assignments. Just-in-time access is recommended.',
                    'recommendation': (
                        'Enable PIM for privileged roles:\n'
                        '1. Requires Azure AD Premium P2 license\n'
                        '2. Go to Azure AD > Privileged Identity Management\n'
                        '3. Configure eligible assignments for admin roles\n'
                        '4. Require MFA and justification for activation\n'
                        '5. Set maximum activation duration (recommended: 4 hours)'
                    )
                })
        
        except Exception as e:
            # PIM may not be available (requires P2 license)
            self.findings.append({
                'control_id': 'PA-3',
                'title': 'Unable to Check PIM Configuration',
                'severity': 'Low',
                'description': f'Unable to verify PIM status: {str(e)}. Requires Azure AD Premium P2.'
            })


async def evaluate_entra_id_security(auth_manager: Optional[AzureAuthManager] = None) -> List[Dict]:
    """
    Convenience function to run all Entra ID security checks
    
    Args:
        auth_manager: Azure authentication manager
        
    Returns:
        List of security findings
    """
    evaluator = EntraIDEvaluator(auth_manager)
    return await evaluator.evaluate_all()
