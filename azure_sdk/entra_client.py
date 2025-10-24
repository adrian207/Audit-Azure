"""
Microsoft Entra ID (Azure AD) Client

Query and manage Microsoft Entra ID (formerly Azure Active Directory) security settings.
"""

from typing import List, Dict, Optional, Any
# msgraph SDK types may not be available to the static analyzer in this environment
from msgraph import GraphServiceClient  # type: ignore[import]
from msgraph.generated.users.users_request_builder import UsersRequestBuilder  # type: ignore[import]
from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder  # type: ignore[import]
from azure.identity import ClientSecretCredential  # type: ignore[import]
from .auth import AzureAuthManager


class EntraClient:
    """Microsoft Entra ID operations"""
    # Treat the underlying Graph client as Any to avoid attribute/type noise
    graph_client: Any
    
    def __init__(self, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Entra ID client
        
        Args:
            auth_manager: Authentication manager
        """
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        
        # Microsoft Graph requires specific credential
        # Ensure credential values are present and typed as str for downstream SDKs
        tenant_id = self.auth_manager.tenant_id or ''
        client_id = self.auth_manager.client_id or ''
        client_secret = self.auth_manager.client_secret or ''

        if not (tenant_id and client_id and client_secret):
            raise ValueError("EntraClient requires tenant_id, client_id and client_secret to be set in the auth manager")

        credential = ClientSecretCredential(
            tenant_id=str(tenant_id),
            client_id=str(client_id),
            client_secret=str(client_secret)
        )
        
        # GraphServiceClient can expose many dynamic attributes; keep as Any for static analysis
        self.graph_client = GraphServiceClient(
            credentials=credential,
            scopes=['https://graph.microsoft.com/.default']
        )  # type: ignore[assignment]
    
    async def get_users(self, filter_query: Optional[str] = None) -> List[Dict]:
        """
        Get users from Entra ID
        
        Args:
            filter_query: OData filter query
            
        Returns:
            List of users
        """
        request = self.graph_client.users.get()
        if filter_query:
            request.query_parameters.filter = filter_query
        
        users = await request
        
        return [
            {
                'id': user.id,
                'user_principal_name': user.user_principal_name,
                'display_name': user.display_name,
                'mail': user.mail,
                'job_title': user.job_title,
                'account_enabled': user.account_enabled,
                'user_type': user.user_type
            }
            for user in users.value
        ]
    
    async def get_mfa_status(self) -> List[Dict]:
        """
        Get MFA registration status for all users
        
        Returns:
            List of users with MFA status
        """
        # Query authentication methods
        users = await self.get_users()
        mfa_status = []
        
        for user in users:
            methods = await self.graph_client.users.by_user_id(user['id']).authentication.methods.get()
            
            has_mfa = any(
                method.odata_type in [
                    '#microsoft.graph.phoneAuthenticationMethod',
                    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                    '#microsoft.graph.fido2AuthenticationMethod'
                ]
                for method in methods.value
            )
            
            mfa_status.append({
                'user_id': user['id'],
                'user_principal_name': user['user_principal_name'],
                'display_name': user['display_name'],
                'mfa_enabled': has_mfa,
                'method_count': len(methods.value)
            })
        
        return mfa_status
    
    async def get_conditional_access_policies(self) -> List[Dict]:
        """
        Get Conditional Access policies
        
        Returns:
            List of CA policies
        """
        policies = await self.graph_client.identity.conditional_access.policies.get()
        
        return [
            {
                'id': policy.id,
                'display_name': policy.display_name,
                'state': policy.state,
                'conditions': {
                    'users': policy.conditions.users,
                    'applications': policy.conditions.applications,
                    'locations': policy.conditions.locations,
                    'platforms': policy.conditions.platforms,
                    'sign_in_risk_levels': policy.conditions.sign_in_risk_levels,
                    'user_risk_levels': policy.conditions.user_risk_levels
                },
                'grant_controls': policy.grant_controls,
                'session_controls': policy.session_controls
            }
            for policy in policies.value
        ]
    
    async def get_privileged_users(self) -> List[Dict]:
        """
        Get users with privileged roles
        
        Returns:
            List of privileged users
        """
        # Get directory role assignments
        role_assignments = await self.graph_client.directory_roles.get()
        
        privileged_roles = [
            'Global Administrator',
            'Privileged Role Administrator',
            'Security Administrator',
            'Application Administrator',
            'Cloud Application Administrator'
        ]
        
        privileged_users = []
        
        for role in role_assignments.value:
            if role.display_name in privileged_roles:
                members = await self.graph_client.directory_roles.by_directory_role_id(role.id).members.get()
                
                for member in members.value:
                    privileged_users.append({
                        'user_id': member.id,
                        'display_name': getattr(member, 'display_name', 'N/A'),
                        'role_name': role.display_name,
                        'role_id': role.id
                    })
        
        return privileged_users
    
    async def get_service_principals(self) -> List[Dict]:
        """
        Get service principals (applications)
        
        Returns:
            List of service principals
        """
        service_principals = await self.graph_client.service_principals.get()
        
        return [
            {
                'id': sp.id,
                'app_id': sp.app_id,
                'display_name': sp.display_name,
                'account_enabled': sp.account_enabled,
                'app_roles': sp.app_roles,
                'service_principal_type': sp.service_principal_type,
                'sign_in_audience': sp.sign_in_audience
            }
            for sp in service_principals.value
        ]
    
    async def get_guest_users(self) -> List[Dict]:
        """
        Get guest users in directory
        
        Returns:
            List of guest users
        """
        guests = await self.get_users(filter_query="userType eq 'Guest'")
        return guests
    
    async def check_legacy_auth(self) -> Dict[str, Any]:
        """
        Check for legacy authentication usage
        
        Returns:
            Legacy auth summary
        """
        # Query sign-in logs for legacy auth
        sign_ins = await self.graph_client.audit_logs.sign_ins.get(
            query_parameters={
                'filter': "clientAppUsed ne 'Modern' and createdDateTime ge 2024-01-01"
            }
        )
        
        legacy_usage = {}
        for sign_in in sign_ins.value:
            app = sign_in.client_app_used
            if app not in legacy_usage:
                legacy_usage[app] = 0
            legacy_usage[app] += 1
        
        return {
            'has_legacy_auth': len(legacy_usage) > 0,
            'legacy_protocols': legacy_usage,
            'total_legacy_sign_ins': sum(legacy_usage.values())
        }
    
    async def get_pim_assignments(self) -> List[Dict]:
        """
        Get Privileged Identity Management role assignments
        
        Returns:
            List of PIM assignments
        """
        # Query PIM assignments
        assignments = await self.graph_client.privileged_access.azure_resources.role_assignments.get()
        
        return [
            {
                'id': assignment.id,
                'resource_id': assignment.resource_id,
                'role_definition_id': assignment.role_definition_id,
                'subject_id': assignment.subject_id,
                'assignment_state': assignment.assignment_state,
                'start_date_time': assignment.start_date_time,
                'end_date_time': assignment.end_date_time
            }
            for assignment in assignments.value
        ]
