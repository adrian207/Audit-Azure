"""
Azure Authentication Manager

Handles authentication to Azure services using various credential types.
Supports: DefaultAzureCredential, Service Principal, Managed Identity, CLI credentials.
"""

import os
from typing import Optional
from azure.identity import (
    DefaultAzureCredential,
    ClientSecretCredential,
    ManagedIdentityCredential,
    AzureCliCredential,
    ChainedTokenCredential
)
from azure.core.credentials import TokenCredential


class AzureAuthManager:
    """Manage Azure authentication"""
    
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        use_cli: bool = True,
        use_managed_identity: bool = False
    ):
        """
        Initialize authentication manager
        
        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            client_secret: Service principal client secret
            use_cli: Use Azure CLI credentials
            use_managed_identity: Use managed identity
        """
        self.tenant_id = tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.use_cli = use_cli
        self.use_managed_identity = use_managed_identity
        self._credential: Optional[TokenCredential] = None
    
    def get_credential(self) -> TokenCredential:
        """
        Get Azure credential using best available method
        
        Returns:
            TokenCredential for Azure SDK clients
        """
        if self._credential:
            return self._credential
        
        credentials = []
        
        # 1. Try Service Principal if configured
        if self.tenant_id and self.client_id and self.client_secret:
            credentials.append(
                ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            )
        
        # 2. Try Managed Identity if enabled
        if self.use_managed_identity:
            credentials.append(ManagedIdentityCredential())
        
        # 3. Try Azure CLI credentials if enabled
        if self.use_cli:
            credentials.append(AzureCliCredential())
        
        # Use ChainedTokenCredential to try methods in order
        if credentials:
            self._credential = ChainedTokenCredential(*credentials)
        else:
            # Fallback to DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        
        return self._credential
    
    def get_access_token(self, scope: str = "https://management.azure.com/.default") -> str:
        """
        Get access token for specific scope
        
        Args:
            scope: OAuth2 scope
            
        Returns:
            Access token string
        """
        credential = self.get_credential()
        token = credential.get_token(scope)
        return token.token
    
    @staticmethod
    def from_environment() -> 'AzureAuthManager':
        """
        Create auth manager from environment variables
        
        Environment variables:
        - AZURE_TENANT_ID
        - AZURE_CLIENT_ID
        - AZURE_CLIENT_SECRET
        - AZURE_USE_CLI (default: true)
        - AZURE_USE_MANAGED_IDENTITY (default: false)
        """
        return AzureAuthManager(
            tenant_id=os.getenv('AZURE_TENANT_ID'),
            client_id=os.getenv('AZURE_CLIENT_ID'),
            client_secret=os.getenv('AZURE_CLIENT_SECRET'),
            use_cli=os.getenv('AZURE_USE_CLI', 'true').lower() == 'true',
            use_managed_identity=os.getenv('AZURE_USE_MANAGED_IDENTITY', 'false').lower() == 'true'
        )
