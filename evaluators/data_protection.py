"""
Data Protection Evaluator

Evaluates Azure data protection controls including:
- Encryption at rest and in transit
- Storage account security
- Database encryption (TDE)
- Key Vault configuration
- Data classification
- Backup and retention
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure_sdk.resource_graph import ResourceGraphClient
from azure_sdk.auth import AzureAuthManager


class DataProtectionEvaluator:
    """Evaluate Azure data protection and encryption controls"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Data Protection evaluator
        
        Args:
            subscription_id: Azure subscription ID
            auth_manager: Azure authentication manager
        """
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        self.client = ResourceGraphClient(auth_manager=self.auth_manager)
        self.findings = []
    
    async def evaluate_all(self) -> List[Dict]:
        """
        Run all data protection security checks
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        # Run all checks
        await self.check_storage_encryption()
        await self.check_storage_https()
        await self.check_sql_encryption()
        await self.check_keyvault_configuration()
        await self.check_disk_encryption()
        await self.check_backup_configuration()
        await self.check_data_classification()
        
        return self.findings
    
    async def check_storage_encryption(self):
        """
        ASB-DP-1: Encryption at rest for storage accounts
        
        Checks:
        - Storage accounts without encryption
        - Customer-managed keys vs Microsoft-managed
        - Infrastructure encryption
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.storage/storageaccounts'
            | extend encryption = properties.encryption
            | extend encryptionEnabled = encryption.services.blob.enabled
            | extend keySource = encryption.keySource
            | extend infrastructureEncryption = encryption.requireInfrastructureEncryption
            | project id, name, location, encryptionEnabled, keySource, infrastructureEncryption
            """
            
            storage_accounts = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for unencrypted accounts
            unencrypted = [s for s in storage_accounts if not s.get('encryptionEnabled', True)]
            
            if unencrypted:
                self.findings.append({
                    'control_id': 'DP-1',
                    'title': 'Storage Accounts Without Encryption',
                    'severity': 'Critical',
                    'description': f'{len(unencrypted)} storage accounts do not have encryption enabled',
                    'affected_resources': [s['id'] for s in unencrypted],
                    'recommendation': (
                        'Enable encryption for all storage accounts. '
                        'Azure Storage Service Encryption (SSE) should be enabled by default.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Storage Account > Security + networking > Encryption',
                            '2. Ensure encryption is enabled',
                            '3. Consider using customer-managed keys for enhanced control',
                            '4. Enable infrastructure encryption for double encryption'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable encryption for storage account (should be default)
az storage account update \\
    --name [STORAGE_ACCOUNT_NAME] \\
    --resource-group [RG_NAME] \\
    --encryption-services blob file

# Enable infrastructure encryption (must be set at creation)
az storage account create \\
    --name [NEW_STORAGE_ACCOUNT] \\
    --resource-group [RG_NAME] \\
    --require-infrastructure-encryption
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/storage/common/storage-service-encryption',
                        'https://learn.microsoft.com/azure/storage/common/infrastructure-encryption-enable'
                    ]
                })
            
            # Check for Microsoft-managed keys (recommend customer-managed)
            microsoft_keys = [s for s in storage_accounts if s.get('keySource') == 'Microsoft.Storage']
            
            if len(microsoft_keys) > 0:
                self.findings.append({
                    'control_id': 'DP-1',
                    'title': 'Storage Accounts Using Microsoft-Managed Keys',
                    'severity': 'Low',
                    'description': f'{len(microsoft_keys)} storage accounts use Microsoft-managed keys (recommend CMK for sensitive data)',
                    'affected_resources': [s['id'] for s in microsoft_keys[:10]],
                    'recommendation': (
                        'Consider using customer-managed keys (CMK) for sensitive storage accounts. '
                        'CMKs provide enhanced control and key rotation capabilities.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create Azure Key Vault',
                            '2. Generate or import encryption key',
                            '3. Grant storage account access to Key Vault',
                            '4. Configure storage account to use CMK',
                            '5. Monitor key rotation'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create Key Vault
az keyvault create \\
    --name [KV_NAME] \\
    --resource-group [RG_NAME] \\
    --enable-purge-protection

# Create encryption key
az keyvault key create \\
    --vault-name [KV_NAME] \\
    --name storage-encryption-key \\
    --kty RSA

# Configure storage account CMK
az storage account update \\
    --name [STORAGE_ACCOUNT_NAME] \\
    --resource-group [RG_NAME] \\
    --encryption-key-vault https://[KV_NAME].vault.azure.net \\
    --encryption-key-name storage-encryption-key
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/storage/common/customer-managed-keys-overview'
                    ]
                })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'DP-1',
                'title': 'Error Checking Storage Encryption',
                'severity': 'Medium',
                'description': f'Failed to evaluate storage encryption: {str(e)}'
            })
    
    async def check_storage_https(self):
        """
        ASB-DP-2: Encryption in transit
        
        Checks:
        - HTTPS-only enforcement
        - Minimum TLS version
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.storage/storageaccounts'
            | extend httpsOnly = properties.supportsHttpsTrafficOnly
            | extend minTlsVersion = properties.minimumTlsVersion
            | project id, name, httpsOnly, minTlsVersion
            """
            
            storage_accounts = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for HTTP allowed
            http_allowed = [s for s in storage_accounts if not s.get('httpsOnly', False)]
            
            if http_allowed:
                self.findings.append({
                    'control_id': 'DP-2',
                    'title': 'Storage Accounts Allow HTTP Traffic',
                    'severity': 'Critical',
                    'description': f'{len(http_allowed)} storage accounts allow unencrypted HTTP traffic',
                    'affected_resources': [s['id'] for s in http_allowed],
                    'recommendation': 'Enable HTTPS-only for all storage accounts to encrypt data in transit',
                    'remediation': {
                        'steps': [
                            '1. Go to Storage Account > Configuration',
                            '2. Set "Secure transfer required" to Enabled',
                            '3. Set minimum TLS version to 1.2',
                            '4. Test application connectivity'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable HTTPS-only and TLS 1.2
az storage account update \\
    --name [STORAGE_ACCOUNT_NAME] \\
    --resource-group [RG_NAME] \\
    --https-only true \\
    --min-tls-version TLS1_2
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer'
                    ]
                })
            
            # Check TLS version
            old_tls = [s for s in storage_accounts 
                      if s.get('minTlsVersion') and s['minTlsVersion'] < 'TLS1_2']
            
            if old_tls:
                self.findings.append({
                    'control_id': 'DP-2',
                    'title': 'Storage Accounts Using Old TLS Versions',
                    'severity': 'High',
                    'description': f'{len(old_tls)} storage accounts allow TLS < 1.2',
                    'affected_resources': [s['id'] for s in old_tls],
                    'recommendation': 'Upgrade minimum TLS version to 1.2 for all storage accounts',
                    'remediation': {
                        'steps': [
                            '1. Review client applications for TLS 1.2 support',
                            '2. Update storage account minimum TLS to 1.2',
                            '3. Test connectivity',
                            '4. Monitor for connection errors'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Set minimum TLS to 1.2
az storage account update \\
    --name [STORAGE_ACCOUNT_NAME] \\
    --resource-group [RG_NAME] \\
    --min-tls-version TLS1_2
'''
                    }
                })
        
        except Exception as e:
            pass
    
    async def check_sql_encryption(self):
        """
        ASB-DP-3: Database encryption (TDE)
        
        Checks:
        - Transparent Data Encryption (TDE)
        - SQL Server encryption
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.sql/servers/databases'
            | where name !in ('master', 'model', 'msdb', 'tempdb')
            | extend tdeEnabled = properties.transparentDataEncryption
            | project id, name, serverName = split(id, '/')[8], tdeEnabled
            """
            
            databases = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # TDE should be enabled by default, but check for any disabled
            tde_disabled = [db for db in databases if not db.get('tdeEnabled')]
            
            if tde_disabled:
                self.findings.append({
                    'control_id': 'DP-3',
                    'title': 'SQL Databases Without TDE',
                    'severity': 'Critical',
                    'description': f'{len(tde_disabled)} SQL databases do not have Transparent Data Encryption enabled',
                    'affected_resources': [db['id'] for db in tde_disabled],
                    'recommendation': 'Enable TDE for all SQL databases to encrypt data at rest',
                    'remediation': {
                        'steps': [
                            '1. Go to SQL Database > Security > Data encryption',
                            '2. Enable Transparent Data Encryption',
                            '3. Consider using customer-managed TDE protector',
                            '4. Monitor encryption progress'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable TDE (should be default)
az sql db tde set \\
    --server [SERVER_NAME] \\
    --database [DB_NAME] \\
    --resource-group [RG_NAME] \\
    --status Enabled

# Use customer-managed TDE protector
az sql server tde-key set \\
    --server [SERVER_NAME] \\
    --resource-group [RG_NAME] \\
    --kid https://[KV_NAME].vault.azure.net/keys/[KEY_NAME]/[VERSION]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview',
                        'https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-byok-overview'
                    ]
                })
            
            # Check for databases (recommend CMK for production)
            if len(databases) > 5:
                self.findings.append({
                    'control_id': 'DP-3',
                    'title': 'Consider Customer-Managed TDE Keys',
                    'severity': 'Low',
                    'description': f'{len(databases)} SQL databases found - consider CMK for sensitive databases',
                    'recommendation': (
                        'Use customer-managed TDE protector keys for production databases. '
                        'Provides enhanced control and compliance capabilities.'
                    ),
                    'references': [
                        'https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-byok-overview'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_keyvault_configuration(self):
        """
        ASB-DP-4: Key Vault security
        
        Checks:
        - Purge protection
        - Soft delete
        - Network access
        - RBAC vs access policies
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.keyvault/vaults'
            | extend softDelete = properties.enableSoftDelete
            | extend purgeProtection = properties.enablePurgeProtection
            | extend rbacEnabled = properties.enableRbacAuthorization
            | extend networkAcls = properties.networkAcls
            | project id, name, softDelete, purgeProtection, rbacEnabled, networkAcls
            """
            
            keyvaults = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check purge protection
            no_purge = [kv for kv in keyvaults if not kv.get('purgeProtection', False)]
            
            if no_purge:
                self.findings.append({
                    'control_id': 'DP-4',
                    'title': 'Key Vaults Without Purge Protection',
                    'severity': 'High',
                    'description': f'{len(no_purge)} Key Vaults do not have purge protection enabled',
                    'affected_resources': [kv['id'] for kv in no_purge],
                    'recommendation': (
                        'Enable purge protection to prevent permanent deletion of keys/secrets. '
                        'This is required for compliance and key recovery.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Enable soft-delete if not already enabled',
                            '2. Enable purge protection (irreversible)',
                            '3. Note: This setting cannot be disabled once enabled',
                            '4. Update deployment templates'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable purge protection (requires soft-delete)
az keyvault update \\
    --name [KV_NAME] \\
    --resource-group [RG_NAME] \\
    --enable-purge-protection true

# Create new Key Vault with protection
az keyvault create \\
    --name [KV_NAME] \\
    --resource-group [RG_NAME] \\
    --enable-soft-delete true \\
    --enable-purge-protection true
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview',
                        'https://learn.microsoft.com/azure/key-vault/general/security-features'
                    ]
                })
            
            # Check soft delete
            no_soft_delete = [kv for kv in keyvaults if not kv.get('softDelete', True)]
            
            if no_soft_delete:
                self.findings.append({
                    'control_id': 'DP-4',
                    'title': 'Key Vaults Without Soft Delete',
                    'severity': 'Critical',
                    'description': f'{len(no_soft_delete)} Key Vaults do not have soft delete enabled',
                    'affected_resources': [kv['id'] for kv in no_soft_delete],
                    'recommendation': 'Enable soft delete to allow recovery of deleted keys/secrets',
                    'remediation': {
                        'steps': [
                            '1. Enable soft-delete (default for new vaults)',
                            '2. Set retention period to 90 days',
                            '3. Test key recovery process',
                            '4. Document recovery procedures'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable soft-delete
az keyvault update \\
    --name [KV_NAME] \\
    --resource-group [RG_NAME] \\
    --enable-soft-delete true \\
    --retention-days 90
'''
                    }
                })
            
            # Recommend RBAC over access policies
            access_policy_vaults = [kv for kv in keyvaults if not kv.get('rbacEnabled', False)]
            
            if len(access_policy_vaults) > 0:
                self.findings.append({
                    'control_id': 'DP-4',
                    'title': 'Key Vaults Using Access Policies Instead of RBAC',
                    'severity': 'Low',
                    'description': f'{len(access_policy_vaults)} Key Vaults use access policies (recommend RBAC)',
                    'affected_resources': [kv['id'] for kv in access_policy_vaults[:5]],
                    'recommendation': (
                        'Migrate to Azure RBAC for Key Vault access control. '
                        'RBAC provides centralized access management and better auditing.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Document current access policy assignments',
                            '2. Enable RBAC authorization on Key Vault',
                            '3. Assign RBAC roles (Key Vault Administrator, Reader, etc.)',
                            '4. Remove access policies',
                            '5. Test access with RBAC'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable RBAC authorization
az keyvault update \\
    --name [KV_NAME] \\
    --resource-group [RG_NAME] \\
    --enable-rbac-authorization true

# Assign RBAC role
az role assignment create \\
    --role "Key Vault Secrets Officer" \\
    --assignee [USER_OR_SP_ID] \\
    --scope /subscriptions/[SUB_ID]/resourceGroups/[RG]/providers/Microsoft.KeyVault/vaults/[KV_NAME]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/key-vault/general/rbac-guide'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_disk_encryption(self):
        """
        ASB-DP-5: VM disk encryption
        
        Checks:
        - Azure Disk Encryption enabled
        - Managed disk encryption
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.compute/virtualmachines'
            | extend diskEncryption = properties.storageProfile.osDisk.encryptionSettings
            | extend managedDisk = properties.storageProfile.osDisk.managedDisk
            | project id, name, diskEncryption, managedDisk
            """
            
            vms = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for unencrypted VMs (note: managed disks have encryption at rest by default)
            unencrypted_vms = [vm for vm in vms 
                              if not vm.get('diskEncryption') and not vm.get('managedDisk')]
            
            if unencrypted_vms:
                self.findings.append({
                    'control_id': 'DP-5',
                    'title': 'VMs Without Disk Encryption',
                    'severity': 'High',
                    'description': f'{len(unencrypted_vms)} VMs may not have disk encryption enabled',
                    'affected_resources': [vm['id'] for vm in unencrypted_vms],
                    'recommendation': (
                        'Enable Azure Disk Encryption for VMs. '
                        'Use managed disks with encryption at rest.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create Key Vault for disk encryption keys',
                            '2. Enable Azure Disk Encryption on VM',
                            '3. Verify encryption status',
                            '4. Use managed disks for automatic encryption'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Enable Azure Disk Encryption
az vm encryption enable \\
    --resource-group [RG_NAME] \\
    --name [VM_NAME] \\
    --disk-encryption-keyvault [KV_NAME] \\
    --volume-type ALL

# Check encryption status
az vm encryption show \\
    --resource-group [RG_NAME] \\
    --name [VM_NAME]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview',
                        'https://learn.microsoft.com/azure/virtual-machines/linux/disk-encryption-overview'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_backup_configuration(self):
        """
        ASB-DP-6: Backup and retention
        
        Checks:
        - Backup enabled for critical resources
        - Retention policies
        """
        try:
            # Check Recovery Services vaults
            query = """
            Resources
            | where type == 'microsoft.recoveryservices/vaults'
            | project id, name, location
            """
            
            vaults = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            if len(vaults) == 0:
                self.findings.append({
                    'control_id': 'DP-6',
                    'title': 'No Backup Vaults Configured',
                    'severity': 'High',
                    'description': 'No Recovery Services vaults found - backup may not be configured',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Configure Azure Backup for critical resources. '
                        'Create Recovery Services vault and enable backup for VMs, databases, and file shares.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create Recovery Services vault',
                            '2. Configure backup policies (retention, frequency)',
                            '3. Enable backup for VMs and databases',
                            '4. Test restore procedures',
                            '5. Monitor backup jobs'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create Recovery Services vault
az backup vault create \\
    --resource-group [RG_NAME] \\
    --name [VAULT_NAME] \\
    --location [LOCATION]

# Enable backup for VM
az backup protection enable-for-vm \\
    --resource-group [RG_NAME] \\
    --vault-name [VAULT_NAME] \\
    --vm [VM_NAME] \\
    --policy-name DefaultPolicy
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/backup/backup-overview',
                        'https://learn.microsoft.com/azure/backup/backup-azure-vms-first-look-arm'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_data_classification(self):
        """
        ASB-DP-7: Data classification and labeling
        
        Checks:
        - Microsoft Purview integration
        - Data sensitivity labels
        """
        try:
            # Check for Microsoft Purview accounts
            query = """
            Resources
            | where type == 'microsoft.purview/accounts'
            | project id, name
            """
            
            purview = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            if len(purview) == 0:
                self.findings.append({
                    'control_id': 'DP-7',
                    'title': 'No Data Classification Solution',
                    'severity': 'Medium',
                    'description': 'Microsoft Purview not configured - data classification may be missing',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Consider deploying Microsoft Purview for data discovery, classification, and governance. '
                        'Required for compliance with data protection regulations.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create Microsoft Purview account',
                            '2. Register data sources',
                            '3. Configure classification rules',
                            '4. Apply sensitivity labels',
                            '5. Monitor compliance dashboard'
                        ]
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/purview/overview',
                        'https://learn.microsoft.com/azure/purview/create-catalog-portal'
                    ]
                })
        
        except Exception as e:
            pass


def run_evaluation(subscription_id: str) -> List[Dict]:
    """
    Convenience function to run Data Protection evaluation
    
    Args:
        subscription_id: Azure subscription ID
        
    Returns:
        List of findings
    """
    evaluator = DataProtectionEvaluator(subscription_id)
    return asyncio.run(evaluator.evaluate_all())
