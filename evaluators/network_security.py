"""
Network Security Evaluator

Evaluates Azure network security controls including:
- Network Security Groups (NSG) rules
- Azure Firewall configuration
- DDoS Protection
- Private Endpoints
- VNet peering security
- Web Application Firewall (WAF)
- Network segmentation
"""

import asyncio
from typing import List, Dict, Any, Optional
from azure_sdk.resource_graph import ResourceGraphClient, AccessDeniedError
from azure_sdk.auth import AzureAuthManager


class NetworkSecurityEvaluator:
    """Evaluate Azure network security controls"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Network Security evaluator
        
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
        Run all network security checks
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        # Run all checks
        await self.check_nsg_rules()
        await self.check_public_ips()
        await self.check_ddos_protection()
        await self.check_private_endpoints()
        await self.check_azure_firewall()
        await self.check_network_segmentation()
        await self.check_waf_deployment()
        
        return self.findings
    
    async def check_nsg_rules(self):
        """
        ASB-NS-1: Network Security Group rules
        
        Checks:
        - Overly permissive rules
        - Allow rules from Internet
        - Management port exposure (RDP, SSH)
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/networksecuritygroups'
            | extend rules = properties.securityRules
            | mvexpand rules
            | extend ruleName = rules.name
            | extend direction = rules.properties.direction
            | extend access = rules.properties.access
            | extend protocol = rules.properties.protocol
            | extend sourceAddress = rules.properties.sourceAddressPrefix
            | extend destinationPort = rules.properties.destinationPortRange
            | extend priority = rules.properties.priority
            | where direction == 'Inbound' and access == 'Allow'
            | project id, name, ruleName, sourceAddress, destinationPort, priority
            """
            
            nsg_rules = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for rules allowing traffic from Internet
            internet_rules = [
                rule for rule in nsg_rules
                if rule.get('sourceAddress') in ['*', 'Internet', '0.0.0.0/0', 'Any']
            ]
            
            if internet_rules:
                # Check for dangerous ports
                dangerous_ports = ['22', '3389', '1433', '3306', '5432', '27017']
                dangerous_rules = [
                    rule for rule in internet_rules
                    if any(port in str(rule.get('destinationPort', '')) for port in dangerous_ports)
                ]
                
                if dangerous_rules:
                    self.findings.append({
                        'control_id': 'NS-1',
                        'title': 'NSG Rules Allow Dangerous Ports from Internet',
                        'severity': 'Critical',
                        'description': f'{len(dangerous_rules)} NSG rules allow management/database ports from Internet',
                        'affected_resources': [f"{rule['id']}/{rule['ruleName']}" for rule in dangerous_rules[:5]],
                        'recommendation': (
                            'Remove or restrict NSG rules allowing RDP (3389), SSH (22), and database ports from Internet. '
                            'Use Azure Bastion, VPN, or Private Endpoints instead.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Review each NSG rule allowing Internet access',
                                '2. Change source to specific IP ranges or Service Tags',
                                '3. Deploy Azure Bastion for secure RDP/SSH access',
                                '4. Use Private Endpoints for database access',
                                '5. Delete overly permissive rules'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Remove dangerous NSG rule
az network nsg rule delete \\
    --resource-group [RG_NAME] \\
    --nsg-name [NSG_NAME] \\
    --name [RULE_NAME]

# Update rule to restrict source
az network nsg rule update \\
    --resource-group [RG_NAME] \\
    --nsg-name [NSG_NAME] \\
    --name [RULE_NAME] \\
    --source-address-prefixes [YOUR_IP_RANGE]

# Deploy Azure Bastion
az network bastion create \\
    --resource-group [RG_NAME] \\
    --name [BASTION_NAME] \\
    --vnet-name [VNET_NAME] \\
    --public-ip-address [PIP_NAME]
'''
                        },
                        'references': [
                            'https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview',
                            'https://learn.microsoft.com/azure/bastion/bastion-overview'
                        ]
                    })
                
                # Check for * rules (allow all)
                allow_all = [
                    rule for rule in internet_rules
                    if rule.get('destinationPort') in ['*', '0-65535']
                ]
                
                if allow_all:
                    self.findings.append({
                        'control_id': 'NS-1',
                        'title': 'NSG Rules Allow All Ports from Internet',
                        'severity': 'Critical',
                        'description': f'{len(allow_all)} NSG rules allow all ports from Internet',
                        'affected_resources': [f"{rule['id']}/{rule['ruleName']}" for rule in allow_all],
                        'recommendation': (
                            'Never use * for destination ports in inbound rules from Internet. '
                            'Specify exact ports required and use least privilege principle.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Identify required ports for the application',
                                '2. Delete the allow-all rule',
                                '3. Create specific rules for required ports only',
                                '4. Test application connectivity',
                                '5. Monitor NSG flow logs'
                            ]
                        }
                    })
        
        except AccessDeniedError as e:
            # Provide actionable remediation for RBAC issues
            self.findings.append({
                'control_id': 'NS-1',
                'title': 'Insufficient permissions to query Azure Resource Graph',
                'severity': 'High',
                'description': (
                    'The service principal could not query Resource Graph (AccessDenied). '
                    'Assign Reader at the subscription scope and ensure the Microsoft.ResourceGraph '
                    'provider is registered.'
                ),
                'affected_resources': [f"/subscriptions/{self.subscription_id}"],
                'remediation': {
                    'steps': [
                        '1) Assign Reader role to the service principal at the subscription scope:',
                        f"   az role assignment create --assignee {self.auth_manager.client_id} --role Reader --scope /subscriptions/{self.subscription_id}",
                        '2) Register the Resource Graph provider (once per tenant):',
                        '   az provider register --namespace Microsoft.ResourceGraph --wait',
                        '3) (Optional) Ensure Microsoft.Network provider is registered:',
                        '   az provider register --namespace Microsoft.Network --wait',
                        '4) Re-run the evaluation.'
                    ]
                }
            })
        except Exception as e:
            self.findings.append({
                'control_id': 'NS-1',
                'title': 'Error Checking NSG Rules',
                'severity': 'Medium',
                'description': f'Failed to evaluate NSG rules: {str(e)}'
            })
    
    async def check_public_ips(self):
        """
        ASB-NS-2: Minimize public IP exposure
        
        Checks:
        - Public IPs attached to VMs
        - Public IPs on databases
        - Unused public IPs
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/publicipaddresses'
            | extend attached = isnotnull(properties.ipConfiguration)
            | project id, name, attached, ipAddress = properties.ipAddress
            """
            
            public_ips = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for VMs with public IPs
            vm_query = """
            Resources
            | where type == 'microsoft.compute/virtualmachines'
            | extend nics = properties.networkProfile.networkInterfaces
            | mvexpand nics
            | extend nicId = tostring(nics.id)
            | join kind=inner (
                Resources
                | where type == 'microsoft.network/networkinterfaces'
                | extend ipConfigs = properties.ipConfigurations
                | mvexpand ipConfigs
                | extend publicIp = ipConfigs.properties.publicIPAddress
                | where isnotnull(publicIp)
                | project nicId = id, publicIpId = tostring(publicIp.id)
            ) on $left.nicId == $right.nicId
            | project vmId = id, vmName = name, publicIpId
            """
            
            vms_with_public_ip = self.client.query_resources(
                vm_query,
                subscriptions=[self.subscription_id]
            )
            
            if vms_with_public_ip:
                self.findings.append({
                    'control_id': 'NS-2',
                    'title': 'VMs with Public IP Addresses',
                    'severity': 'High',
                    'description': f'{len(vms_with_public_ip)} VMs have public IP addresses directly attached',
                    'affected_resources': [vm['vmId'] for vm in vms_with_public_ip[:10]],
                    'recommendation': (
                        'Remove public IPs from VMs. Use Azure Bastion, Load Balancer, '
                        'Application Gateway, or VPN Gateway for external access.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Deploy Azure Bastion for management access',
                            '2. Use Load Balancer or Application Gateway for application traffic',
                            '3. Remove public IP from VM NIC',
                            '4. Verify connectivity through new access method',
                            '5. Delete unused public IPs'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Remove public IP from NIC
az network nic ip-config update \\
    --resource-group [RG_NAME] \\
    --nic-name [NIC_NAME] \\
    --name [IP_CONFIG_NAME] \\
    --remove PublicIpAddress

# Delete public IP
az network public-ip delete \\
    --resource-group [RG_NAME] \\
    --name [PIP_NAME]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/bastion/bastion-overview',
                        'https://learn.microsoft.com/azure/load-balancer/load-balancer-overview'
                    ]
                })
            
            # Check for unattached public IPs
            unattached = [pip for pip in public_ips if not pip.get('attached')]
            
            if len(unattached) > 5:
                self.findings.append({
                    'control_id': 'NS-2',
                    'title': 'Unused Public IP Addresses',
                    'severity': 'Low',
                    'description': f'{len(unattached)} public IPs are not attached to any resource (cost optimization)',
                    'affected_resources': [pip['id'] for pip in unattached[:10]],
                    'recommendation': 'Delete unused public IP addresses to reduce costs and attack surface',
                    'remediation': {
                        'steps': [
                            '1. Verify public IPs are truly unused',
                            '2. Document IP addresses if needed for records',
                            '3. Delete unused public IPs',
                            '4. Review cost savings'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# List unattached public IPs
az network public-ip list --query "[?ipConfiguration==null].{Name:name, RG:resourceGroup}" --output table

# Delete unattached public IP
az network public-ip delete --resource-group [RG_NAME] --name [PIP_NAME]
'''
                    }
                })
        
        except Exception as e:
            pass
    
    async def check_ddos_protection(self):
        """
        ASB-NS-3: DDoS Protection
        
        Checks:
        - DDoS Protection Standard enabled
        - VNets without DDoS protection
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/virtualnetworks'
            | extend ddosProtection = properties.enableDdosProtection
            | extend ddosPlan = properties.ddosProtectionPlan
            | project id, name, ddosProtection, ddosPlan
            """
            
            vnets = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for VNets without DDoS Protection
            no_ddos = [vnet for vnet in vnets if not vnet.get('ddosProtection', False)]
            
            if no_ddos and len(vnets) > 0:
                severity = 'Critical' if len(vnets) > 5 else 'High'
                
                self.findings.append({
                    'control_id': 'NS-3',
                    'title': 'VNets Without DDoS Protection',
                    'severity': severity,
                    'description': f'{len(no_ddos)} of {len(vnets)} VNets do not have DDoS Protection enabled',
                    'affected_resources': [vnet['id'] for vnet in no_ddos[:10]],
                    'recommendation': (
                        'Enable Azure DDoS Protection Standard for production VNets. '
                        'Provides advanced DDoS mitigation, monitoring, and attack analytics.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create DDoS Protection Plan',
                            '2. Associate plan with VNets',
                            '3. Configure DDoS alerts',
                            '4. Review DDoS metrics and logs',
                            '5. Test DDoS simulation'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create DDoS Protection Plan
az network ddos-protection create \\
    --resource-group [RG_NAME] \\
    --name [DDOS_PLAN_NAME]

# Enable DDoS on VNet
az network vnet update \\
    --resource-group [RG_NAME] \\
    --name [VNET_NAME] \\
    --ddos-protection true \\
    --ddos-protection-plan [DDOS_PLAN_ID]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview',
                        'https://learn.microsoft.com/azure/ddos-protection/manage-ddos-protection'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_private_endpoints(self):
        """
        ASB-NS-4: Private Endpoints for PaaS services
        
        Checks:
        - Storage accounts without private endpoints
        - SQL databases without private endpoints
        - Key Vaults without private endpoints
        """
        try:
            # Check for private endpoints
            pe_query = """
            Resources
            | where type == 'microsoft.network/privateendpoints'
            | extend connectedService = properties.privateLinkServiceConnections[0].properties.privateLinkServiceId
            | project id, name, connectedService
            """
            
            private_endpoints = self.client.query_resources(
                pe_query,
                subscriptions=[self.subscription_id]
            )
            
            # Check storage accounts
            storage_query = """
            Resources
            | where type == 'microsoft.storage/storageaccounts'
            | extend privateEndpointConnections = properties.privateEndpointConnections
            | extend hasPrivateEndpoint = isnotnull(privateEndpointConnections) and array_length(privateEndpointConnections) > 0
            | project id, name, hasPrivateEndpoint
            """
            
            storage_accounts = self.client.query_resources(
                storage_query,
                subscriptions=[self.subscription_id]
            )
            
            storage_no_pe = [sa for sa in storage_accounts if not sa.get('hasPrivateEndpoint', False)]
            
            if storage_no_pe and len(storage_accounts) > 0:
                self.findings.append({
                    'control_id': 'NS-4',
                    'title': 'Storage Accounts Without Private Endpoints',
                    'severity': 'High',
                    'description': f'{len(storage_no_pe)} of {len(storage_accounts)} storage accounts lack private endpoints',
                    'affected_resources': [sa['id'] for sa in storage_no_pe[:10]],
                    'recommendation': (
                        'Deploy private endpoints for storage accounts to eliminate public Internet exposure. '
                        'Combine with network rules to enforce private access only.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create private endpoint in target VNet',
                            '2. Connect to storage account',
                            '3. Configure private DNS zone',
                            '4. Disable public network access on storage',
                            '5. Test connectivity from VNet'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create private endpoint for storage
az network private-endpoint create \\
    --resource-group [RG_NAME] \\
    --name [PE_NAME] \\
    --vnet-name [VNET_NAME] \\
    --subnet [SUBNET_NAME] \\
    --private-connection-resource-id [STORAGE_ID] \\
    --group-id blob \\
    --connection-name [CONNECTION_NAME]

# Disable public access
az storage account update \\
    --resource-group [RG_NAME] \\
    --name [STORAGE_NAME] \\
    --public-network-access Disabled
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/storage/common/storage-private-endpoints',
                        'https://learn.microsoft.com/azure/private-link/private-endpoint-overview'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_azure_firewall(self):
        """
        ASB-NS-5: Azure Firewall deployment
        
        Checks:
        - Azure Firewall presence
        - Firewall policy configuration
        - Threat intelligence enabled
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/azurefirewalls'
            | extend sku = properties.sku.tier
            | extend threatIntel = properties.threatIntelMode
            | project id, name, sku, threatIntel
            """
            
            firewalls = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for VNets
            vnet_query = """
            Resources
            | where type == 'microsoft.network/virtualnetworks'
            | summarize count()
            """
            
            vnet_count_result = self.client.query_resources(
                vnet_query,
                subscriptions=[self.subscription_id]
            )
            
            vnet_count = vnet_count_result[0].get('count_', 0) if vnet_count_result else 0
            
            if vnet_count > 2 and len(firewalls) == 0:
                self.findings.append({
                    'control_id': 'NS-5',
                    'title': 'No Azure Firewall Deployed',
                    'severity': 'High',
                    'description': f'{vnet_count} VNets found but no Azure Firewall for centralized security',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Deploy Azure Firewall for centralized network security, filtering, and logging. '
                        'Use hub-spoke topology with firewall in hub VNet.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Design hub-spoke network topology',
                            '2. Create Azure Firewall in hub VNet',
                            '3. Configure firewall policies',
                            '4. Enable threat intelligence',
                            '5. Route spoke VNet traffic through firewall',
                            '6. Configure logging to Log Analytics'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create Azure Firewall
az network firewall create \\
    --resource-group [RG_NAME] \\
    --name [FW_NAME] \\
    --location [LOCATION] \\
    --vnet-name [HUB_VNET_NAME] \\
    --public-ip [PIP_NAME] \\
    --sku AZFW_VNet \\
    --tier Standard

# Enable threat intelligence
az network firewall update \\
    --resource-group [RG_NAME] \\
    --name [FW_NAME] \\
    --threat-intel-mode Alert
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/firewall/overview',
                        'https://learn.microsoft.com/azure/architecture/reference-architectures/hybrid-networking/hub-spoke'
                    ]
                })
            
            # Check threat intelligence on existing firewalls
            if firewalls:
                no_threat_intel = [fw for fw in firewalls if fw.get('threatIntel') != 'Alert' and fw.get('threatIntel') != 'Deny']
                
                if no_threat_intel:
                    self.findings.append({
                        'control_id': 'NS-5',
                        'title': 'Azure Firewalls Without Threat Intelligence',
                        'severity': 'Medium',
                        'description': f'{len(no_threat_intel)} firewalls do not have threat intelligence enabled',
                        'affected_resources': [fw['id'] for fw in no_threat_intel],
                        'recommendation': 'Enable threat intelligence in Alert or Deny mode on all Azure Firewalls',
                        'remediation': {
                            'steps': [
                                '1. Go to Azure Firewall settings',
                                '2. Enable Threat Intelligence',
                                '3. Set to Alert or Deny mode',
                                '4. Monitor threat intelligence alerts'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Enable threat intelligence
az network firewall update \\
    --resource-group [RG_NAME] \\
    --name [FW_NAME] \\
    --threat-intel-mode Deny
'''
                        }
                    })
        
        except Exception as e:
            pass
    
    async def check_network_segmentation(self):
        """
        ASB-NS-6: Network segmentation
        
        Checks:
        - Subnet count per VNet
        - NSG assignment to subnets
        - Application/tier segregation
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/virtualnetworks'
            | extend subnets = properties.subnets
            | mvexpand subnets
            | extend subnetName = subnets.name
            | extend nsg = subnets.properties.networkSecurityGroup
            | extend hasNSG = isnotnull(nsg)
            | project vnetId = id, vnetName = name, subnetName, hasNSG
            """
            
            vnet_subnets = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for subnets without NSG
            subnets_no_nsg = [s for s in vnet_subnets if not s.get('hasNSG', False)]
            
            # Filter out special subnets (AzureFirewallSubnet, GatewaySubnet, etc.)
            special_subnets = ['AzureFirewallSubnet', 'GatewaySubnet', 'AzureBastionSubnet']
            subnets_no_nsg = [
                s for s in subnets_no_nsg
                if s.get('subnetName') not in special_subnets
            ]
            
            if subnets_no_nsg:
                self.findings.append({
                    'control_id': 'NS-6',
                    'title': 'Subnets Without Network Security Groups',
                    'severity': 'High',
                    'description': f'{len(subnets_no_nsg)} subnets do not have NSGs attached',
                    'affected_resources': [f"{s['vnetId']}/subnets/{s['subnetName']}" for s in subnets_no_nsg[:10]],
                    'recommendation': (
                        'Attach NSGs to all subnets for network micro-segmentation. '
                        'Create separate NSGs for different application tiers (web, app, data).'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create NSG with appropriate rules',
                            '2. Associate NSG with subnet',
                            '3. Test application connectivity',
                            '4. Enable NSG flow logs',
                            '5. Monitor traffic patterns'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create NSG
az network nsg create \\
    --resource-group [RG_NAME] \\
    --name [NSG_NAME]

# Associate with subnet
az network vnet subnet update \\
    --resource-group [RG_NAME] \\
    --vnet-name [VNET_NAME] \\
    --name [SUBNET_NAME] \\
    --network-security-group [NSG_NAME]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview',
                        'https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_waf_deployment(self):
        """
        ASB-NS-7: Web Application Firewall
        
        Checks:
        - WAF enabled on Application Gateways
        - WAF policies configured
        - WAF mode (Detection vs Prevention)
        """
        try:
            query = """
            Resources
            | where type == 'microsoft.network/applicationgateways'
            | extend wafEnabled = properties.webApplicationFirewallConfiguration.enabled
            | extend wafMode = properties.webApplicationFirewallConfiguration.firewallMode
            | project id, name, wafEnabled, wafMode
            """
            
            app_gateways = self.client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            if app_gateways:
                # Check for WAF not enabled
                no_waf = [ag for ag in app_gateways if not ag.get('wafEnabled', False)]
                
                if no_waf:
                    self.findings.append({
                        'control_id': 'NS-7',
                        'title': 'Application Gateways Without WAF',
                        'severity': 'Critical',
                        'description': f'{len(no_waf)} Application Gateways do not have WAF enabled',
                        'affected_resources': [ag['id'] for ag in no_waf],
                        'recommendation': (
                            'Enable Web Application Firewall on all Application Gateways. '
                            'WAF protects against OWASP Top 10 vulnerabilities and common attacks.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Upgrade Application Gateway to WAF SKU',
                                '2. Enable WAF in Prevention mode',
                                '3. Configure WAF policy with OWASP rules',
                                '4. Test application functionality',
                                '5. Monitor WAF logs for attacks'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Create WAF policy
az network application-gateway waf-policy create \\
    --resource-group [RG_NAME] \\
    --name [WAF_POLICY_NAME] \\
    --type OWASP \\
    --version 3.2

# Update Application Gateway with WAF
az network application-gateway update \\
    --resource-group [RG_NAME] \\
    --name [AG_NAME] \\
    --waf-policy [WAF_POLICY_ID]
'''
                        },
                        'references': [
                            'https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview',
                            'https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-configuration'
                        ]
                    })
                
                # Check WAF mode (should be Prevention)
                detection_mode = [ag for ag in app_gateways if ag.get('wafMode') == 'Detection']
                
                if detection_mode:
                    self.findings.append({
                        'control_id': 'NS-7',
                        'title': 'WAF in Detection Mode Only',
                        'severity': 'Medium',
                        'description': f'{len(detection_mode)} Application Gateways have WAF in Detection mode (not blocking)',
                        'affected_resources': [ag['id'] for ag in detection_mode],
                        'recommendation': (
                            'Change WAF mode from Detection to Prevention. '
                            'Detection mode only logs attacks without blocking them.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Review WAF logs for false positives',
                                '2. Configure exclusions if needed',
                                '3. Change WAF mode to Prevention',
                                '4. Monitor for blocked requests',
                                '5. Fine-tune rules as needed'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Set WAF to Prevention mode
az network application-gateway waf-config set \\
    --resource-group [RG_NAME] \\
    --gateway-name [AG_NAME] \\
    --enabled true \\
    --firewall-mode Prevention
'''
                        }
                    })
        
        except Exception as e:
            pass


def run_evaluation(subscription_id: str) -> List[Dict]:
    """
    Convenience function to run Network Security evaluation
    
    Args:
        subscription_id: Azure subscription ID
        
    Returns:
        List of findings
    """
    evaluator = NetworkSecurityEvaluator(subscription_id)
    return asyncio.run(evaluator.evaluate_all())
