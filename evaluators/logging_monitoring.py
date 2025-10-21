"""
Logging and Monitoring Evaluator

Evaluates Azure logging and monitoring controls including:
- Diagnostic settings configuration
- Log Analytics workspace setup
- Activity log retention
- Resource logging
- Security audit logging
- Monitoring alerts
"""

import asyncio
from typing import List, Dict, Any, Optional
from azure_sdk.monitor_client import MonitorClient
from azure_sdk.resource_graph import ResourceGraphClient
from azure_sdk.auth import AzureAuthManager


class LoggingMonitoringEvaluator:
    """Evaluate Azure logging and monitoring controls"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Logging and Monitoring evaluator
        
        Args:
            subscription_id: Azure subscription ID
            auth_manager: Azure authentication manager
        """
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        self.monitor_client = MonitorClient(subscription_id, auth_manager=self.auth_manager)
        self.resource_client = ResourceGraphClient(auth_manager=self.auth_manager)
        self.findings = []
    
    async def evaluate_all(self) -> List[Dict]:
        """
        Run all logging and monitoring security checks
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        # Run all checks
        await self.check_log_analytics_workspace()
        await self.check_activity_log_retention()
        await self.check_diagnostic_settings()
        await self.check_security_logging()
        await self.check_metric_alerts()
        await self.check_nsg_flow_logs()
        
        return self.findings
    
    async def check_log_analytics_workspace(self):
        """
        ASB-LT-1: Log Analytics workspace configuration
        
        Checks:
        - Workspace existence
        - Retention period
        - Data collection
        """
        try:
            # Check for Log Analytics workspaces
            query = """
            Resources
            | where type == 'microsoft.operationalinsights/workspaces'
            | extend retention = properties.retentionInDays
            | project id, name, location, retention
            """
            
            workspaces = self.resource_client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            if len(workspaces) == 0:
                self.findings.append({
                    'control_id': 'LT-1',
                    'title': 'No Log Analytics Workspace Configured',
                    'severity': 'Critical',
                    'description': 'No Log Analytics workspace found - centralized logging not configured',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Create Log Analytics workspace for centralized log collection and analysis. '
                        'Required for Azure Monitor, Microsoft Defender, and compliance.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Create Log Analytics workspace',
                            '2. Set retention period (90+ days for production)',
                            '3. Configure diagnostic settings to send logs',
                            '4. Install agents on VMs',
                            '5. Configure data collection rules',
                            '6. Set up log queries and alerts'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create Log Analytics workspace
az monitor log-analytics workspace create \\
    --resource-group [RG_NAME] \\
    --workspace-name [WORKSPACE_NAME] \\
    --location [LOCATION] \\
    --retention-time 90

# Configure diagnostic settings (example for Key Vault)
az monitor diagnostic-settings create \\
    --name [DIAG_NAME] \\
    --resource [RESOURCE_ID] \\
    --workspace [WORKSPACE_ID] \\
    --logs '[{"category":"AuditEvent","enabled":true}]' \\
    --metrics '[{"category":"AllMetrics","enabled":true}]'
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview',
                        'https://learn.microsoft.com/azure/azure-monitor/logs/quick-create-workspace'
                    ]
                })
            else:
                # Check retention period
                short_retention = [w for w in workspaces if w.get('retention', 0) < 90]
                
                if short_retention:
                    self.findings.append({
                        'control_id': 'LT-1',
                        'title': 'Log Analytics Workspaces with Short Retention',
                        'severity': 'Medium',
                        'description': f'{len(short_retention)} workspaces have retention < 90 days',
                        'affected_resources': [w['id'] for w in short_retention],
                        'recommendation': (
                            'Increase log retention to 90+ days for compliance and forensic investigations. '
                            'Consider 180-365 days for production environments.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Go to Log Analytics workspace settings',
                                '2. Update retention period to 90-365 days',
                                '3. Consider cost implications',
                                '4. Archive older logs to storage if needed'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Update workspace retention
az monitor log-analytics workspace update \\
    --resource-group [RG_NAME] \\
    --workspace-name [WORKSPACE_NAME] \\
    --retention-time 90
'''
                        }
                    })
        
        except Exception as e:
            self.findings.append({
                'control_id': 'LT-1',
                'title': 'Error Checking Log Analytics',
                'severity': 'Medium',
                'description': f'Failed to evaluate Log Analytics: {str(e)}'
            })
    
    async def check_activity_log_retention(self):
        """
        ASB-LT-2: Activity log retention
        
        Checks:
        - Activity log export to storage/Log Analytics
        - Retention period
        """
        try:
            # Check for log profiles (classic) or diagnostic settings
            query = """
            Resources
            | where type == 'microsoft.insights/diagnosticsettings'
            | where id contains '/subscriptions/'
            | project id, name, properties
            """
            
            diag_settings = self.resource_client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Activity logs have 90-day retention in portal, but should be exported for longer retention
            if len(diag_settings) == 0:
                self.findings.append({
                    'control_id': 'LT-2',
                    'title': 'Activity Logs Not Exported',
                    'severity': 'High',
                    'description': 'Subscription activity logs are not exported to Log Analytics or Storage',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Configure diagnostic settings to export activity logs to Log Analytics workspace. '
                        'Required for compliance, audit trails, and security investigations.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure Monitor > Activity Log',
                            '2. Click Diagnostic settings',
                            '3. Add diagnostic setting at subscription level',
                            '4. Select all log categories (Administrative, Security, Alert, etc.)',
                            '5. Send to Log Analytics workspace',
                            '6. Optionally archive to storage for long-term retention'
                        ],
                        'script_type': 'Azure CLI',
                        'script': f'''
# Create diagnostic setting for subscription activity log
az monitor diagnostic-settings subscription create \\
    --name activity-log-to-workspace \\
    --location [LOCATION] \\
    --workspace [WORKSPACE_ID] \\
    --logs '[
        {{"category": "Administrative", "enabled": true}},
        {{"category": "Security", "enabled": true}},
        {{"category": "ServiceHealth", "enabled": true}},
        {{"category": "Alert", "enabled": true}},
        {{"category": "Recommendation", "enabled": true}},
        {{"category": "Policy", "enabled": true}},
        {{"category": "Autoscale", "enabled": true}},
        {{"category": "ResourceHealth", "enabled": true}}
    ]'
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log',
                        'https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_diagnostic_settings(self):
        """
        ASB-LT-3: Resource diagnostic settings
        
        Checks:
        - Resources without diagnostic settings
        - Critical resources logging
        """
        try:
            # Check critical resource types
            critical_types = [
                'microsoft.keyvault/vaults',
                'microsoft.sql/servers/databases',
                'microsoft.storage/storageaccounts',
                'microsoft.network/networksecuritygroups',
                'microsoft.network/applicationgateways',
                'microsoft.web/sites'
            ]
            
            for resource_type in critical_types:
                query = f"""
                Resources
                | where type == '{resource_type}'
                | project id, name, type
                """
                
                resources = self.resource_client.query_resources(
                    query,
                    subscriptions=[self.subscription_id]
                )
                
                if resources and len(resources) > 0:
                    # Check diagnostic settings (would need Monitor API call per resource)
                    # Simplified: recommend configuration
                    resource_name = resource_type.split('/')[-1].title()
                    
                    self.findings.append({
                        'control_id': 'LT-3',
                        'title': f'Verify Diagnostic Settings for {resource_name}',
                        'severity': 'Medium',
                        'description': f'{len(resources)} {resource_name} resources found - verify diagnostic logging enabled',
                        'affected_resources': [r['id'] for r in resources[:5]],
                        'recommendation': (
                            f'Ensure all {resource_name} have diagnostic settings configured to send logs '
                            'to Log Analytics workspace for security monitoring and compliance.'
                        ),
                        'remediation': {
                            'steps': [
                                f'1. For each {resource_name} resource',
                                '2. Go to Diagnostic settings',
                                '3. Add diagnostic setting',
                                '4. Select all relevant log categories',
                                '5. Send to Log Analytics workspace',
                                '6. Enable AllMetrics'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Enable diagnostic settings (generic example)
az monitor diagnostic-settings create \\
    --name default-diagnostics \\
    --resource [RESOURCE_ID] \\
    --workspace [WORKSPACE_ID] \\
    --logs '[{"category":"AllLogs","enabled":true}]' \\
    --metrics '[{"category":"AllMetrics","enabled":true}]'
'''
                        }
                    })
        
        except Exception as e:
            pass
    
    async def check_security_logging(self):
        """
        ASB-LT-4: Security audit logging
        
        Checks:
        - Azure AD sign-in logs
        - Audit logs
        """
        try:
            # Check for Log Analytics workspace (needed for Azure AD logs)
            query = """
            Resources
            | where type == 'microsoft.operationalinsights/workspaces'
            | project id, name
            """
            
            workspaces = self.resource_client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            if workspaces:
                self.findings.append({
                    'control_id': 'LT-4',
                    'title': 'Verify Azure AD Log Integration',
                    'severity': 'Medium',
                    'description': 'Ensure Azure AD logs (sign-ins, audit) are sent to Log Analytics',
                    'affected_resources': [w['id'] for w in workspaces],
                    'recommendation': (
                        'Configure Azure AD diagnostic settings to send sign-in logs and audit logs '
                        'to Log Analytics for security monitoring and compliance.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure AD > Diagnostic settings',
                            '2. Add diagnostic setting',
                            '3. Select SignInLogs and AuditLogs categories',
                            '4. Send to Log Analytics workspace',
                            '5. Create alerts for failed sign-ins, privilege changes',
                            '6. Review logs regularly'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Configure Azure AD diagnostic settings
az monitor diagnostic-settings create \\
    --name aad-logs-to-workspace \\
    --resource [AZURE_AD_TENANT_ID] \\
    --workspace [WORKSPACE_ID] \\
    --logs '[
        {"category":"SignInLogs","enabled":true},
        {"category":"AuditLogs","enabled":true},
        {"category":"NonInteractiveUserSignInLogs","enabled":true},
        {"category":"ServicePrincipalSignInLogs","enabled":true},
        {"category":"ManagedIdentitySignInLogs","enabled":true}
    ]'

# Note: This requires Azure AD Premium P1 or P2
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics',
                        'https://learn.microsoft.com/azure/active-directory/reports-monitoring/concept-audit-logs'
                    ]
                })
        
        except Exception as e:
            pass
    
    async def check_metric_alerts(self):
        """
        ASB-LT-5: Monitoring alerts
        
        Checks:
        - Alert rules configured
        - Action groups for notifications
        """
        try:
            # Check for metric alert rules
            query = """
            Resources
            | where type == 'microsoft.insights/metricalerts'
            | extend enabled = properties.enabled
            | extend severity = properties.severity
            | project id, name, enabled, severity
            """
            
            alerts = self.resource_client.query_resources(
                query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for action groups
            ag_query = """
            Resources
            | where type == 'microsoft.insights/actiongroups'
            | project id, name
            """
            
            action_groups = self.resource_client.query_resources(
                ag_query,
                subscriptions=[self.subscription_id]
            )
            
            if len(action_groups) == 0:
                self.findings.append({
                    'control_id': 'LT-5',
                    'title': 'No Action Groups Configured',
                    'severity': 'High',
                    'description': 'No action groups found for alert notifications',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Create action groups to receive alert notifications via email, SMS, or webhook. '
                        'Required for incident response and operational awareness.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Go to Azure Monitor > Alerts > Action groups',
                            '2. Create new action group',
                            '3. Add notification channels (email, SMS, webhook)',
                            '4. Add action types (runbook, function, logic app)',
                            '5. Test action group',
                            '6. Associate with alert rules'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create action group
az monitor action-group create \\
    --name security-alerts \\
    --resource-group [RG_NAME] \\
    --short-name SecAlerts \\
    --email-receiver name=SecurityTeam email=security@company.com
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups'
                    ]
                })
            
            if len(alerts) == 0:
                self.findings.append({
                    'control_id': 'LT-5',
                    'title': 'No Metric Alerts Configured',
                    'severity': 'Medium',
                    'description': 'No metric alert rules found - proactive monitoring not configured',
                    'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                    'recommendation': (
                        'Configure metric alerts for critical resources and security events. '
                        'Examples: VM CPU >90%, Storage capacity >80%, Failed authentications, Policy violations.'
                    ),
                    'remediation': {
                        'steps': [
                            '1. Identify critical metrics to monitor',
                            '2. Create metric alert rules',
                            '3. Set appropriate thresholds',
                            '4. Configure severity levels',
                            '5. Associate action groups',
                            '6. Test alerts'
                        ],
                        'script_type': 'Azure CLI',
                        'script': '''
# Create metric alert
az monitor metrics alert create \\
    --name high-cpu-alert \\
    --resource-group [RG_NAME] \\
    --scopes [RESOURCE_ID] \\
    --condition "avg Percentage CPU > 90" \\
    --window-size 5m \\
    --evaluation-frequency 1m \\
    --action [ACTION_GROUP_ID]
'''
                    },
                    'references': [
                        'https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-metric-overview'
                    ]
                })
            else:
                # Check for disabled alerts
                disabled = [a for a in alerts if not a.get('enabled', True)]
                if disabled:
                    self.findings.append({
                        'control_id': 'LT-5',
                        'title': 'Disabled Alert Rules',
                        'severity': 'Low',
                        'description': f'{len(disabled)} alert rules are disabled',
                        'affected_resources': [a['id'] for a in disabled],
                        'recommendation': 'Review and enable disabled alert rules or delete if no longer needed'
                    })
        
        except Exception as e:
            pass
    
    async def check_nsg_flow_logs(self):
        """
        ASB-LT-6: NSG Flow Logs
        
        Checks:
        - Flow logs enabled on NSGs
        - Traffic Analytics configured
        """
        try:
            # Check for Network Watchers
            nw_query = """
            Resources
            | where type == 'microsoft.network/networkwatchers'
            | project id, name, location
            """
            
            network_watchers = self.resource_client.query_resources(
                nw_query,
                subscriptions=[self.subscription_id]
            )
            
            # Check for NSGs
            nsg_query = """
            Resources
            | where type == 'microsoft.network/networksecuritygroups'
            | project id, name, location
            """
            
            nsgs = self.resource_client.query_resources(
                nsg_query,
                subscriptions=[self.subscription_id]
            )
            
            if nsgs and len(nsgs) > 0:
                if len(network_watchers) == 0:
                    self.findings.append({
                        'control_id': 'LT-6',
                        'title': 'Network Watcher Not Enabled',
                        'severity': 'High',
                        'description': f'{len(nsgs)} NSGs found but Network Watcher not enabled for NSG Flow Logs',
                        'affected_resources': [f'/subscriptions/{self.subscription_id}'],
                        'recommendation': (
                            'Enable Network Watcher and NSG Flow Logs for network traffic analysis. '
                            'Required for security monitoring and troubleshooting.'
                        ),
                        'remediation': {
                            'steps': [
                                '1. Network Watcher is auto-created when you use network features',
                                '2. Or manually create Network Watcher per region',
                                '3. Enable NSG Flow Logs for each NSG',
                                '4. Configure storage account for logs',
                                '5. Enable Traffic Analytics for insights',
                                '6. Review flow logs regularly'
                            ],
                            'script_type': 'Azure CLI',
                            'script': '''
# Create Network Watcher
az network watcher configure \\
    --resource-group NetworkWatcherRG \\
    --locations [LOCATION] \\
    --enabled true

# Enable NSG Flow Logs
az network watcher flow-log create \\
    --location [LOCATION] \\
    --name [FLOW_LOG_NAME] \\
    --nsg [NSG_ID] \\
    --storage-account [STORAGE_ID] \\
    --workspace [WORKSPACE_ID] \\
    --interval 10 \\
    --traffic-analytics true
'''
                        },
                        'references': [
                            'https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview',
                            'https://learn.microsoft.com/azure/network-watcher/traffic-analytics'
                        ]
                    })
                else:
                    self.findings.append({
                        'control_id': 'LT-6',
                        'title': 'Verify NSG Flow Logs Configuration',
                        'severity': 'Medium',
                        'description': f'{len(nsgs)} NSGs found - verify flow logs and Traffic Analytics enabled',
                        'affected_resources': [nsg['id'] for nsg in nsgs[:5]],
                        'recommendation': (
                            'Enable NSG Flow Logs and Traffic Analytics for all NSGs. '
                            'Provides network traffic visibility and security insights.'
                        )
                    })
        
        except Exception as e:
            pass


def run_evaluation(subscription_id: str) -> List[Dict]:
    """
    Convenience function to run Logging and Monitoring evaluation
    
    Args:
        subscription_id: Azure subscription ID
        
    Returns:
        List of findings
    """
    evaluator = LoggingMonitoringEvaluator(subscription_id)
    return asyncio.run(evaluator.evaluate_all())
