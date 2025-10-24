"""
Azure Monitor Client

Query logs, metrics, and diagnostic settings.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from azure.mgmt.monitor import MonitorManagementClient  # type: ignore[import]
from azure.monitor.query import LogsQueryClient  # type: ignore[import]
from .auth import AzureAuthManager


class MonitorClient:
    """Azure Monitor operations"""
    mgmt_client: Any
    logs_client: Any
    metrics_client: Any
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        """
        Initialize Monitor client
        
        Args:
            subscription_id: Azure subscription ID
            auth_manager: Authentication manager
        """
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        credential = self.auth_manager.get_credential()
        
        # Treat SDK clients as Any to reduce static-analysis noise
        self.mgmt_client: Any = MonitorManagementClient(credential, subscription_id)  # type: ignore
        self.logs_client: Any = LogsQueryClient(credential)  # type: ignore
        # Note: MetricsQueryClient not available in current azure-monitor-query version
        self.metrics_client: Any = None
    
    def get_diagnostic_settings(self, resource_id: str) -> List[Dict]:
        """
        Get diagnostic settings for resource
        
        Args:
            resource_id: Resource ID
            
        Returns:
            List of diagnostic settings
        """
        settings = []
        
        for setting in self.mgmt_client.diagnostic_settings.list(resource_id):
            settings.append({
                'id': setting.id,
                'name': setting.name,
                'storage_account_id': setting.storage_account_id,
                'workspace_id': setting.workspace_id,
                'event_hub_authorization_rule_id': setting.event_hub_authorization_rule_id,
                'logs': [
                    {
                        'category': log.category,
                        'enabled': log.enabled,
                        'retention_days': log.retention_policy.days if log.retention_policy else 0
                    }
                    for log in setting.logs
                ] if setting.logs else [],
                'metrics': [
                    {
                        'category': metric.category,
                        'enabled': metric.enabled
                    }
                    for metric in setting.metrics
                ] if setting.metrics else []
            })
        
        return settings
    
    def query_logs(
        self,
        workspace_id: str,
        query: str,
        timespan: Optional[timedelta] = None
    ) -> List[Dict]:
        """
        Query Log Analytics workspace
        
        Args:
            workspace_id: Workspace ID
            query: KQL query
            timespan: Query timespan (defaults to 24 hours)
            
        Returns:
            Query results
        """
        if not timespan:
            timespan = timedelta(hours=24)
        
        response = self.logs_client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timespan
        )
        
        results = []
        for table in response.tables:
            for row in table.rows:
                result = {}
                for i, column in enumerate(table.columns):
                    result[column.name] = row[i]
                results.append(result)
        
        return results
    
    def get_activity_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        filter_query: Optional[str] = None
    ) -> List[Dict]:
        """
        Get Activity Log events
        
        Args:
            start_time: Start time (defaults to 24 hours ago)
            end_time: End time (defaults to now)
            filter_query: OData filter
            
        Returns:
            Activity log events
        """
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=24)
        if not end_time:
            end_time = datetime.utcnow()
        
        filter_str = f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}'"
        if filter_query:
            filter_str += f" and {filter_query}"
        
        events = []
        for event in self.mgmt_client.activity_logs.list(filter=filter_str):
            events.append({
                'id': event.id,
                'event_name': event.event_name.value if event.event_name else None,
                'category': event.category.value if event.category else None,
                'operation_name': event.operation_name.value if event.operation_name else None,
                'resource_id': event.resource_id,
                'resource_group': event.resource_group_name,
                'timestamp': event.event_timestamp,
                'level': event.level.value if event.level else None,
                'status': event.status.value if event.status else None,
                'caller': event.caller,
                'correlation_id': event.correlation_id
            })
        
        return events
    
    def get_failed_operations(self, hours: int = 24) -> List[Dict]:
        """
        Get failed operations from Activity Log
        
        Args:
            hours: Look back hours
            
        Returns:
            Failed operations
        """
        start_time = datetime.utcnow() - timedelta(hours=hours)
        filter_query = "status eq 'Failed'"
        
        return self.get_activity_logs(
            start_time=start_time,
            filter_query=filter_query
        )
    
    def check_nsg_flow_logs(self, nsg_id: str) -> Dict[str, Any]:
        """
        Check if NSG flow logs are enabled
        
        Args:
            nsg_id: Network Security Group resource ID
            
        Returns:
            Flow log status
        """
        # Parse resource group from NSG ID
        parts = nsg_id.split('/')
        resource_group = parts[4]
        
        try:
            flow_logs = self.mgmt_client.flow_logs.list(
                resource_group_name=resource_group,
                network_watcher_name='NetworkWatcher_' + parts[8]  # Region-based
            )
            
            for log in flow_logs:
                if log.target_resource_id == nsg_id:
                    return {
                        'enabled': log.enabled,
                        'storage_id': log.storage_id,
                        'retention_days': log.retention_policy.days if log.retention_policy else 0,
                        'format': log.format.version if log.format else None
                    }
            
            return {'enabled': False}
        
        except Exception:
            return {'enabled': False, 'error': 'Unable to check flow logs'}
    
    def get_metrics(
        self,
        resource_id: str,
        metric_names: List[str],
        timespan: Optional[timedelta] = None,
        aggregation: str = 'Average'
    ) -> Dict[str, List]:
        """
        Get metrics for resource
        
        Args:
            resource_id: Resource ID
            metric_names: List of metric names
            timespan: Query timespan
            aggregation: Aggregation type
            
        Returns:
            Metrics data
        """
        # Note: MetricsQueryClient not available in current azure-monitor-query version
        # This is a placeholder implementation
        return {
            'error': 'MetricsQueryClient not available in current azure-monitor-query version',
            'metrics': {}
        }
