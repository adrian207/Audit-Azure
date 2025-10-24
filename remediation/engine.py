"""
Automated Remediation System
Provides automated fixes for common Azure security issues
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure_sdk.auth import AzureAuthManager
from azure_sdk.resource_graph import ResourceGraphClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient


class RemediationEngine:
    """Automated remediation for Azure security findings"""
    
    def __init__(self, subscription_id: str, auth_manager: Optional[AzureAuthManager] = None):
        self.subscription_id = subscription_id
        self.auth_manager = auth_manager or AzureAuthManager.from_environment()
        self.resource_client = ResourceManagementClient(
            self.auth_manager.get_credential(), subscription_id
        )
        self.storage_client = StorageManagementClient(
            self.auth_manager.get_credential(), subscription_id
        )
        self.network_client = NetworkManagementClient(
            self.auth_manager.get_credential(), subscription_id
        )
        self.resource_graph = ResourceGraphClient(auth_manager=self.auth_manager)
    
    async def remediate_finding(self, finding: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
        """
        Remediate a specific finding
        
        Args:
            finding: Finding object with remediation details
            dry_run: If True, only simulate the remediation
            
        Returns:
            Remediation result with status and details
        """
        control_id = finding.get("ControlId", "")
        remediation_type = finding.get("RemediationType", "manual")
        
        result = {
            "finding_id": finding.get("FindingId"),
            "control_id": control_id,
            "remediation_type": remediation_type,
            "dry_run": dry_run,
            "status": "pending",
            "details": {},
            "timestamp": datetime.now(datetime.UTC).isoformat()
        }
        
        try:
            if control_id.startswith("DP-") and "storage" in finding.get("Summary", "").lower():
                result = await self._remediate_storage_https(finding, dry_run)
            elif control_id.startswith("NS-") and "nsg" in finding.get("Summary", "").lower():
                result = await self._remediate_nsg_rules(finding, dry_run)
            elif control_id.startswith("IM-") and "mfa" in finding.get("Summary", "").lower():
                result = await self._remediate_mfa_policy(finding, dry_run)
            else:
                result["status"] = "manual_required"
                result["details"] = {"message": "Manual remediation required"}
        except Exception as e:
            result["status"] = "failed"
            result["details"] = {"error": str(e)}
        
        return result
    
    async def _remediate_storage_https(self, finding: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        """Remediate storage account HTTPS requirement"""
        impacted_resources = finding.get("ImpactedResources", [])
        if isinstance(impacted_resources, str):
            try:
                impacted_resources = json.loads(impacted_resources)
            except:
                impacted_resources = []
        
        results = []
        for resource in impacted_resources:
            resource_id = resource.get("id", "")
            if not resource_id:
                continue
            
            # Parse resource details
            parts = resource_id.split('/')
            if len(parts) < 9:
                continue
            
            resource_group = parts[4]
            storage_account = parts[8]
            
            try:
                if not dry_run:
                    # Enable HTTPS-only for storage account
                    storage_account_obj = self.storage_client.storage_accounts.get_properties(
                        resource_group, storage_account
                    )
                    storage_account_obj.enable_https_traffic_only = True
                    
                    self.storage_client.storage_accounts.update(
                        resource_group, storage_account, storage_account_obj
                    )
                
                results.append({
                    "resource_id": resource_id,
                    "action": "enabled_https_only",
                    "status": "success" if not dry_run else "simulated"
                })
            except Exception as e:
                results.append({
                    "resource_id": resource_id,
                    "action": "enabled_https_only",
                    "status": "failed",
                    "error": str(e)
                })
        
        return {
            "finding_id": finding.get("FindingId"),
            "control_id": finding.get("ControlId"),
            "remediation_type": "automated",
            "dry_run": dry_run,
            "status": "completed",
            "details": {"remediated_resources": results},
            "timestamp": datetime.now(datetime.UTC).isoformat()
        }
    
    async def _remediate_nsg_rules(self, finding: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        """Remediate NSG rules allowing unrestricted access"""
        impacted_resources = finding.get("ImpactedResources", [])
        if isinstance(impacted_resources, str):
            try:
                impacted_resources = json.loads(impacted_resources)
            except:
                impacted_resources = []
        
        results = []
        for resource in impacted_resources:
            resource_id = resource.get("id", "")
            if not resource_id:
                continue
            
            # Parse NSG details
            parts = resource_id.split('/')
            if len(parts) < 9:
                continue
            
            resource_group = parts[4]
            nsg_name = parts[8]
            
            try:
                if not dry_run:
                    # Get NSG and remove problematic rules
                    nsg = self.network_client.network_security_groups.get(
                        resource_group, nsg_name
                    )
                    
                    # Remove rules with source 0.0.0.0/0
                    rules_to_remove = []
                    for rule in nsg.security_rules:
                        if rule.source_address_prefix == "0.0.0.0/0":
                            rules_to_remove.append(rule.name)
                    
                    for rule_name in rules_to_remove:
                        self.network_client.security_rules.delete(
                            resource_group, nsg_name, rule_name
                        )
                
                results.append({
                    "resource_id": resource_id,
                    "action": "removed_unrestricted_rules",
                    "status": "success" if not dry_run else "simulated"
                })
            except Exception as e:
                results.append({
                    "resource_id": resource_id,
                    "action": "removed_unrestricted_rules",
                    "status": "failed",
                    "error": str(e)
                })
        
        return {
            "finding_id": finding.get("FindingId"),
            "control_id": finding.get("ControlId"),
            "remediation_type": "automated",
            "dry_run": dry_run,
            "status": "completed",
            "details": {"remediated_resources": results},
            "timestamp": datetime.now(datetime.UTC).isoformat()
        }
    
    async def _remediate_mfa_policy(self, finding: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        """Remediate MFA policy (requires Entra ID admin permissions)"""
        # This would require Entra ID admin permissions
        # For now, return a manual remediation requirement
        return {
            "finding_id": finding.get("FindingId"),
            "control_id": finding.get("ControlId"),
            "remediation_type": "manual",
            "dry_run": dry_run,
            "status": "manual_required",
            "details": {
                "message": "MFA policy remediation requires Entra ID admin permissions",
                "instructions": [
                    "1. Navigate to Azure Active Directory > Security > Authentication methods",
                    "2. Enable MFA for all users or specific groups",
                    "3. Configure Conditional Access policies",
                    "4. Set up MFA registration policy"
                ]
            },
            "timestamp": datetime.now(datetime.UTC).isoformat()
        }
    
    async def get_remediation_preview(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Get a preview of what remediation would do"""
        return await self.remediate_finding(finding, dry_run=True)
    
    async def execute_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Execute actual remediation"""
        return await self.remediate_finding(finding, dry_run=False)


# Remediation templates for common issues
REMEDIATION_TEMPLATES = {
    "storage_https": {
        "name": "Enable HTTPS-only for Storage Accounts",
        "description": "Configure storage accounts to require HTTPS traffic only",
        "automated": True,
        "risk_level": "low",
        "estimated_time": "2-5 minutes"
    },
    "nsg_unrestricted": {
        "name": "Remove Unrestricted NSG Rules",
        "description": "Remove Network Security Group rules that allow unrestricted access",
        "automated": True,
        "risk_level": "medium",
        "estimated_time": "5-10 minutes"
    },
    "mfa_policy": {
        "name": "Configure MFA Policy",
        "description": "Set up Multi-Factor Authentication policies",
        "automated": False,
        "risk_level": "high",
        "estimated_time": "30-60 minutes"
    },
    "rbac_cleanup": {
        "name": "Clean Up Excessive RBAC Assignments",
        "description": "Remove unnecessary role assignments",
        "automated": False,
        "risk_level": "high",
        "estimated_time": "15-30 minutes"
    }
}
