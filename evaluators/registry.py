"""Evaluator registry: explicit mapping of ControlId -> evaluator function.

This avoids dynamic discovery and centralizes control -> evaluator mapping.
"""
from typing import Optional
from evaluators import identity, networking, data

# Map ControlId to (module, function_name)
CONTROL_EVALUATOR = {
    # Legacy control IDs
    "IAM-001": (identity, "check_users_without_mfa"),
    "IAM-002": (identity, "check_owner_role_assignments"),
    "IAM-003": (identity, "check_service_principals"),
    "NET-001": (networking, "check_nsg_inbound_any"),
    "NET-002": (networking, "check_ddos_enabled"),
    "NET-003": (networking, "check_private_endpoints"),
    "DATA-001": (data, "check_storage_https_only"),
}

# Map ASB Control IDs to evaluator classes
# This maps each control to its evaluator class
ASB_CONTROL_EVALUATOR = {
    # Network Security (NS-1 through NS-7)
    "NS-1": "NetworkSecurityEvaluator",
    "NS-2": "NetworkSecurityEvaluator",
    "NS-3": "NetworkSecurityEvaluator",
    "NS-4": "NetworkSecurityEvaluator",
    "NS-5": "NetworkSecurityEvaluator",
    "NS-6": "NetworkSecurityEvaluator",
    "NS-7": "NetworkSecurityEvaluator",
    
    # Identity Management (IM-2 through IM-6)
    "IM-2": "EntraIDEvaluator",
    "IM-3": "EntraIDEvaluator",
    "IM-4": "EntraIDEvaluator",
    "IM-5": "EntraIDEvaluator",
    "IM-6": "EntraIDEvaluator",
    
    # Privileged Access (PA-1, PA-3)
    "PA-1": "EntraIDEvaluator",
    "PA-3": "EntraIDEvaluator",
    
    # Data Protection (DP-1 through DP-7)
    "DP-1": "DataProtectionEvaluator",
    "DP-2": "DataProtectionEvaluator",
    "DP-3": "DataProtectionEvaluator",
    "DP-4": "DataProtectionEvaluator",
    "DP-5": "DataProtectionEvaluator",
    "DP-6": "DataProtectionEvaluator",
    "DP-7": "DataProtectionEvaluator",
    
    # Governance & Strategy (GS-1 through GS-6)
    "GS-1": "AzurePolicyEvaluator",
    "GS-2": "AzurePolicyEvaluator",
    "GS-3": "AzurePolicyEvaluator",
    "GS-4": "AzurePolicyEvaluator",
    "GS-5": "AzurePolicyEvaluator",
    "GS-6": "AzurePolicyEvaluator",
    
    # Posture & Vulnerability Management (PV-1 through PV-7)
    "PV-1": "VulnerabilityManagementEvaluator",
    "PV-2": "VulnerabilityManagementEvaluator",
    "PV-3": "VulnerabilityManagementEvaluator",
    "PV-4": "VulnerabilityManagementEvaluator",
    "PV-5": "VulnerabilityManagementEvaluator",
    "PV-6": "VulnerabilityManagementEvaluator",
    "PV-7": "VulnerabilityManagementEvaluator",
    
    # Logging & Threat Detection (LT-1 through LT-6)
    "LT-1": "LoggingMonitoringEvaluator",
    "LT-2": "LoggingMonitoringEvaluator",
    "LT-3": "LoggingMonitoringEvaluator",
    "LT-4": "LoggingMonitoringEvaluator",
    "LT-5": "LoggingMonitoringEvaluator",
    "LT-6": "LoggingMonitoringEvaluator",
}

def get_evaluator_by_control(control_id: str, subscription_id: Optional[str] = None):
    """Get evaluator for a given control ID.
    
    Args:
        control_id: The control ID (e.g., "NS-1", "IM-2")
        subscription_id: Azure subscription ID (required for ASB evaluators)
    
    Returns:
        - For legacy controls: function
        - For ASB controls: evaluator class instance
        - None if not found
    """
    import os
    
    # Get subscription_id from environment if not provided
    if not subscription_id:
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')

    # Ensure subscription_id is a string (or None) for downstream use
    if subscription_id is None:
        subscription_id = None
    
    # Check legacy control mappings first
    entry = CONTROL_EVALUATOR.get(control_id)
    if entry:
        module, func_name = entry
        fn = getattr(module, func_name, None)
        return fn
    
    # Check ASB control mappings
    evaluator_class_name = ASB_CONTROL_EVALUATOR.get(control_id)
    if evaluator_class_name:
        # Import auth manager
        from azure_sdk.auth import AzureAuthManager
        
        # Create auth manager from environment variables
        auth_manager = AzureAuthManager.from_environment()
        
        # Import and instantiate the evaluator class with required parameters
        if evaluator_class_name == "NetworkSecurityEvaluator":
            from evaluators.network_security import NetworkSecurityEvaluator
            return NetworkSecurityEvaluator(subscription_id=str(subscription_id or ''), auth_manager=auth_manager)
        elif evaluator_class_name == "EntraIDEvaluator":
            from evaluators.entra_id import EntraIDEvaluator
            # EntraID evaluations are tenant-scoped; no subscription_id parameter
            return EntraIDEvaluator(auth_manager=auth_manager)
        elif evaluator_class_name == "DataProtectionEvaluator":
            from evaluators.data_protection import DataProtectionEvaluator
            return DataProtectionEvaluator(subscription_id=str(subscription_id or ''), auth_manager=auth_manager)
        elif evaluator_class_name == "AzurePolicyEvaluator":
            from evaluators.azure_policy import AzurePolicyEvaluator
            return AzurePolicyEvaluator(subscription_id=str(subscription_id or ''), auth_manager=auth_manager)
        elif evaluator_class_name == "VulnerabilityManagementEvaluator":
            from evaluators.vulnerability_mgmt import VulnerabilityManagementEvaluator
            return VulnerabilityManagementEvaluator(subscription_id=str(subscription_id or ''), auth_manager=auth_manager)
        elif evaluator_class_name == "LoggingMonitoringEvaluator":
            from evaluators.logging_monitoring import LoggingMonitoringEvaluator
            return LoggingMonitoringEvaluator(subscription_id=str(subscription_id or ''), auth_manager=auth_manager)
    
    return None
