"""Evaluator module exports."""
from .registry import get_evaluator_by_control
from .identity import check_users_without_mfa, check_service_principals
from .networking import check_nsg_inbound_any, check_ddos_enabled
from .data import check_storage_https_only

# Comprehensive evaluators
from .entra_id import EntraIDEvaluator
from .azure_policy import AzurePolicyEvaluator
from .data_protection import DataProtectionEvaluator
from .network_security import NetworkSecurityEvaluator
from .vulnerability_mgmt import VulnerabilityManagementEvaluator
from .logging_monitoring import LoggingMonitoringEvaluator
from .secure_score import SecureScoreCalculator

__all__ = [
    # Legacy functions
    'get_evaluator_by_control',
    'check_users_without_mfa',
    'check_service_principals',
    'check_nsg_inbound_any',
    'check_ddos_enabled',
    'check_storage_https_only',
    
    # Comprehensive evaluators (NEW)
    'EntraIDEvaluator',
    'AzurePolicyEvaluator',
    'DataProtectionEvaluator',
    'NetworkSecurityEvaluator',
    'VulnerabilityManagementEvaluator',
    'LoggingMonitoringEvaluator',
    'SecureScoreCalculator',
]
