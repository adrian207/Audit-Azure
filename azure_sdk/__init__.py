"""
Azure SDK Integration Layer

Provides authenticated clients and helper methods for Azure services.
"""

from .auth import AzureAuthManager
from .resource_graph import ResourceGraphClient
from .policy_client import PolicyClient
from .monitor_client import MonitorClient
from .defender_client import DefenderClient
from .entra_client import EntraClient

__all__ = [
    'AzureAuthManager',
    'ResourceGraphClient',
    'PolicyClient',
    'MonitorClient',
    'DefenderClient',
    'EntraClient',
]
