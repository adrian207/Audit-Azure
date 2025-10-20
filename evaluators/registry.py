"""Evaluator registry: explicit mapping of ControlId -> evaluator function.

This avoids dynamic discovery and centralizes control -> evaluator mapping.
"""
from evaluators import identity, networking, data

# Map ControlId to (module, function_name)
CONTROL_EVALUATOR = {
    "IAM-001": (identity, "check_users_without_mfa"),
    "IAM-002": (identity, "check_owner_role_assignments"),
    "IAM-003": (identity, "check_service_principals"),
    "NET-001": (networking, "check_nsg_inbound_any"),
    "NET-002": (networking, "check_ddos_enabled"),
    "NET-003": (networking, "check_private_endpoints"),
    "DATA-001": (data, "check_storage_https_only"),
}

def get_evaluator_by_control(control_id: str):
    entry = CONTROL_EVALUATOR.get(control_id)
    if not entry:
        return None
    module, func_name = entry
    fn = getattr(module, func_name, None)
    return fn
