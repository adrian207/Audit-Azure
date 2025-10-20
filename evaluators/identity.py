"""Evaluator stubs for Identity domain.

These are minimal functions that demonstrate the expected input/output.
They return sample Finding-like dicts for integration testing.
"""
import datetime
import uuid


def check_users_without_mfa(evidence):
    """Evaluate evidence (list of users) and return findings list."""
    # evidence: dict or list containing users with mfaEnabled flag
    users = evidence.get("users", []) if isinstance(evidence, dict) else []
    missing = [u for u in users if not u.get("mfaEnabled", False)]
    if not missing:
        return []
    finding = {
        "FindingId": str(uuid.uuid4()),
        "ControlId": "IAM-001",
        "Domain": "Identity",
        "Severity": "High",
        "RiskScore": 85,
        "Summary": f"{len(missing)} accounts don\'t have MFA enabled",
        "Description": "Multi-factor authentication is not enforced for these user accounts.",
        "ImpactedResources": [
            {"ResourceId": u.get("id",""), "ResourceType": "Microsoft.Entra/user", "ResourceName": u.get("userPrincipalName",""), "SubscriptionId": "N/A", "Location": "Global"}
            for u in missing
        ],
        "EvidenceRefs": [
            {"EvidenceId": evidence.get("EvidenceId","ev-unknown"), "Source": "EntraAPI", "QueryOrRequest": evidence.get("query", "GET /users"), "Timestamp": datetime.datetime.now(datetime.UTC).isoformat(), "RawResultHash": "sha256:sample"}
        ],
        "Recommendation": "Enable MFA for all users via Conditional Access policies.",
        "Remediation": {"FixType": "Policy", "DryRunPlan": "Create CA policy requiring MFA", "RollbackPlan": "Remove CA policy"},
        "Status": "Open",
        "GeneratedAt": datetime.datetime.now(datetime.UTC).isoformat(),
        "BenchmarkMappings": []
    }
    return [finding]


def check_service_principals(evidence):
    # placeholder
    return []
