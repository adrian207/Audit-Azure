"""Evaluator functions for Data domain controls."""
import datetime
import uuid

def check_storage_https_only(evidence):
    """Check storage accounts enforce HTTPS traffic only."""
    accounts = evidence.get("RawResult", []) if isinstance(evidence, dict) else []
    insecure = [
        a for a in accounts 
        if not a.get("properties", {}).get("supportsHttpsTrafficOnly", True)
    ]
    if not insecure:
        return []
    
    finding = {
        "FindingId": str(uuid.uuid4()),
        "ControlId": "DATA-001",
        "Domain": "Data",
        "Severity": "High",
        "RiskScore": 80,
        "Summary": f"{len(insecure)} storage accounts allow non-HTTPS traffic",
        "Description": "Storage accounts should require secure transfer (HTTPS) to protect data in transit.",
        "ImpactedResources": [
            {
                "ResourceId": a.get("id",""),
                "ResourceType": "Microsoft.Storage/storageAccounts",
                "ResourceName": a.get("name",""),
                "SubscriptionId": a.get("subscriptionId",""),
                "Location": a.get("location","")
            }
            for a in insecure
        ],
        "EvidenceRefs": [
            {
                "EvidenceId": evidence.get("EvidenceId","ev-unknown"),
                "Source": "ARG",
                "QueryOrRequest": evidence.get("QueryOrRequest", "GET storageAccounts"),
                "Timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                "RawResultHash": "sha256:sample"
            }
        ],
        "Recommendation": "Enable 'Secure transfer required' on all storage accounts.",
        "Remediation": {
            "FixType": "Config",
            "DryRunPlan": "Enable HTTPS-only traffic",
            "RollbackPlan": "Disable HTTPS-only requirement"
        },
        "Status": "Open",
    "GeneratedAt": datetime.datetime.now(datetime.UTC).isoformat(),
        "BenchmarkMappings": [
            {"Framework": "CIS", "Control": "3.1"},
            {"Framework": "MCSB", "Control": "DP-2"}
        ]
    }
    return [finding]