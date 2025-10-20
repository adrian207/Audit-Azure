"""Evaluator stubs for Networking domain."""
import datetime
import uuid


def check_nsg_inbound_any(evidence):
    # evidence expected: dict with securityRules
    rules = evidence.get("securityRules", []) if isinstance(evidence, dict) else []
    open_rules = [r for r in rules if r.get("sourceAddressPrefix") in ("0.0.0.0/0","*")]
    if not open_rules:
        return []
    finding = {
        "FindingId": str(uuid.uuid4()),
        "ControlId": "NET-001",
        "Domain": "Networking",
        "Severity": "Critical",
        "RiskScore": 95,
        "Summary": f"{len(open_rules)} NSG rules allow inbound from Internet",
        "Description": "NSG rules allow inbound traffic from any IP which increases attack surface.",
        "ImpactedResources": [
            {"ResourceId": r.get("id",""), "ResourceType": "Microsoft.Network/networkSecurityGroups/securityRules", "ResourceName": r.get("name",""), "SubscriptionId": r.get("subscriptionId",""), "Location": r.get("location","")}
            for r in open_rules
        ],
        "EvidenceRefs": [
            {"EvidenceId": evidence.get("EvidenceId","ev-unknown"), "Source": "ARG", "QueryOrRequest": evidence.get("query","GET securityRules"), "Timestamp": datetime.datetime.now(datetime.UTC).isoformat(), "RawResultHash": "sha256:sample"}
        ],
        "Recommendation": "Restrict NSG rules to known IPs or use JIT/bastion.",
        "Remediation": {"FixType": "Config", "DryRunPlan": "Modify NSG rules to limit source ranges", "RollbackPlan": "Restore previous NSG rules"},
        "Status": "Open",
        "GeneratedAt": datetime.datetime.now(datetime.UTC).isoformat(),
        "BenchmarkMappings": [{"Framework": "CIS", "Control": "6.1"}, {"Framework": "MCSB", "Control": "NS-1"}]
    }
    return [finding]


def check_ddos_enabled(evidence):
    return []
