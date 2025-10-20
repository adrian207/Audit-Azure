from evaluators.identity import check_users_without_mfa
from evaluators.networking import check_nsg_inbound_any

def test_identity_mfa_finding():
    evidence = {"users": [{"id":"u1","userPrincipalName":"a@b.com","mfaEnabled":False}]}
    findings = check_users_without_mfa(evidence)
    assert isinstance(findings, list)
    assert len(findings) == 1
    f = findings[0]
    assert f["ControlId"] == "IAM-001"
    assert "mfa" in f["Summary"].lower()


def test_networking_nsg_finding():
    evidence = {"securityRules": [{"id":"r1","name":"allow","sourceAddressPrefix":"0.0.0.0/0","subscriptionId":"sub1","location":"eastus"}]}
    findings = check_nsg_inbound_any(evidence)
    assert isinstance(findings, list)
    assert len(findings) == 1
    f = findings[0]
    assert f["ControlId"] == "NET-001"
    assert "NSG" in f["Summary"] or "inbound" in f["Summary"].lower()
