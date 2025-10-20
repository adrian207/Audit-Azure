from evaluators.data import check_storage_https_only

def test_storage_https_finding():
    """Test evaluator for storage accounts without HTTPS enforced."""
    evidence = {
        "RawResult": [
            {
                "id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
                "name": "sa1",
                "location": "eastus",
                "subscriptionId": "sub1",
                "properties": {"supportsHttpsTrafficOnly": False}
            }
        ]
    }
    findings = check_storage_https_only(evidence)
    assert isinstance(findings, list)
    assert len(findings) == 1
    f = findings[0]
    assert f["ControlId"] == "DATA-001"
    assert "https" in f["Summary"].lower()