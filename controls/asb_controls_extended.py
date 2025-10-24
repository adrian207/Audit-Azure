"""
Azure Security Benchmark - Remaining Control Domains
Data Protection, Asset Management, Logging, Incident Response, 
Posture Management, Endpoint Security, Backup/Recovery, DevSecOps, Governance
"""

from controls.asb_controls import ASBControl, ControlMapping


# Data Protection (DP) Controls
DP_CONTROLS = [
    ASBControl(
        control_id="DP-1",
        domain="Data Protection",
        title="Discover and classify sensitive data",
        description="Use Microsoft Purview to identify and label sensitive data",
        security_principle="Know where sensitive data resides to apply appropriate protections",
        azure_guidance="Enable Microsoft Purview Data Map. Configure sensitivity labels. Scan Azure SQL, Storage, Cosmos DB. Apply automatic classification.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["3.1", "3.2"],
            nist_800_53=["SC-28", "MP-2"],
            pci_dss=["3.1", "3.2"],
            iso_27001=["A.8.2.1", "A.8.2.3"]
        )
    ),
    ASBControl(
        control_id="DP-2",
        domain="Data Protection",
        title="Monitor anomalies and threats targeting sensitive data",
        description="Detect suspicious data access patterns",
        security_principle="Identify potential data exfiltration or unauthorized access",
        azure_guidance="Enable Microsoft Defender for Storage, SQL, Cosmos DB. Configure alerts for anomalous access. Monitor data egress patterns.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["13.2"],
            nist_800_53=["SI-4", "AU-6"],
            pci_dss=["10.6"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="DP-3",
        domain="Data Protection",
        title="Encrypt sensitive data at rest",
        description="Use encryption for all data at rest",
        security_principle="Protect data confidentiality when stored",
        azure_guidance="Enable encryption at rest (default for most services). Use customer-managed keys in Key Vault for sensitive workloads. Enable TDE for SQL databases.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["3.11"],
            nist_800_53=["SC-28", "SC-28(1)"],
            pci_dss=["3.4"],
            iso_27001=["A.10.1.1"]
        )
    ),
    ASBControl(
        control_id="DP-4",
        domain="Data Protection",
        title="Use encryption in transit",
        description="Encrypt all data in motion",
        security_principle="Protect data confidentiality during transmission",
        azure_guidance="Require TLS 1.2+ for all services. Disable HTTP, use HTTPS only. Enable 'Secure transfer required' on Storage accounts. Use IPsec for VPN connections.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["3.10"],
            nist_800_53=["SC-8", "SC-8(1)"],
            pci_dss=["4.1", "4.2"],
            iso_27001=["A.13.1.1", "A.13.2.1"]
        )
    ),
    ASBControl(
        control_id="DP-5",
        domain="Data Protection",
        title="Use Azure Key Vault",
        description="Store secrets, keys, and certificates in Key Vault",
        security_principle="Centralize cryptographic key and secret management",
        azure_guidance="Create Key Vaults with RBAC access. Enable soft delete and purge protection. Use managed identities to access Key Vault. Rotate keys regularly.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["3.11", "16.9"],
            nist_800_53=["SC-12", "SC-13"],
            pci_dss=["3.5", "3.6"],
            iso_27001=["A.10.1.2"]
        )
    ),
    ASBControl(
        control_id="DP-6",
        domain="Data Protection",
        title="Manage data lifecycle and retention",
        description="Implement data retention and disposal policies",
        security_principle="Comply with data retention requirements and minimize data exposure",
        azure_guidance="Configure lifecycle management policies for Storage. Use retention policies for backups. Implement soft delete. Document and test data disposal procedures.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["3.3"],
            nist_800_53=["MP-6", "SI-12"],
            pci_dss=["3.1", "9.8"],
            iso_27001=["A.8.2.3", "A.8.3.2"]
        )
    ),
    ASBControl(
        control_id="DP-7",
        domain="Data Protection",
        title="Use a data loss prevention process",
        description="Prevent unauthorized data exfiltration",
        security_principle="Detect and block sensitive data from leaving the organization",
        azure_guidance="Use Microsoft Purview DLP policies. Monitor data downloads and transfers. Alert on suspicious file operations. Block or encrypt sensitive data transfers.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["3.12"],
            nist_800_53=["SC-7", "AC-4"],
            pci_dss=["3.2"],
            iso_27001=["A.13.2.1"]
        )
    ),
    ASBControl(
        control_id="DP-8",
        domain="Data Protection",
        title="Ensure security of key management process",
        description="Implement proper key lifecycle management",
        security_principle="Protect cryptographic keys throughout their lifecycle",
        azure_guidance="Use Azure Key Vault Managed HSM for highest security. Implement key rotation. Separate duties (key admin vs key user). Audit key usage.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["3.11"],
            nist_800_53=["SC-12", "SC-13"],
            pci_dss=["3.5", "3.6"],
            iso_27001=["A.10.1.2"]
        )
    ),
]


# Asset Management (AM) Controls
AM_CONTROLS = [
    ASBControl(
        control_id="AM-1",
        domain="Asset Management",
        title="Track asset inventory and their risks",
        description="Maintain complete inventory of Azure resources",
        security_principle="You can't protect what you don't know exists",
        azure_guidance="Use Azure Resource Graph to query resources. Tag resources with owner, environment, data classification. Use Defender for Cloud inventory.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["1.1", "1.2"],
            nist_800_53=["CM-8", "PM-5"],
            pci_dss=["2.4"],
            iso_27001=["A.8.1.1", "A.8.1.2"]
        )
    ),
    ASBControl(
        control_id="AM-2",
        domain="Asset Management",
        title="Use only approved services",
        description="Maintain approved service catalog",
        security_principle="Control sprawl and reduce attack surface",
        azure_guidance="Use Azure Policy to restrict allowed resource types. Implement resource provider registration controls. Document approved services.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["2.3"],
            nist_800_53=["CM-2", "CM-7"],
            pci_dss=["2.2"],
            iso_27001=["A.12.5.1"]
        )
    ),
    ASBControl(
        control_id="AM-3",
        domain="Asset Management",
        title="Ensure only approved services are allowed",
        description="Enforce approved service catalog",
        security_principle="Prevent unauthorized service deployment",
        azure_guidance="Use Azure Policy with Deny effect to block unapproved resource types. Monitor for policy violations. Regular review approved service list.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["2.3"],
            nist_800_53=["CM-2", "CM-7"],
            pci_dss=["2.2"],
            iso_27001=["A.12.5.1"]
        )
    ),
    ASBControl(
        control_id="AM-4",
        domain="Asset Management",
        title="Use standard naming and resource tagging",
        description="Implement consistent resource naming and tagging",
        security_principle="Improve resource organization, cost management, and security",
        azure_guidance="Define naming convention (e.g., CAF). Require tags: Environment, Owner, CostCenter, DataClassification. Use Azure Policy to enforce.",
        severity="Low",
        mappings=ControlMapping(
            cis_v8=["1.1"],
            nist_800_53=["CM-8"],
            pci_dss=["2.4"],
            iso_27001=["A.8.1.1"]
        )
    ),
    ASBControl(
        control_id="AM-5",
        domain="Asset Management",
        title="Use Azure Monitor for asset lifecycle",
        description="Monitor resource creation, modification, deletion",
        security_principle="Maintain visibility into infrastructure changes",
        azure_guidance="Enable Activity Log retention. Send to Log Analytics. Alert on critical resource changes. Monitor for resource deletion.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["8.2"],
            nist_800_53=["AU-6", "CM-3"],
            pci_dss=["10.2"],
            iso_27001=["A.12.4.1"]
        )
    ),
]


# Logging and Threat Detection (LT) Controls
LT_CONTROLS = [
    ASBControl(
        control_id="LT-1",
        domain="Logging and Threat Detection",
        title="Enable threat detection capabilities",
        description="Use Microsoft Defender for Cloud for threat detection",
        security_principle="Detect threats using advanced analytics and threat intelligence",
        azure_guidance="Enable Defender plans for Servers, Storage, SQL, Key Vault, Containers, App Service. Configure alert notifications. Integrate with SIEM.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["8.11", "13.2"],
            nist_800_53=["SI-4", "AU-6"],
            pci_dss=["10.6", "11.4"],
            iso_27001=["A.12.6.1", "A.16.1.2"]
        )
    ),
    ASBControl(
        control_id="LT-2",
        domain="Logging and Threat Detection",
        title="Enable threat detection for identity and access",
        description="Monitor identity-based threats",
        security_principle="Detect credential compromise and identity attacks",
        azure_guidance="Enable Azure AD Identity Protection. Configure risky user and sign-in policies. Monitor for impossible travel, anonymous IP usage, password spray.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["6.7", "8.11"],
            nist_800_53=["SI-4", "IA-10"],
            pci_dss=["10.6", "11.4"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="LT-3",
        domain="Logging and Threat Detection",
        title="Enable logging for security investigation",
        description="Capture comprehensive logs for security analysis",
        security_principle="Ensure sufficient data for incident investigation",
        azure_guidance="Enable diagnostic settings for all resources. Send to Log Analytics. Capture resource logs, activity logs, Azure AD logs. Retain logs ≥1 year.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["8.2", "8.5", "8.12"],
            nist_800_53=["AU-3", "AU-6", "AU-12"],
            pci_dss=["10.1", "10.2", "10.3"],
            iso_27001=["A.12.4.1"]
        )
    ),
    ASBControl(
        control_id="LT-4",
        domain="Logging and Threat Detection",
        title="Enable network logging",
        description="Capture network traffic logs for analysis",
        security_principle="Investigate network-based attacks and policy violations",
        azure_guidance="Enable NSG Flow Logs. Configure Azure Firewall diagnostic logs. Use Traffic Analytics. Capture DNS logs.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["8.2", "8.5", "13.6"],
            nist_800_53=["AU-3", "AU-6", "SI-4"],
            pci_dss=["10.8"],
            iso_27001=["A.12.4.1"]
        )
    ),
    ASBControl(
        control_id="LT-5",
        domain="Logging and Threat Detection",
        title="Centralize security log management",
        description="Aggregate logs in central SIEM",
        security_principle="Enable correlation and analysis across all security data",
        azure_guidance="Use Microsoft Sentinel as SIEM. Ingest logs from all sources. Create analytic rules for threat detection. Configure automated responses.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["8.2", "8.11"],
            nist_800_53=["AU-6", "SI-4"],
            pci_dss=["10.6"],
            iso_27001=["A.12.4.1", "A.16.1.7"]
        )
    ),
    ASBControl(
        control_id="LT-6",
        domain="Logging and Threat Detection",
        title="Configure log storage and retention",
        description="Store logs securely with appropriate retention",
        security_principle="Meet compliance requirements and investigation needs",
        azure_guidance="Store logs in immutable storage. Set retention ≥365 days (per requirements). Encrypt log data. Control access with RBAC.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["8.3"],
            nist_800_53=["AU-4", "AU-11"],
            pci_dss=["10.7"],
            iso_27001=["A.12.4.1"]
        )
    ),
    ASBControl(
        control_id="LT-7",
        domain="Logging and Threat Detection",
        title="Use automated tools to investigate",
        description="Leverage AI/ML for threat detection",
        security_principle="Detect sophisticated threats faster than manual analysis",
        azure_guidance="Enable Microsoft Sentinel UEBA. Use Fusion ML detections. Configure threat intelligence feeds. Automate incident investigation.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["13.9"],
            nist_800_53=["SI-4", "IR-4"],
            pci_dss=["11.4"],
            iso_27001=["A.12.6.1"]
        )
    ),
]


# Export all domain controls
DOMAIN_CONTROLS = {
    "DP": DP_CONTROLS,
    "AM": AM_CONTROLS,
    "LT": LT_CONTROLS,
}
