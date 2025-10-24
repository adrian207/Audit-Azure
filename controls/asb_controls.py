"""
Azure Security Benchmark (ASB) Control Catalog
Based on Microsoft Cloud Security Benchmark v3.0

This module defines all control domains aligned with:
- CIS Controls v8
- NIST SP 800-53 r4
- PCI-DSS v3.2.1
- ISO/IEC 27001
"""

from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ControlMapping:
    """External framework control mappings"""
    cis_v8: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    pci_dss: Optional[List[str]] = None
    iso_27001: Optional[List[str]] = None


@dataclass
class ASBControl:
    """Azure Security Benchmark Control Definition"""
    control_id: str
    domain: str
    title: str
    description: str
    security_principle: str
    azure_guidance: str
    severity: str  # Critical, High, Medium, Low
    mappings: ControlMapping
    implementation_guidance: Optional[str] = None
    
    
# Network Security (NS) Controls
NS_CONTROLS = [
    ASBControl(
        control_id="NS-1",
        domain="Network Security",
        title="Establish network segmentation boundaries",
        description="Segment networks to isolate and protect workloads",
        security_principle="Implement network segmentation using Virtual Networks, Network Security Groups, and Application Security Groups",
        azure_guidance="Use Azure Virtual Networks (VNets) for network isolation. Apply NSGs to subnets and NICs. Use Azure Firewall for centralized network filtering.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["12.1", "12.2"],
            nist_800_53=["SC-7", "AC-4"],
            pci_dss=["1.1", "1.2", "1.3"],
            iso_27001=["A.13.1.1", "A.13.1.3"]
        )
    ),
    ASBControl(
        control_id="NS-2",
        domain="Network Security",
        title="Secure cloud services with network controls",
        description="Use Private Endpoints, Service Endpoints, and network policies",
        security_principle="Restrict network access to Azure PaaS services using private connectivity",
        azure_guidance="Enable Private Link/Private Endpoints for Azure services. Use Service Endpoints where Private Link is not available. Disable public network access.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["12.1", "12.8"],
            nist_800_53=["SC-7", "AC-6"],
            pci_dss=["1.2", "1.3"],
            iso_27001=["A.13.1.1"]
        )
    ),
    ASBControl(
        control_id="NS-3",
        domain="Network Security",
        title="Deploy firewall at network edge",
        description="Use Azure Firewall or NVA for edge security",
        security_principle="Centralize network filtering and threat protection at the network perimeter",
        azure_guidance="Deploy Azure Firewall with Threat Intelligence. Use FQDN filtering, network rules, and application rules. Enable diagnostic logging.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["13.1", "13.2"],
            nist_800_53=["SC-7", "SI-4"],
            pci_dss=["1.1", "10.6"],
            iso_27001=["A.13.1.1"]
        )
    ),
    ASBControl(
        control_id="NS-4",
        domain="Network Security",
        title="Deploy web application firewall",
        description="Protect web applications with WAF",
        security_principle="Use Azure Application Gateway WAF or Azure Front Door WAF to protect against OWASP Top 10",
        azure_guidance="Enable WAF on Application Gateway or Front Door. Use OWASP CRS 3.2 or custom rules. Set to Prevention mode.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["13.1"],
            nist_800_53=["SC-7", "SI-10"],
            pci_dss=["6.5", "6.6"],
            iso_27001=["A.14.1.2"]
        )
    ),
    ASBControl(
        control_id="NS-5",
        domain="Network Security",
        title="Deploy DDoS protection",
        description="Enable DDoS Protection Standard for production workloads",
        security_principle="Protect against volumetric and protocol DDoS attacks",
        azure_guidance="Enable DDoS Protection Standard on VNets hosting public-facing resources. Configure DDoS response team notifications.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["13.1"],
            nist_800_53=["SC-5"],
            pci_dss=["10.6"],
            iso_27001=["A.17.2.1"]
        )
    ),
    ASBControl(
        control_id="NS-6",
        domain="Network Security",
        title="Deploy network intrusion detection/prevention",
        description="Use Azure Firewall Premium IDPS",
        security_principle="Detect and prevent network-based attacks using signature and anomaly-based detection",
        azure_guidance="Enable Azure Firewall Premium with IDPS in Alert or Alert and Deny mode. Customize signature rules based on environment.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["13.2", "13.7"],
            nist_800_53=["SI-4", "SI-3"],
            pci_dss=["11.4"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="NS-7",
        domain="Network Security",
        title="Simplify network security configuration",
        description="Use Azure Firewall Manager or Network Manager",
        security_principle="Centralize network security policy management across subscriptions and regions",
        azure_guidance="Use Azure Firewall Manager for centralized policy. Use Azure Virtual Network Manager for network topology management.",
        severity="Low",
        mappings=ControlMapping(
            cis_v8=["4.1"],
            nist_800_53=["CM-2", "CM-6"],
            pci_dss=["2.2"],
            iso_27001=["A.12.1.1"]
        )
    ),
]


# Identity Management (IM) Controls
IM_CONTROLS = [
    ASBControl(
        control_id="IM-1",
        domain="Identity Management",
        title="Use centralized identity and authentication system",
        description="Use Microsoft Entra ID as the central identity provider",
        security_principle="Centralize identity management to reduce complexity and improve security",
        azure_guidance="Use Microsoft Entra ID (Azure AD) for all user and application authentication. Avoid local accounts and SQL authentication.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["5.1", "6.1"],
            nist_800_53=["IA-2", "AC-2"],
            pci_dss=["8.1", "8.2"],
            iso_27001=["A.9.2.1"]
        )
    ),
    ASBControl(
        control_id="IM-2",
        domain="Identity Management",
        title="Protect identity and authentication systems",
        description="Enable MFA and protect against identity attacks",
        security_principle="Enforce multi-factor authentication and monitor for identity threats",
        azure_guidance="Enable Microsoft Entra MFA for all users. Use Conditional Access policies. Enable Identity Protection for risk-based policies.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["6.3", "6.4"],
            nist_800_53=["IA-2(1)", "IA-2(2)"],
            pci_dss=["8.3"],
            iso_27001=["A.9.4.2"]
        )
    ),
    ASBControl(
        control_id="IM-3",
        domain="Identity Management",
        title="Manage application identities securely",
        description="Use managed identities for Azure resources",
        security_principle="Eliminate credential management overhead using Azure managed identities",
        azure_guidance="Use System-assigned or User-assigned Managed Identities. Avoid service principal secrets. Use Workload Identity Federation for external systems.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.3", "16.9"],
            nist_800_53=["IA-4", "IA-5"],
            pci_dss=["8.2"],
            iso_27001=["A.9.2.1"]
        )
    ),
    ASBControl(
        control_id="IM-4",
        domain="Identity Management",
        title="Authenticate with Microsoft Entra ID",
        description="Use Azure AD authentication for all services",
        security_principle="Leverage Azure AD authentication capabilities instead of legacy authentication",
        azure_guidance="Enable Microsoft Entra authentication for SQL, Storage, App Services, etc. Disable basic/legacy authentication protocols.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.1", "6.1"],
            nist_800_53=["IA-2", "IA-5"],
            pci_dss=["8.1", "8.2"],
            iso_27001=["A.9.2.1"]
        )
    ),
    ASBControl(
        control_id="IM-5",
        domain="Identity Management",
        title="Use strong authentication controls",
        description="Implement passwordless or strong MFA methods",
        security_principle="Move beyond password-based authentication to phishing-resistant methods",
        azure_guidance="Deploy Windows Hello for Business, FIDO2 security keys, or Microsoft Authenticator passwordless. Require MFA for all users.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["6.3", "6.5"],
            nist_800_53=["IA-2(1)", "IA-2(8)"],
            pci_dss=["8.3"],
            iso_27001=["A.9.4.2"]
        )
    ),
    ASBControl(
        control_id="IM-6",
        domain="Identity Management",
        title="Use conditional access",
        description="Implement risk-based and context-aware access policies",
        security_principle="Apply Zero Trust principles with dynamic access controls",
        azure_guidance="Create Conditional Access policies based on user, location, device, application. Require compliant devices. Block legacy authentication.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["6.1", "6.2"],
            nist_800_53=["AC-2", "AC-3"],
            pci_dss=["8.1"],
            iso_27001=["A.9.1.2"]
        )
    ),
    ASBControl(
        control_id="IM-7",
        domain="Identity Management",
        title="Eliminate unintended credential exposure",
        description="Prevent secrets in code, use Key Vault",
        security_principle="Avoid hardcoded credentials and use centralized secret management",
        azure_guidance="Store secrets in Azure Key Vault. Use managed identities to access Key Vault. Scan code for exposed secrets. Rotate credentials regularly.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["16.9", "16.10"],
            nist_800_53=["IA-5(7)", "SC-12"],
            pci_dss=["8.2.1"],
            iso_27001=["A.10.1.1", "A.10.1.2"]
        )
    ),
    ASBControl(
        control_id="IM-8",
        domain="Identity Management",
        title="Restrict credential sharing",
        description="Prevent shared accounts and credential sharing",
        security_principle="Ensure individual accountability with unique credentials",
        azure_guidance="Disable shared accounts. Use named accounts for all users. Implement Privileged Access Workstations for admins. Use Azure AD groups for permission assignment.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.2", "5.3"],
            nist_800_53=["IA-2", "AC-2"],
            pci_dss=["8.1", "8.5"],
            iso_27001=["A.9.2.1"]
        )
    ),
    ASBControl(
        control_id="IM-9",
        domain="Identity Management",
        title="Secure user access to resources",
        description="Implement least privilege and Just-In-Time access",
        security_principle="Grant minimum necessary permissions and use time-limited access",
        azure_guidance="Use Azure RBAC with principle of least privilege. Enable PIM for privileged roles. Conduct access reviews quarterly.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.4", "6.7", "6.8"],
            nist_800_53=["AC-2", "AC-6"],
            pci_dss=["7.1", "7.2"],
            iso_27001=["A.9.1.2", "A.9.2.3"]
        )
    ),
]


# Privileged Access (PA) Controls
PA_CONTROLS = [
    ASBControl(
        control_id="PA-1",
        domain="Privileged Access",
        title="Separate and limit highly privileged users",
        description="Use separate admin accounts with MFA",
        security_principle="Isolate privileged operations from standard user activities",
        azure_guidance="Require dedicated admin accounts. Enable MFA for all privileged users. Use Privileged Access Workstations (PAWs).",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["5.4", "6.1"],
            nist_800_53=["AC-2", "AC-6"],
            pci_dss=["7.1", "8.1"],
            iso_27001=["A.9.2.3"]
        )
    ),
    ASBControl(
        control_id="PA-2",
        domain="Privileged Access",
        title="Avoid standing access for user accounts",
        description="Use Just-In-Time (JIT) and Just-Enough-Access (JEA)",
        security_principle="Provide time-limited elevated access only when needed",
        azure_guidance="Enable Azure AD Privileged Identity Management (PIM). Require approval for privileged role activation. Set maximum duration limits.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["5.4", "6.8"],
            nist_800_53=["AC-2", "AC-6(2)"],
            pci_dss=["7.1", "7.2"],
            iso_27001=["A.9.2.3", "A.9.2.5"]
        )
    ),
    ASBControl(
        control_id="PA-3",
        domain="Privileged Access",
        title="Manage lifecycle of identities and entitlements",
        description="Automate identity lifecycle and access reviews",
        security_principle="Continuously validate that access rights remain appropriate",
        azure_guidance="Use Azure AD Identity Governance. Configure automated access reviews. Implement entitlement management. Remove orphaned accounts.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.1", "5.2", "5.3"],
            nist_800_53=["AC-2", "IA-4"],
            pci_dss=["8.1.3", "8.1.4"],
            iso_27001=["A.9.2.5", "A.9.2.6"]
        )
    ),
    ASBControl(
        control_id="PA-4",
        domain="Privileged Access",
        title="Review and reconcile user access",
        description="Conduct periodic access reviews",
        security_principle="Validate access rights remain necessary and appropriate",
        azure_guidance="Use Azure AD Access Reviews. Review privileged role assignments quarterly. Review RBAC assignments semi-annually. Document review outcomes.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["5.3", "6.8"],
            nist_800_53=["AC-2", "AC-6(7)"],
            pci_dss=["7.1.2", "7.1.3"],
            iso_27001=["A.9.2.5"]
        )
    ),
    ASBControl(
        control_id="PA-5",
        domain="Privileged Access",
        title="Set up emergency access",
        description="Configure break-glass accounts",
        security_principle="Ensure ability to recover from identity system failures",
        azure_guidance="Create 2+ break-glass accounts with Global Admin. Use strong passwords stored securely. Exclude from Conditional Access. Monitor usage with alerts.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["5.1"],
            nist_800_53=["AC-2", "CP-2"],
            pci_dss=["8.1"],
            iso_27001=["A.17.1.1"]
        )
    ),
    ASBControl(
        control_id="PA-6",
        domain="Privileged Access",
        title="Use privileged access workstations",
        description="Require PAWs for administrative tasks",
        security_principle="Isolate high-risk administrative tasks to dedicated secure workstations",
        azure_guidance="Deploy Privileged Access Workstations (PAWs) using Intune. Restrict internet browsing and email. Use Conditional Access to require PAWs for admin tasks.",
        severity="High",
        mappings=ControlMapping(
            cis_v8=["12.7", "12.8"],
            nist_800_53=["AC-6", "SC-7"],
            pci_dss=["2.2", "8.3"],
            iso_27001=["A.11.2.6"]
        )
    ),
    ASBControl(
        control_id="PA-7",
        domain="Privileged Access",
        title="Follow just-in-time access principle",
        description="Provide time-limited access for privileged operations",
        security_principle="Minimize window of opportunity for privilege abuse",
        azure_guidance="Use Azure PIM for role activation. Set maximum activation duration. Require MFA for activation. Log all privilege elevations.",
        severity="Critical",
        mappings=ControlMapping(
            cis_v8=["5.4", "6.8"],
            nist_800_53=["AC-2", "AC-6"],
            pci_dss=["7.1", "7.2"],
            iso_27001=["A.9.2.3"]
        )
    ),
    ASBControl(
        control_id="PA-8",
        domain="Privileged Access",
        title="Determine access process for cloud provider support",
        description="Control vendor access with Customer Lockbox",
        security_principle="Maintain control over Microsoft support access to resources",
        azure_guidance="Enable Customer Lockbox for Azure. Require approval for Microsoft support access. Monitor lockbox requests. Document approval/denial rationale.",
        severity="Medium",
        mappings=ControlMapping(
            cis_v8=["5.4"],
            nist_800_53=["AC-2", "AC-6"],
            pci_dss=["7.1", "7.2"],
            iso_27001=["A.9.2.3"]
        )
    ),
]


# Continue with remaining control domains...
# (DP, AM, LT, IR, PV, ES, BR, DS, GS)

# Control Registry
ALL_CONTROLS = {
    "NS": NS_CONTROLS,
    "IM": IM_CONTROLS,
    "PA": PA_CONTROLS,
    # Add remaining domains
}


def get_control_by_id(control_id: str) -> Optional[ASBControl]:
    """Retrieve a control by its ID"""
    for domain_controls in ALL_CONTROLS.values():
        for control in domain_controls:
            if control.control_id == control_id:
                return control
    return None


def get_controls_by_domain(domain: str) -> List[ASBControl]:
    """Get all controls for a specific domain"""
    return ALL_CONTROLS.get(domain, [])


def get_all_controls() -> List[ASBControl]:
    """Get all ASB controls"""
    all_controls = []
    for domain_controls in ALL_CONTROLS.values():
        all_controls.extend(domain_controls)
    return all_controls
