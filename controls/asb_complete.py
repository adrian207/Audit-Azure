"""
Complete Azure Security Benchmark Control Framework
All remaining domains: IR, PV, ES, BR, DS, GS
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
    weight: int = 1  # For secure score calculation


# Incident Response (IR) Controls
IR_CONTROLS = [
    ASBControl(
        control_id="IR-1",
        domain="Incident Response",
        title="Preparation and training",
        description="Establish IR plan and train personnel",
        security_principle="Prepare for effective incident response",
        azure_guidance="Document IR procedures. Define roles and responsibilities. Conduct tabletop exercises. Integrate with Microsoft Defender for Cloud and Sentinel.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["17.1"],
            nist_800_53=["IR-1", "IR-2"],
            pci_dss=["12.10"],
            iso_27001=["A.16.1.1", "A.16.1.2"]
        )
    ),
    ASBControl(
        control_id="IR-2",
        domain="Incident Response",
        title="Detection and analysis",
        description="Implement threat detection mechanisms",
        security_principle="Quickly identify and assess security incidents",
        azure_guidance="Use Microsoft Sentinel for detection. Configure alert rules. Implement UEBA. Define incident severity classification.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["17.2", "17.3"],
            nist_800_53=["IR-4", "IR-5"],
            pci_dss=["10.6", "11.4"],
            iso_27001=["A.16.1.2", "A.16.1.4"]
        )
    ),
    ASBControl(
        control_id="IR-3",
        domain="Incident Response",
        title="Containment",
        description="Implement containment strategies",
        security_principle="Limit the scope and impact of incidents",
        azure_guidance="Use NSGs to isolate compromised resources. Disable user accounts. Revoke access tokens. Snapshot compromised VMs for forensics.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["17.4"],
            nist_800_53=["IR-4"],
            pci_dss=["12.10.5"],
            iso_27001=["A.16.1.5"]
        )
    ),
    ASBControl(
        control_id="IR-4",
        domain="Incident Response",
        title="Post-incident activities",
        description="Conduct post-incident review and lessons learned",
        security_principle="Continuously improve incident response capabilities",
        azure_guidance="Document incidents in Sentinel. Conduct post-mortem analysis. Update detection rules. Track metrics (MTTD, MTTR).",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["17.9"],
            nist_800_53=["IR-4", "IR-8"],
            pci_dss=["12.10.7"],
            iso_27001=["A.16.1.6", "A.16.1.7"]
        )
    ),
]


# Posture and Vulnerability Management (PV) Controls
PV_CONTROLS = [
    ASBControl(
        control_id="PV-1",
        domain="Posture and Vulnerability Management",
        title="Conduct vulnerability scans",
        description="Regularly scan for vulnerabilities",
        security_principle="Identify security weaknesses before attackers do",
        azure_guidance="Enable Microsoft Defender Vulnerability Management. Scan VMs, containers, databases. Implement continuous assessment.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["7.1", "7.2"],
            nist_800_53=["RA-5"],
            pci_dss=["11.2"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="PV-2",
        domain="Posture and Vulnerability Management",
        title="Audit and enforce secure configurations",
        description="Monitor for configuration drift",
        security_principle="Ensure resources remain compliant with security baselines",
        azure_guidance="Use Azure Policy for configuration management. Enable Guest Configuration for VMs. Deploy Azure Automanage for baseline enforcement.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["4.1", "4.2"],
            nist_800_53=["CM-2", "CM-6"],
            pci_dss=["2.2"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="PV-3",
        domain="Posture and Vulnerability Management",
        title="Remediate vulnerabilities",
        description="Implement vulnerability remediation process",
        security_principle="Reduce attack surface by fixing known vulnerabilities",
        azure_guidance="Prioritize based on CVSS and exploit availability. Use Azure Update Management. Track SLAs for remediation. Verify fixes.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["7.3", "7.4"],
            nist_800_53=["RA-5", "SI-2"],
            pci_dss=["6.2", "11.2.3"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="PV-4",
        domain="Posture and Vulnerability Management",
        title="Conduct regular security reviews",
        description="Perform periodic security assessments",
        security_principle="Validate security posture through external review",
        azure_guidance="Use Defender for Cloud Secure Score. Conduct quarterly security reviews. Engage third-party penetration testing annually.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["18.1", "18.2"],
            nist_800_53=["CA-2", "CA-7"],
            pci_dss=["11.3"],
            iso_27001=["A.18.2.1"]
        )
    ),
    ASBControl(
        control_id="PV-5",
        domain="Posture and Vulnerability Management",
        title="Perform penetration testing",
        description="Conduct authorized penetration tests",
        security_principle="Validate security controls against real-world attacks",
        azure_guidance="Follow Microsoft Cloud Penetration Testing Rules of Engagement. Notify Microsoft. Use approved testing tools. Document findings.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["18.1"],
            nist_800_53=["CA-8"],
            pci_dss=["11.3"],
            iso_27001=["A.18.2.3"]
        )
    ),
    ASBControl(
        control_id="PV-6",
        domain="Posture and Vulnerability Management",
        title="Rapidly deploy software updates",
        description="Implement patch management process",
        security_principle="Minimize exposure window for known vulnerabilities",
        azure_guidance="Use Azure Update Management Center. Enable automatic updates for critical patches. Test patches in dev/staging. Monitor compliance.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["7.1", "7.2"],
            nist_800_53=["SI-2"],
            pci_dss=["6.2"],
            iso_27001=["A.12.6.1"]
        )
    ),
    ASBControl(
        control_id="PV-7",
        domain="Posture and Vulnerability Management",
        title="Conduct security configuration assessments",
        description="Regularly assess security configurations",
        security_principle="Identify and remediate misconfigurations",
        azure_guidance="Use Defender for Cloud recommendations. Review Security Benchmark compliance. Implement CIS Azure Foundations Benchmark.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["4.1"],
            nist_800_53=["CM-6", "CA-7"],
            pci_dss=["2.2"],
            iso_27001=["A.12.6.1"]
        )
    ),
]


# Endpoint Security (ES) Controls
ES_CONTROLS = [
    ASBControl(
        control_id="ES-1",
        domain="Endpoint Security",
        title="Use endpoint detection and response",
        description="Deploy EDR solution on endpoints",
        security_principle="Detect and respond to endpoint threats",
        azure_guidance="Deploy Microsoft Defender for Endpoint. Enable behavioral monitoring. Configure automated investigation and remediation.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["10.1", "10.2"],
            nist_800_53=["SI-3", "SI-4"],
            pci_dss=["5.1", "5.2"],
            iso_27001=["A.12.2.1"]
        )
    ),
    ASBControl(
        control_id="ES-2",
        domain="Endpoint Security",
        title="Use antimalware software",
        description="Deploy and maintain antimalware protection",
        security_principle="Protect against malware infections",
        azure_guidance="Enable Microsoft Antimalware for Azure. Keep signatures up-to-date. Scan regularly. Log detections to Azure Monitor.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["10.1"],
            nist_800_53=["SI-3"],
            pci_dss=["5.1", "5.2"],
            iso_27001=["A.12.2.1"]
        )
    ),
    ASBControl(
        control_id="ES-3",
        domain="Endpoint Security",
        title="Ensure antimalware is regularly updated",
        description="Maintain current malware definitions",
        security_principle="Detect the latest malware threats",
        azure_guidance="Enable automatic signature updates. Monitor update status. Alert on outdated definitions (>7 days).",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["10.1"],
            nist_800_53=["SI-3"],
            pci_dss=["5.2"],
            iso_27001=["A.12.2.1"]
        )
    ),
]


# Backup and Recovery (BR) Controls
BR_CONTROLS = [
    ASBControl(
        control_id="BR-1",
        domain="Backup and Recovery",
        title="Enable backups",
        description="Implement comprehensive backup strategy",
        security_principle="Ensure business continuity and data recovery capability",
        azure_guidance="Use Azure Backup for VMs, SQL, Files. Configure backup policies. Enable geo-redundant storage for backups.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["11.1", "11.2"],
            nist_800_53=["CP-9", "CP-10"],
            pci_dss=["3.1"],
            iso_27001=["A.12.3.1", "A.17.1.2"]
        )
    ),
    ASBControl(
        control_id="BR-2",
        domain="Backup and Recovery",
        title="Protect backup data",
        description="Secure backups from deletion and tampering",
        security_principle="Prevent ransomware from destroying backups",
        azure_guidance="Enable soft delete for Azure Backup. Use immutable backup vaults. Implement RBAC for backup operations. Monitor backup deletions.",
        severity="Critical",
        weight=3,
        mappings=ControlMapping(
            cis_v8=["11.3"],
            nist_800_53=["CP-9", "CP-6"],
            pci_dss=["3.1"],
            iso_27001=["A.12.3.1"]
        )
    ),
    ASBControl(
        control_id="BR-3",
        domain="Backup and Recovery",
        title="Test backup restoration",
        description="Regularly validate backup recovery",
        security_principle="Ensure backups can actually be restored",
        azure_guidance="Conduct quarterly restore tests. Document RTO/RPO. Test disaster recovery scenarios. Verify data integrity.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["11.5"],
            nist_800_53=["CP-4", "CP-9"],
            pci_dss=["3.1"],
            iso_27001=["A.17.1.3"]
        )
    ),
    ASBControl(
        control_id="BR-4",
        domain="Backup and Recovery",
        title="Enable business continuity and disaster recovery",
        description="Implement BCDR strategy",
        security_principle="Maintain operations during disasters",
        azure_guidance="Use Azure Site Recovery. Configure availability zones. Implement regional failover. Document BCDR runbooks.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["11.4"],
            nist_800_53=["CP-2", "CP-7"],
            pci_dss=["12.10"],
            iso_27001=["A.17.1.1", "A.17.2.1"]
        )
    ),
]


# DevSecOps (DS) Controls
DS_CONTROLS = [
    ASBControl(
        control_id="DS-1",
        domain="DevSecOps",
        title="Implement secure development lifecycle",
        description="Integrate security into SDLC",
        security_principle="Build security in from the start",
        azure_guidance="Use Microsoft Security Development Lifecycle (SDL). Conduct threat modeling. Implement security gates in CI/CD. Train developers.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["16.1"],
            nist_800_53=["SA-3", "SA-4"],
            pci_dss=["6.3", "6.5"],
            iso_27001=["A.14.1.1", "A.14.2.1"]
        )
    ),
    ASBControl(
        control_id="DS-2",
        domain="DevSecOps",
        title="Scan code for vulnerabilities",
        description="Implement static and dynamic code analysis",
        security_principle="Identify vulnerabilities before production",
        azure_guidance="Use GitHub Advanced Security or Defender for DevOps. Scan for secrets, dependencies, code vulnerabilities. Block risky PRs.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["16.2", "16.3"],
            nist_800_53=["SA-11", "RA-5"],
            pci_dss=["6.3.2", "6.5"],
            iso_27001=["A.14.2.1", "A.14.2.5"]
        )
    ),
    ASBControl(
        control_id="DS-3",
        domain="DevSecOps",
        title="Scan dependencies for vulnerabilities",
        description="Monitor third-party component vulnerabilities",
        security_principle="Reduce supply chain risk",
        azure_guidance="Use Dependabot or similar. Monitor CVEs in dependencies. Update vulnerable packages. Maintain SBOM.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["16.11"],
            nist_800_53=["SA-10", "SR-3"],
            pci_dss=["6.2"],
            iso_27001=["A.14.2.1"]
        )
    ),
    ASBControl(
        control_id="DS-4",
        domain="DevSecOps",
        title="Implement infrastructure as code security",
        description="Scan IaC templates for misconfigurations",
        security_principle="Prevent security issues in infrastructure",
        azure_guidance="Scan Bicep/ARM/Terraform templates. Use Policy-as-Code. Validate against security baselines. Use Defender for DevOps.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["16.4"],
            nist_800_53=["CM-2", "CM-6"],
            pci_dss=["2.2"],
            iso_27001=["A.14.2.1"]
        )
    ),
    ASBControl(
        control_id="DS-5",
        domain="DevSecOps",
        title="Secure container images",
        description="Scan and sign container images",
        security_principle="Prevent deployment of vulnerable containers",
        azure_guidance="Use Defender for Containers. Scan images in ACR. Implement image signing. Use minimal base images. Regular rebuild images.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["16.5"],
            nist_800_53=["SA-11", "CM-7"],
            pci_dss=["6.3.2"],
            iso_27001=["A.14.2.1"]
        )
    ),
    ASBControl(
        control_id="DS-6",
        domain="DevSecOps",
        title="Implement secure CI/CD pipelines",
        description="Secure build and deployment pipelines",
        security_principle="Protect the software supply chain",
        azure_guidance="Secure Azure DevOps/GitHub Actions. Use managed identities. Require code reviews. Implement branch protection. Audit pipeline changes.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["16.6"],
            nist_800_53=["SA-10", "CM-3"],
            pci_dss=["6.3.1"],
            iso_27001=["A.14.2.2", "A.14.2.3"]
        )
    ),
]


# Governance and Strategy (GS) Controls
GS_CONTROLS = [
    ASBControl(
        control_id="GS-1",
        domain="Governance and Strategy",
        title="Define security posture management strategy",
        description="Establish comprehensive security strategy",
        security_principle="Align security with business objectives",
        azure_guidance="Define Cloud Adoption Framework security strategy. Establish security governance model. Assign roles and responsibilities.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["1.1"],
            nist_800_53=["PM-1", "PM-9"],
            pci_dss=["12.1"],
            iso_27001=["A.5.1.1", "A.6.1.1"]
        )
    ),
    ASBControl(
        control_id="GS-2",
        domain="Governance and Strategy",
        title="Define security organization and roles",
        description="Establish security team structure",
        security_principle="Ensure clear security responsibilities",
        azure_guidance="Define security functions per Cloud Adoption Framework. Implement separation of duties. Document escalation paths.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["1.2"],
            nist_800_53=["PM-11", "PS-2"],
            pci_dss=["12.5"],
            iso_27001=["A.6.1.1", "A.7.1.2"]
        )
    ),
    ASBControl(
        control_id="GS-3",
        domain="Governance and Strategy",
        title="Align security and business objectives",
        description="Integrate security with business processes",
        security_principle="Security enables rather than hinders business",
        azure_guidance="Participate in architecture reviews. Provide security requirements. Measure security outcomes aligned with business KPIs.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["1.1"],
            nist_800_53=["PM-1"],
            pci_dss=["12.1"],
            iso_27001=["A.5.1.1"]
        )
    ),
    ASBControl(
        control_id="GS-4",
        domain="Governance and Strategy",
        title="Define security standards and policies",
        description="Establish security policies and standards",
        security_principle="Provide clear security expectations",
        azure_guidance="Document security policies. Implement Azure Policy for enforcement. Conduct annual policy reviews. Communicate changes.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["4.1"],
            nist_800_53=["PM-9", "PL-1"],
            pci_dss=["12.1"],
            iso_27001=["A.5.1.1", "A.5.1.2"]
        )
    ),
    ASBControl(
        control_id="GS-5",
        domain="Governance and Strategy",
        title="Conduct security training",
        description="Train personnel on security responsibilities",
        security_principle="People are the first line of defense",
        azure_guidance="Provide security awareness training. Conduct phishing simulations. Train developers on secure coding. Certify security staff.",
        severity="Medium",
        weight=1,
        mappings=ControlMapping(
            cis_v8=["14.1", "14.2"],
            nist_800_53=["AT-2", "AT-3"],
            pci_dss=["12.6"],
            iso_27001=["A.7.2.2"]
        )
    ),
    ASBControl(
        control_id="GS-6",
        domain="Governance and Strategy",
        title="Monitor security posture and compliance",
        description="Track security metrics and compliance status",
        security_principle="Continuous improvement requires measurement",
        azure_guidance="Use Defender for Cloud Secure Score. Track compliance with regulatory frameworks. Report to leadership monthly.",
        severity="High",
        weight=2,
        mappings=ControlMapping(
            cis_v8=["4.1"],
            nist_800_53=["CA-7", "PM-6"],
            pci_dss=["12.8"],
            iso_27001=["A.18.2.1", "A.18.2.2"]
        )
    ),
]


# Export all controls
ALL_ASB_CONTROLS = {
    "IR": IR_CONTROLS,
    "PV": PV_CONTROLS,
    "ES": ES_CONTROLS,
    "BR": BR_CONTROLS,
    "DS": DS_CONTROLS,
    "GS": GS_CONTROLS,
}


def get_all_controls_flat() -> List[ASBControl]:
    """Get flattened list of all controls"""
    all_controls = []
    for domain_controls in ALL_ASB_CONTROLS.values():
        all_controls.extend(domain_controls)
    return all_controls
