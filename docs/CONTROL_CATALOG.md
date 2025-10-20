# Audit-Azure Control Catalog Format

**Author:** Adrian Johnson <adrian207@gmail.com>

## Overview
The control catalog defines the set of controls, their metadata, and the mapping to evaluator functions.

## Example (YAML)
```yaml
controls:
  - ControlId: IAM-001
    Title: "MFA must be enabled for all users"
    Domain: Identity
    Evaluator: identity.check_users_without_mfa
    SeverityRules:
      - High
    Recommendation: "Enable MFA for all users."
    RemediationType: Policy
  - ControlId: NET-001
    Title: "NSG must not allow inbound from Internet"
    Domain: Networking
    Evaluator: networking.check_nsg_inbound_any
    SeverityRules:
      - Critical
    Recommendation: "Restrict NSG rules to known IPs."
    RemediationType: Config
```

## Fields
- ControlId: Unique string
- Title: Human-readable name
- Domain: Category/domain
- Evaluator: Python function (module.function)
- SeverityRules: List of severity levels
- Recommendation: Remediation advice
- RemediationType: Policy/Config/Other
