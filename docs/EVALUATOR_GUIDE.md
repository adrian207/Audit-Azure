# Audit-Azure Evaluator Authoring Guide

**Author:** Adrian Johnson <adrian207@gmail.com>

## Overview
Evaluators are Python functions that analyze evidence and return findings. Each evaluator is mapped to a control in the catalog.

## Creating a New Evaluator
1. Add a function to the appropriate module in `evaluators/` (e.g., `identity.py`, `networking.py`).
2. The function should accept a dict (evidence) and return a list of finding dicts.
3. Register the function in `evaluators/registry.py` with a ControlId.

## Example
```python
def check_custom_policy(evidence):
    # Analyze evidence and return findings
    ...
    return [finding]
```

## Finding Format
- FindingId: str
- ControlId: str
- Domain: str
- Severity: str
- Summary: str
- ImpactedResources: list
- EvidenceRefs: list
- Status: str
- GeneratedAt: ISO8601 string

## Registering the Evaluator
In `evaluators/registry.py`:
```python
CONTROL_EVALUATOR["NEW-001"] = (module, "check_custom_policy")
```
