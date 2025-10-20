# Audit-Azure API Reference

**Author:** Adrian Johnson <adrian207@gmail.com>

## Endpoints

### POST /evidence
- **Description:** Submit evidence for evaluation
- **Request:**
  - Source: str
  - QueryOrRequest: str
  - RawResult: str (JSON-encoded)
  - Timestamp: ISO8601 string (optional)
- **Response:**
  - EvidenceId: str

### POST /evaluate
- **Description:** Run evaluator on evidence
- **Request:**
  - evidenceId: str
  - evaluator: str (ControlId or function name)
- **Response:**
  - created: list of FindingId
  - count: int

### POST /findings
- **Description:** Add a finding
- **Request:** FindingCreate object
- **Response:**
  - FindingId: str

### GET /findings
- **Description:** List all findings
- **Response:** List of findings (summary)

### GET /findings/{id}
- **Description:** Get finding by ID
- **Response:** Finding object

### GET /controls
- **Description:** List all controls in the catalog
- **Response:** List of controls
