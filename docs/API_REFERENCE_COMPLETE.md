# Azure Audit Platform - Complete API Reference

## Overview

This document provides a comprehensive reference for all API endpoints in the Azure Audit Platform. The platform includes **60+ endpoints** across **8 major enterprise systems**.

## Base URL
```
http://localhost:8000
```

## Authentication

Most endpoints require authentication via JWT token. Include the token in the Authorization header:

```bash
Authorization: Bearer YOUR_JWT_TOKEN
```

---

## 1. Core Endpoints

### Root Endpoint
```http
GET /
```
**Description**: Root endpoint with basic information  
**Authentication**: None  
**Response**:
```json
{
  "message": "Azure Audit Platform API",
  "version": "0.1.0",
  "status": "running"
}
```

### Health Check
```http
GET /health
```
**Description**: Application health status  
**Authentication**: None  
**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Azure Connectivity Check
```http
GET /preflight
```
**Description**: Check Azure authentication and resource graph access  
**Authentication**: None  
**Response**:
```json
{
  "azure_connected": true,
  "resource_graph_accessible": true,
  "subscription_id": "sub-123"
}
```

---

## 2. Evidence & Findings

### Create Evidence
```http
POST /evidence
```
**Description**: Create new evidence for evaluation  
**Authentication**: Required  
**Request Body**:
```json
{
  "Source": "Azure Resource Graph",
  "QueryOrRequest": "Resources | where type == 'microsoft.storage/storageaccounts'",
  "RawResult": "{\"resources\": [...]}",
  "Timestamp": "2024-01-01T00:00:00Z"
}
```
**Response**:
```json
{
  "EvidenceId": "evidence-123",
  "Source": "Azure Resource Graph",
  "Timestamp": "2024-01-01T00:00:00Z"
}
```

### List Evidence
```http
GET /evidence
```
**Description**: Get all evidence items  
**Authentication**: Required  
**Query Parameters**:
- `limit` (optional): Number of items to return (default: 100)
- `offset` (optional): Number of items to skip (default: 0)

### List Findings
```http
GET /findings
```
**Description**: Get all security findings  
**Authentication**: Required  
**Query Parameters**:
- `severity` (optional): Filter by severity (Critical, High, Medium, Low)
- `status` (optional): Filter by status (Open, InProgress, Resolved, Suppressed)
- `domain` (optional): Filter by domain
- `limit` (optional): Number of items to return (default: 100)
- `offset` (optional): Number of items to skip (default: 0)

### Get Specific Finding
```http
GET /findings/{finding_id}
```
**Description**: Get detailed information about a specific finding  
**Authentication**: Required  
**Path Parameters**:
- `finding_id`: Unique identifier of the finding

### Evaluate Evidence
```http
POST /evaluate
```
**Description**: Evaluate evidence against a specific control  
**Authentication**: Required  
**Request Body**:
```json
{
  "evidenceId": "evidence-123",
  "evaluator": "IM-2"
}
```

### Run Evaluation
```http
POST /run-evaluation
```
**Description**: Run evaluation against Azure resources  
**Authentication**: Required  
**Request Body**:
```json
{
  "control_id": "IM-2"
}
```

---

## 3. Controls

### List All Controls
```http
GET /controls
```
**Description**: Get all available security controls  
**Authentication**: Required  
**Response**: Array of control objects with metadata

### Get Control Templates
```http
GET /custom-controls/templates
```
**Description**: Get available control templates for custom control creation  
**Authentication**: Required  
**Response**:
```json
[
  {
    "name": "Storage Account Public Access",
    "description": "Check if storage accounts allow public access",
    "category": "data",
    "control_type": "automated",
    "parameters": [...],
    "preview_query": "Resources | where type == 'microsoft.storage/storageaccounts'..."
  }
]
```

### Create Custom Control
```http
POST /custom-controls
```
**Description**: Create a new custom security control  
**Authentication**: Required  
**Request Body**:
```json
{
  "title": "Custom Control Title",
  "description": "Control description",
  "category": "data",
  "control_type": "automated",
  "severity": "High",
  "created_by": "user123",
  "query": "Resources | where...",
  "evaluator_code": "def evaluate_custom_control(evidence): ...",
  "parameters": {...},
  "remediation_steps": "Step-by-step remediation",
  "remediation_type": "manual",
  "remediation_script": "az storage account update...",
  "framework_mappings": {...},
  "tags": ["custom", "storage"],
  "documentation": "Additional documentation"
}
```

### Create from Template
```http
POST /custom-controls/from-template
```
**Description**: Create custom control from predefined template  
**Authentication**: Required  
**Request Body**:
```json
{
  "template_name": "Storage Account Public Access",
  "customizations": {
    "title": "Custom Storage Check",
    "severity": "High",
    "risk_score": 8
  },
  "created_by": "user123"
}
```

### List Custom Controls
```http
GET /custom-controls
```
**Description**: Get all custom controls with filtering  
**Authentication**: Required  
**Query Parameters**:
- `created_by` (optional): Filter by creator
- `category` (optional): Filter by category
- `is_active` (optional): Filter by active status (default: true)

### Get Custom Control
```http
GET /custom-controls/{control_id}
```
**Description**: Get specific custom control details  
**Authentication**: Required

### Update Custom Control
```http
PUT /custom-controls/{control_id}
```
**Description**: Update existing custom control  
**Authentication**: Required  
**Request Body**: Partial update object

### Delete Custom Control
```http
DELETE /custom-controls/{control_id}
```
**Description**: Delete custom control  
**Authentication**: Required

### Execute Custom Control
```http
POST /custom-controls/{control_id}/execute
```
**Description**: Execute custom control evaluator  
**Authentication**: Required  
**Request Body**:
```json
{
  "evidence": {
    "RawResult": [...]
  }
}
```

---

## 4. Remediation

### Get Remediation Preview
```http
POST /remediation/preview
```
**Description**: Get preview of remediation actions  
**Authentication**: Required  
**Request Body**:
```json
{
  "findingId": "finding-123"
}
```
**Response**:
```json
{
  "findingId": "finding-123",
  "dryRun": true,
  "preview": {
    "status": "completed",
    "details": {
      "remediated_resources": [...]
    }
  },
  "blastRadius": 5
}
```

### Execute Remediation
```http
POST /remediation/execute
```
**Description**: Execute remediation actions  
**Authentication**: Required  
**Request Body**:
```json
{
  "findingId": "finding-123",
  "approve": true
}
```

---

## 5. Scheduling

### List Schedules
```http
GET /schedules
```
**Description**: Get all audit schedules  
**Authentication**: Required

### Create Schedule
```http
POST /schedules
```
**Description**: Create new audit schedule  
**Authentication**: Required  
**Request Body**:
```json
{
  "name": "Daily Critical Controls",
  "description": "Daily audit of critical security controls",
  "frequency": "daily",
  "controls": ["IM-2", "IM-3", "NS-1", "NS-2", "DP-1"],
  "subscriptions": ["sub-123"],
  "enabled": true
}
```

### Get Schedule
```http
GET /schedules/{schedule_id}
```
**Description**: Get specific schedule details  
**Authentication**: Required

### Update Schedule
```http
PUT /schedules/{schedule_id}
```
**Description**: Update existing schedule  
**Authentication**: Required  
**Request Body**: Partial update object

### Delete Schedule
```http
DELETE /schedules/{schedule_id}
```
**Description**: Delete schedule  
**Authentication**: Required

### Execute Schedule
```http
POST /schedules/{schedule_id}/execute
```
**Description**: Execute schedule immediately  
**Authentication**: Required

### Get Audit History
```http
GET /audit-history
```
**Description**: Get audit execution history  
**Authentication**: Required  
**Query Parameters**:
- `limit` (optional): Number of items to return (default: 50)

### Get Audit Status
```http
GET /audit-status/{audit_id}
```
**Description**: Get status of specific audit run  
**Authentication**: Required

---

## 6. Compliance & Reporting

### Get Report Templates
```http
GET /reports/templates
```
**Description**: Get available compliance report templates  
**Authentication**: Required  
**Response**:
```json
[
  {
    "framework": "asb",
    "name": "Azure Security Benchmark",
    "version": "v3.0",
    "description": "Compliance report for Azure Security Benchmark",
    "available_formats": ["json", "pdf", "excel", "html"]
  }
]
```

### Generate Compliance Report
```http
POST /reports/generate
```
**Description**: Generate compliance report  
**Authentication**: Required  
**Request Body**:
```json
{
  "framework": "asb",
  "format": "pdf",
  "scope": {
    "time_range": {
      "start_date": "2024-01-01",
      "end_date": "2024-12-31"
    },
    "controls": ["IM-2", "IM-3"]
  },
  "generated_by": "user123"
}
```

### Get Report
```http
GET /reports/{report_id}
```
**Description**: Get specific compliance report  
**Authentication**: Required

### Export Report
```http
GET /reports/{report_id}/export
```
**Description**: Export report in specified format  
**Authentication**: Required  
**Query Parameters**:
- `format` (optional): Export format (json, pdf, excel, html) (default: json)

### Get Compliance Dashboard
```http
GET /compliance/dashboard
```
**Description**: Get compliance dashboard data  
**Authentication**: Required  
**Response**:
```json
{
  "compliance_score": 85.5,
  "total_findings": 150,
  "open_findings": 25,
  "resolved_findings": 125,
  "severity_breakdown": {
    "Critical": 5,
    "High": 10,
    "Medium": 8,
    "Low": 2
  },
  "domain_breakdown": {
    "Identity Management": 8,
    "Network Security": 12,
    "Data Protection": 5
  },
  "total_controls": 74,
  "last_updated": "2024-01-01T00:00:00Z"
}
```

---

## 7. Executive Dashboard

### Get Executive Summary
```http
GET /executive/summary
```
**Description**: Get executive summary dashboard data  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 30)

### Get Security KPIs
```http
GET /executive/kpis
```
**Description**: Get security key performance indicators  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 30)

### Get Risk Metrics
```http
GET /executive/risk-metrics
```
**Description**: Get risk assessment metrics  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 30)

### Get Trend Data
```http
GET /executive/trends
```
**Description**: Get trend data for charts  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 30)

### Get Top Risks
```http
GET /executive/top-risks
```
**Description**: Get top security risks  
**Authentication**: Required  
**Query Parameters**:
- `limit` (optional): Number of risks to return (default: 10)

### Get Compliance by Domain
```http
GET /executive/compliance-by-domain
```
**Description**: Get compliance breakdown by domain  
**Authentication**: Required

---

## 8. Authentication

### User Login
```http
POST /auth/login
```
**Description**: Authenticate user and return access token  
**Authentication**: None  
**Request Body**:
```json
{
  "username": "user@company.com",
  "password": "secure_password"
}
```
**Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "user": {
    "user_id": "user-123",
    "username": "user@company.com",
    "email": "user@company.com",
    "role": "auditor"
  }
}
```

### User Registration
```http
POST /auth/register
```
**Description**: Register new user  
**Authentication**: None  
**Request Body**:
```json
{
  "username": "newuser",
  "email": "user@company.com",
  "password": "secure_password",
  "role": "viewer"
}
```

### Get Current User Info
```http
GET /auth/me
```
**Description**: Get current authenticated user information  
**Authentication**: Required

### User Logout
```http
POST /auth/logout
```
**Description**: Logout current user  
**Authentication**: Required

### Get User Permissions
```http
GET /auth/permissions
```
**Description**: Get current user's permissions  
**Authentication**: Required  
**Response**:
```json
{
  "role": "auditor",
  "permissions": [
    "view_findings",
    "create_findings",
    "update_findings",
    "view_reports",
    "create_reports",
    "manage_schedules",
    "view_audit_history"
  ]
}
```

---

## 9. Audit & Logging

### Get Audit Logs
```http
GET /audit/logs
```
**Description**: Get audit logs with filtering  
**Authentication**: Required  
**Query Parameters**:
- `start_date` (optional): Start date filter (ISO format)
- `end_date` (optional): End date filter (ISO format)
- `user_id` (optional): Filter by user ID
- `activity_type` (optional): Filter by activity type
- `resource_type` (optional): Filter by resource type
- `limit` (optional): Number of items to return (default: 100)
- `offset` (optional): Number of items to skip (default: 0)

### Get Security Events
```http
GET /audit/security-events
```
**Description**: Get security events with filtering  
**Authentication**: Required  
**Query Parameters**:
- `start_date` (optional): Start date filter (ISO format)
- `end_date` (optional): End date filter (ISO format)
- `severity` (optional): Filter by severity
- `event_type` (optional): Filter by event type
- `limit` (optional): Number of items to return (default: 100)
- `offset` (optional): Number of items to skip (default: 0)

### Get Audit Summary
```http
GET /audit/summary
```
**Description**: Get audit activity summary  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 30)

---

## 10. Analytics

### Get Compliance Trend
```http
GET /analytics/compliance-trend
```
**Description**: Get compliance score trend analysis  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 90)
- `granularity` (optional): Data granularity (daily, weekly, monthly) (default: daily)

### Get Finding Trends
```http
GET /analytics/finding-trends
```
**Description**: Get finding trends by severity and domain  
**Authentication**: Required  
**Query Parameters**:
- `days` (optional): Period in days (default: 90)
- `granularity` (optional): Data granularity (daily, weekly, monthly) (default: daily)

### Get Resource Risk Score
```http
GET /analytics/risk-score/{resource_id}
```
**Description**: Get risk score for specific resource  
**Authentication**: Required

### Get Top Risk Resources
```http
GET /analytics/top-risk-resources
```
**Description**: Get top risk resources across environment  
**Authentication**: Required  
**Query Parameters**:
- `limit` (optional): Number of resources to return (default: 20)

### Get Risk Summary
```http
GET /analytics/risk-summary
```
**Description**: Get overall risk summary  
**Authentication**: Required

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "error": "Error message description",
  "details": "Additional error details (optional)",
  "code": "ERROR_CODE (optional)"
}
```

### Common HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required or invalid
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation error
- `500 Internal Server Error`: Server error

---

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Authentication endpoints**: 10 requests per minute per IP
- **General endpoints**: 100 requests per minute per user
- **Heavy operations** (reports, analytics): 10 requests per minute per user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

---

## Pagination

Endpoints that return lists support pagination:

**Query Parameters**:
- `limit`: Number of items per page (default: 100, max: 1000)
- `offset`: Number of items to skip (default: 0)

**Response Headers**:
```
X-Total-Count: 1500
X-Page-Size: 100
X-Page-Offset: 0
```

---

## Data Formats

### Dates and Times
All dates and times are in ISO 8601 format:
```
2024-01-01T00:00:00Z
```

### Severity Levels
- `Critical`: Highest severity
- `High`: High severity
- `Medium`: Medium severity
- `Low`: Lowest severity

### Finding Status
- `Open`: New finding, not yet addressed
- `InProgress`: Finding is being worked on
- `Resolved`: Finding has been fixed
- `Suppressed`: Finding has been suppressed

### User Roles
- `admin`: Full system access
- `auditor`: Audit and reporting capabilities
- `remediator`: Remediation capabilities
- `viewer`: Read-only access

---

## SDKs and Libraries

### Python
```python
import requests

# Set up client
base_url = "http://localhost:8000"
token = "your_jwt_token"
headers = {"Authorization": f"Bearer {token}"}

# Example API call
response = requests.get(f"{base_url}/findings", headers=headers)
findings = response.json()
```

### JavaScript/Node.js
```javascript
const axios = require('axios');

// Set up client
const client = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// Example API call
const response = await client.get('/findings');
const findings = response.data;
```

### PowerShell
```powershell
# Set up headers
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Example API call
$response = Invoke-RestMethod -Uri "http://localhost:8000/findings" -Headers $headers
```

---

## Webhooks

The platform supports webhooks for real-time notifications:

### Webhook Events
- `finding.created`: New finding created
- `finding.resolved`: Finding resolved
- `audit.completed`: Audit run completed
- `remediation.executed`: Remediation executed

### Webhook Payload
```json
{
  "event": "finding.created",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "finding_id": "finding-123",
    "severity": "High",
    "summary": "Security finding description"
  }
}
```

---

## Conclusion

This API reference covers all 60+ endpoints across the 8 major enterprise systems. For interactive API documentation, visit `/docs` when the application is running.

For additional support or questions, please refer to the main documentation or contact your system administrator.
