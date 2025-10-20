# Audit-Azure: Detailed Design Document

**Project:** Audit-Azure  
**Author:** Adrian Johnson <adrian207@gmail.com>  
**Date:** 2025-10-20

---

## 1. Overview
Audit-Azure is a modular, extensible platform for auditing Azure environments. It provides evidence collection, evaluation, and reporting for security, compliance, and operational best practices using FastAPI, SQLAlchemy, and a plugin-based evaluator system.

## 2. Architecture
- **API Layer:** FastAPI app exposes REST endpoints for evidence, findings, controls, and evaluation.
- **Persistence Layer:** SQLAlchemy models and SQLite/Postgres for storing evidence, findings, and reports.
- **Evaluators:** Pluggable Python modules for domain-specific checks (Identity, Networking, Data, etc.).
- **Control Catalog:** YAML/DB mapping of controls to evaluator logic.
- **UI (optional):** React/Next.js frontend for visualization (not covered in this doc).

### 2.1 Component Diagram
- api/
- persistence/
- evaluators/
- controls/
- tests/
- docs/

## 3. Data Model
- **Evidence:** Source, Query, Timestamp, RawResult, Hash
- **Finding:** ControlId, Domain, Severity, Summary, ImpactedResources, EvidenceRefs, Status, GeneratedAt
- **ControlCatalog:** ControlId, Title, Domain, Evaluator, SeverityRules, Recommendation

## 4. API Endpoints
- `POST /evidence` — Submit evidence
- `POST /evaluate` — Run evaluator on evidence
- `POST /findings` — Add finding
- `GET /findings` — List findings
- `GET /findings/{id}` — Get finding
- `GET /controls` — List controls

## 5. Evaluator System
- Registry maps ControlId to Python function
- Each evaluator returns a list of finding dicts
- Extensible: add new modules/functions for new domains

## 6. Database
- SQLAlchemy ORM
- SQLite for dev/tests, Postgres for prod
- Alembic for migrations (future)

## 7. Security
- Input validation via Pydantic
- ORM prevents SQL injection
- AuthN/AuthZ (future)

## 8. Testing
- Pytest for unit/integration tests
- Temporary SQLite DB for isolation
- Test coverage for API, evaluators, and persistence

## 9. Deployment
- Dockerfile (future)
- Azure App Service/Container Apps (future)

## 10. Supporting Documents
- [API Reference](./API_REFERENCE.md)
- [Setup Guide](./SETUP.md)
- [Evaluator Authoring Guide](./EVALUATOR_GUIDE.md)
- [Control Catalog Format](./CONTROL_CATALOG.md)
- [Test Strategy](./TEST_STRATEGY.md)
- [Changelog](./CHANGELOG.md)

---

## 11. Author
Adrian Johnson <adrian207@gmail.com>




