# Audit-Azure Test Strategy

**Author:** Adrian Johnson <adrian207@gmail.com>

## Overview
Testing ensures reliability, correctness, and maintainability of the Audit-Azure platform.

## Types of Tests
- **Unit Tests:** Test individual functions (evaluators, models, utils)
- **Integration Tests:** Test API endpoints and DB interactions
- **End-to-End Tests:** (Future) Simulate real user flows

## Tools
- Pytest
- FastAPI TestClient
- Temporary SQLite DB for isolation

## Coverage
- All API endpoints
- Evaluator logic
- Persistence layer

## Running Tests
```sh
pytest
```

## CI/CD
- (Future) GitHub Actions for automated test runs
