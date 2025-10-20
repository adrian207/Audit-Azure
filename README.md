# Audit-Azure

**Author:** Adrian Johnson <adrian207@gmail.com>

Audit-Azure is a modular, extensible platform for auditing Azure environments. It provides evidence collection, evaluation, and reporting for security, compliance, and operational best practices using FastAPI, SQLAlchemy, and a plugin-based evaluator system.

## Features
- FastAPI REST API for evidence, findings, controls, and evaluation
- SQLAlchemy ORM with SQLite/Postgres support
- Pluggable Python evaluators for security and compliance checks
- Control catalog for mapping controls to logic
- Pytest-based test suite
- Professional documentation in `docs/`

## Quick Start
1. **Clone the repository:**
   ```sh
   git clone https://github.com/your-org/Audit-Azure.git
   cd Audit-Azure
   ```
2. **Install dependencies:**
   ```sh
   pip install -e .
   ```
3. **Run the API:**
   ```sh
   uvicorn api.main:app --reload
   ```
4. **Run tests:**
   ```sh
   pytest
   ```

## Documentation
- See the `docs/` directory for:
  - DESIGN.md (detailed design)
  - API_REFERENCE.md
  - SETUP.md
  - EVALUATOR_GUIDE.md
  - CONTROL_CATALOG.md
  - TEST_STRATEGY.md
  - CHANGELOG.md

## Contributing
Pull requests are welcome! Please see the documentation and follow the project structure.

## License
MIT (or your preferred license)
