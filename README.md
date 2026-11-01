# Audit-Azure

Python platform that checks Azure subscriptions against Azure Security Benchmark (ASB) and CIS-aligned controls. It collects configuration through the Azure SDKs, evaluates it, and stores findings and evidence behind a FastAPI service with a React dashboard.

## What it does

- **Collects** data from Azure Resource Graph, Microsoft Defender for Cloud, Azure Policy, Azure Monitor and Entra ID (`azure_sdk/`)
- **Evaluates** controls in these areas (`evaluators/`): identity, Entra ID, network security, networking, data protection, logging and monitoring, vulnerability management, Azure Policy compliance and Secure Score
- **Control catalog** of 74 ASB controls, served by `/controls`
- **Stores** findings and evidence in SQLite by default, or PostgreSQL through `DATABASE_URL`, with Alembic migrations
- **Serves** a REST API (`/run-evaluation`, `/evaluate`, `/findings`, `/controls`, `/evidence`, `/remediation/preview`, `/remediation/execute`, `/preflight`, `/health`) with interactive docs at `/docs`, and a React dashboard built with Vite
- **Includes** PowerShell collectors and remediation scripts for MFA, NSGs and storage (`scripts/collectors/`, `scripts/remediations/`)

## Requirements

- Python 3.11 or later (tested on 3.11 and 3.13)
- Node.js 20.19+ or 22.12+ for the dashboard
- Azure CLI, or a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`). Authentication tries the service principal, then managed identity, then the Azure CLI login
- Reader on the subscriptions you assess, plus Security Reader for Defender data
- Or just Docker and Docker Compose

## Quick start

**Docker (API, UI and PostgreSQL):**

```bash
git clone https://github.com/adrian207/Audit-Azure.git
cd Audit-Azure
cp .env.docker.example .env      # set the AZURE_* values and DB_PASSWORD
docker compose up -d
```

**Local:**

```bash
./install.sh        # creates the Python venv in api/ and installs UI packages (install.bat on Windows)
az login
./run_all.sh        # API on http://localhost:8000, UI on http://localhost:3000
```

Then open `http://localhost:8000/docs` and call `POST /run-evaluation`, or use the dashboard.

## Repository layout

```
api/            FastAPI app and request schemas
azure_sdk/      Authentication and Azure service clients
evaluators/     Control evaluators and registry
controls/       ASB control definitions and starter catalog
persistence/    SQLAlchemy models and Alembic migrations
scripts/        PowerShell collectors and remediations, DB init, benchmark update checker
ui/             React dashboard (Vite)
tests/          pytest suite
docs/           Getting started, API reference, control catalog, design
```

## Documentation

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- [docs/CONTROL_CATALOG.md](docs/CONTROL_CATALOG.md)
- [docs/EVALUATOR_GUIDE.md](docs/EVALUATOR_GUIDE.md)

## Tests

```bash
cd api && source venv/bin/activate && cd ..
pytest tests
```

## License

MIT. See [LICENSE](LICENSE).

## Author

Adrian Johnson · [github.com/adrian207](https://github.com/adrian207)
