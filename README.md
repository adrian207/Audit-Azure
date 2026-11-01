# Audit-Azure

Python platform that checks Azure subscriptions against Azure Security Benchmark (ASB) and CIS-aligned controls. It collects configuration through the Azure SDKs, evaluates it, and stores findings and evidence behind a FastAPI service with a React dashboard.

## What it does

- **Collects** data from Azure Resource Graph, Microsoft Defender for Cloud, Azure Policy, Azure Monitor and Entra ID (`azure_sdk/`)
- **Evaluates** controls in these areas (`evaluators/`): identity, Entra ID, network security, networking, data protection, logging and monitoring, vulnerability management, Azure Policy compliance and Secure Score
- **Control catalog** of 74 ASB controls, served by `/controls`
- **Stores** findings and evidence in SQLite by default, or PostgreSQL through `DATABASE_URL`, with Alembic migrations
- **Serves** a REST API (`/run-evaluation`, `/evaluate`, `/findings`, `/controls`, `/evidence`, `/remediation/preview`, `/remediation/execute`, `/preflight`, `/health`) protected by an API key, with interactive docs at `/docs`, and a React dashboard built with Vite
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
cp .env.docker.example .env      # set the AZURE_* values, DB_PASSWORD and API_MASTER_KEY (openssl rand -hex 32)
docker compose up -d
```

**Local:**

```bash
./install.sh        # creates the Python venv, installs UI packages and writes .env with a new API key (install.bat on Windows)
az login
./run_all.sh        # API on http://localhost:8000, UI on http://localhost:3000
```

Then use the dashboard, or open `http://localhost:8000/docs`, click **Authorize**, enter the key and call `POST /run-evaluation`.

## Authentication

Every API endpoint except `/health` and the docs requires an `X-API-Key` header matching `API_MASTER_KEY`. If the key isn't set, the API returns 503 rather than running open (`AUTH_DISABLED=true` turns this off for local experiments). Requests are also rate-limited per key (`RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` seconds).

The dashboard never sees the key: its server forwards `/api` requests to the API and adds the header (`ui/vite.config.js`).

```bash
curl -H "X-API-Key: $API_MASTER_KEY" http://localhost:8000/findings
```

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
