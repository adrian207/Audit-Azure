# Audit-Azure Setup Guide

**Author:** Adrian Johnson <adrian207@gmail.com>

## Prerequisites
- Python 3.10+
- pip
- Node.js (for UI, optional)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/your-org/Audit-Azure.git
   cd Audit-Azure
   ```
2. Install Python dependencies:
   ```sh
   pip install -e .
   ```
3. (Optional) Install UI dependencies:
   ```sh
   cd ui
   npm install
   ```

## Running the API
```sh
uvicorn api.main:app --reload
```

## Running Tests
```sh
pytest
```

## Configuration
- Set `AZ_AUDIT_DB` env var to change DB (default: SQLite)
- Edit `controls/starter_catalog.yaml` to customize controls
