# Audit-Azure

**Author:** Adrian Johnson <adrian207@gmail.com>

Audit-Azure is a modular, extensible platform for auditing Azure environments. It provides evidence collection, evaluation, and reporting for security, compliance, and operational best practices using FastAPI, SQLAlchemy, and a plugin-based evaluator system.

## Features
- 🔐 FastAPI REST API for evidence, findings, controls, and evaluation
- 💾 SQLAlchemy ORM with SQLite/Postgres support
- 🧩 Pluggable Python evaluators for security and compliance checks
- 📋 Control catalog for mapping controls to evaluation logic
- ✅ Pytest-based test suite with robust isolation
- 🎨 Modern React UI for user-friendly interaction
- 📚 Professional documentation in `docs/`

## Architecture

The project is organized into the following directories:

- **api/** - FastAPI REST API endpoints
- **ui/** - React web interface
- **persistence/** - SQLAlchemy models and database logic
- **evaluators/** - Pluggable evaluation modules (identity, networking, data, etc.)
- **controls/** - Control catalog definitions
- **tests/** - Pytest test suite
- **docs/** - Comprehensive documentation
- **scripts/** - Utility scripts

## Quick Start

### Backend (API)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/Audit-Azure.git
   cd Audit-Azure
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or install in development mode:
   ```bash
   pip install -e .
   ```

3. **Run the API:**
   ```bash
   cd api
   uvicorn main:app --reload
   ```
   The API will be available at `http://localhost:8000`

4. **View API documentation:**
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

### Frontend (UI)

1. **Navigate to the UI directory:**
   ```bash
   cd ui
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```
   The UI will open at `http://localhost:3000`

### Running Tests

```bash
cd tests
pytest -v
```

## Using the Platform

1. **Start the backend API** (see Backend Quick Start above)
2. **Start the frontend UI** (see Frontend Quick Start above)
3. **Navigate to** `http://localhost:3000` in your browser
4. **Use the UI to:**
   - View the dashboard with audit statistics
   - Browse and create evidence items
   - View findings and filter by severity
   - Browse the control catalog
   - Run evaluations on specific controls

## API Endpoints

- `GET /evidence` - List all evidence
- `POST /evidence` - Create new evidence
- `GET /findings` - List all findings
- `GET /controls` - List all controls
- `POST /evaluate` - Run evaluation for a control

See `docs/API_REFERENCE.md` for complete API documentation.

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **DESIGN.md** - System architecture and design
- **API_REFERENCE.md** - Complete API documentation
- **SETUP.md** - Detailed setup and configuration
- **EVALUATOR_GUIDE.md** - Guide for writing custom evaluators
- **CONTROL_CATALOG.md** - Control definitions and mappings
- **TEST_STRATEGY.md** - Testing approach and guidelines
- **CHANGELOG.md** - Version history

## Project Structure

```
Audit-Azure/
├── api/              # FastAPI application
├── ui/               # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── api.js       # API client
│   │   └── App.js       # Main app
│   └── public/
├── persistence/      # Database models
├── evaluators/       # Evaluation logic
│   ├── identity.py
│   ├── networking.py
│   └── data/
├── controls/         # Control definitions
├── tests/            # Test suite
├── docs/             # Documentation
└── scripts/          # Utility scripts
```

## Development

### Adding a New Evaluator

1. Create a new module in `evaluators/`
2. Define evaluation functions that return findings
3. Register the control-to-function mapping in `evaluators/registry.py`
4. Add tests in `tests/`

See `docs/EVALUATOR_GUIDE.md` for detailed instructions.

### Database Configuration

By default, the project uses SQLite for development and testing. For production:

1. Set up a PostgreSQL database
2. Configure the connection string in `persistence/db.py`
3. Run migrations if needed

## Contributing

Pull requests are welcome! Please:

1. Follow the existing code structure
2. Add tests for new features
3. Update documentation as needed
4. Ensure all tests pass before submitting

## License

MIT License - see LICENSE file for details

## Contact

**Adrian Johnson**  
📧 adrian207@gmail.com

---

Built with ❤️ for Azure security and compliance
