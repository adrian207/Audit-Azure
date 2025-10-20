from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
import os
from pathlib import Path
import sys
import yaml

# Add parent directory to path to resolve imports
parent_dir = str(Path(__file__).parent.parent.absolute())
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from persistence.models import Base

# Use shared in-memory SQLite for tests if requested
if os.environ.get('AZ_AUDIT_DB', '').startswith('sqlite:///:memory:'):
    DB_PATH = 'sqlite:///:memory:?cache=shared'
else:
    DB_PATH = os.environ.get('AZ_AUDIT_DB', 'sqlite:///./audit.db')

engine = create_engine(DB_PATH, connect_args={"check_same_thread": False} if DB_PATH.startswith('sqlite') else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database schema and seed control catalog."""
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # Seed control catalog if empty
    try:
        from .models import ControlCatalog
        Session = SessionLocal()
        count = Session.query(ControlCatalog).count()
        if count == 0:
            # Create minimal catalog for tests if real one not found
            controls = [
                {
                    'ControlId': 'IAM-001',
                    'Title': 'MFA Enforcement',
                    'Domain': 'Identity',
                    'Evaluator': 'check_users_without_mfa',
                    'Recommendation': 'Enable MFA',
                    'RemediationType': 'Policy'
                }
            ]
            # Try loading full catalog
            try:
                with open('controls/starter_catalog.yaml','r',encoding='utf-8') as fh:
                    doc = yaml.safe_load(fh)
                    controls = doc.get('controls', controls)
            except:
                pass

            for c in controls:
                cc = ControlCatalog(
                    ControlId=c.get('ControlId'),
                    Title=c.get('Title'),
                    Domain=c.get('Domain'),
                    BenchmarkMappings=c.get('BenchmarkMappings'),
                    Evaluator=c.get('Evaluator'),
                    SeverityRules=None,
                    Recommendation=c.get('Recommendation'),
                    RemediationType=c.get('RemediationType')
                )
                Session.add(cc)
            Session.commit()
    except Exception as e:
        print(f"Warning: Failed to seed control catalog: {e}")
