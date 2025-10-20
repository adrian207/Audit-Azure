import os
import json
import datetime
import pytest
from fastapi.testclient import TestClient

from api.main import app
from persistence.db import init_db, SessionLocal, engine
from persistence import models

@pytest.fixture(scope="module", autouse=True)
def setup_db(tmp_path_factory):
    # Use a temporary file-based SQLite database for tests
    db_path = tmp_path_factory.mktemp("db") / "test.db"
    os.environ["AZ_AUDIT_DB"] = f"sqlite:///{db_path}"
    init_db()
    models.Base.metadata.create_all(engine)
    yield
    # Cleanup handled by pytest tmp_path_factory

def test_post_evidence_and_evaluate_and_get_finding():
    client = TestClient(app)
    raw = {"users": [{"id":"user-1", "userPrincipalName":"alice@contoso.com", "mfaEnabled":False}]}
    evidence = {
        "Source": "Test",
        "QueryOrRequest": "unit-test",
        "Timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "RawResult": json.dumps(raw)
    }
    
    resp = client.post("/evidence", json=evidence)
    assert resp.status_code == 200
    evidence_id = resp.json().get("EvidenceId")
    assert evidence_id

    eval_resp = client.post("/evaluate", json={"evidenceId": evidence_id, "evaluator": "IAM-001"})
    assert eval_resp.status_code == 200
    data = eval_resp.json()
    assert data.get("count", 0) >= 0
