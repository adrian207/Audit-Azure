import datetime
import json

from fastapi.testclient import TestClient

from api.main import app
from persistence import models
from persistence.db import engine

KEY = {"X-API-Key": "test-api-key"}


def setup_module(module):
    models.Base.metadata.create_all(engine)


def test_health_and_docs_are_public():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_protected_endpoints_require_a_valid_key():
    client = TestClient(app)
    for path in ("/controls", "/findings", "/evidence"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get(path, headers=KEY).status_code == 200


def test_cors_preflight_is_not_blocked():
    client = TestClient(app)
    resp = client.options(
        "/controls",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    assert resp.status_code == 200


def test_evidence_list_and_get():
    client = TestClient(app, headers=KEY)
    raw = {"users": [{"id": "u1", "mfaEnabled": False}]}
    created = client.post("/evidence", json={
        "Source": "Test",
        "QueryOrRequest": "list-test",
        "Timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "RawResult": json.dumps(raw),
    })
    assert created.status_code == 200
    eid = created.json()["EvidenceId"]

    listed = client.get("/evidence")
    assert listed.status_code == 200
    row = next(r for r in listed.json() if r["EvidenceId"] == eid)
    assert row["Source"] == "Test" and row["QueryOrRequest"] == "list-test"
    assert len(row["Hash"]) == 64 and "RawResult" not in row

    one = client.get(f"/evidence/{eid}")
    assert one.status_code == 200 and json.loads(one.json()["RawResult"]) == raw
    assert client.get("/evidence/does-not-exist").status_code == 404
