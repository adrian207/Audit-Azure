import sys
import uuid
import yaml
import datetime
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    from fastapi import FastAPI, Depends, HTTPException
    from pydantic import BaseModel
    from sqlalchemy.orm import Session
except ImportError as e:
    print(f"Error importing required packages: {e}")
    print("Please install required packages with: pip install fastapi pydantic sqlalchemy")
    sys.exit(1)

# Add parent directory to path to resolve imports
parent_dir = str(Path(__file__).parent.parent.absolute())
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from persistence.db import SessionLocal, get_db
    from persistence.models import Base, Evidence, Finding, ControlCatalog
    from evaluators import get_evaluator_by_control
except ImportError as e:
    print(f"Error importing project modules: {e}")
    print("Please check that all required modules are in the Python path")
    sys.exit(1)

def create_app():
    """Create FastAPI application."""
    app = FastAPI(title="Azure Audit API", version="0.1.0")
    return app

app = create_app()

class EvidenceCreate(BaseModel):
    """Evidence creation request."""
    Source: str
    QueryOrRequest: str
    RawResult: Optional[str] = None
    Timestamp: Optional[datetime.datetime] = None

class EvidenceRef(BaseModel):
    """Evidence reference for findings."""
    EvidenceId: str
    Source: str
    QueryOrRequest: str
    Timestamp: datetime.datetime
    RawResultHash: str

class FindingCreate(BaseModel):
    """Finding creation request."""
    ControlId: str
    Domain: str
    Severity: str
    Summary: str
    Description: Optional[str] = None
    ImpactedResources: List[dict] = []
    EvidenceRefs: List[EvidenceRef]

# In-memory stores for MVP/testing
EVIDENCE_STORE = {}
FINDINGS_STORE = {}


def compute_hash(raw: str) -> str:
    h = hashlib.sha256()
    h.update(raw.encode('utf-8'))
    return h.hexdigest()

@app.post("/evidence", response_model=dict)
async def post_evidence(item: EvidenceCreate, db: Session = Depends(get_db)):
    """Create evidence record."""
    try:
        # Generate UUID for the evidence
        eid = str(uuid.uuid4())
        
        # Process raw result and compute hash
        raw = item.RawResult
        raw_json = ""
        if raw is not None:
            try:
                if isinstance(raw, str):
                    raw_json = raw
                elif isinstance(raw, dict):
                    raw_json = yaml.dump(raw, default_flow_style=False)
                else:
                    raw_json = str(raw)
            except Exception as yaml_error:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid RawResult format: {str(yaml_error)}"
                )
        item_hash = hashlib.sha256(raw_json.encode()).hexdigest()

        # Set timestamp if not provided
        timestamp = item.Timestamp or datetime.datetime.now(datetime.UTC)

        # Create evidence record
        evidence = Evidence(
            EvidenceId=eid,
            Source=item.Source,
            QueryOrRequest=item.QueryOrRequest,
            Timestamp=timestamp,
            RawResult=raw,
            Hash=item_hash
        )

        try:
            # Persist to database
            db.add(evidence)
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Database error: {str(e)}"
            )

        # Store complete item data for quick access
        evidence_data = {
            "EvidenceId": eid,
            "Source": item.Source,
            "QueryOrRequest": item.QueryOrRequest,
            "Timestamp": timestamp.isoformat(),
            "RawResult": raw,
            "Hash": item_hash
        }
        EVIDENCE_STORE[eid] = evidence_data
        
        return {"EvidenceId": eid}
        
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid data format: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/findings")
async def post_finding(f: FindingCreate):
    fid = str(uuid.uuid4())
    obj = f.dict()
    obj["FindingId"] = fid
    obj["GeneratedAt"] = datetime.datetime.utcnow().isoformat()

    db = SessionLocal()
    try:
        fd = Finding(
            FindingId=fid,
            ControlId=obj.get("ControlId"),
            Domain=obj.get("Domain"),
            Severity=obj.get("Severity"),
            RiskScore=obj.get("RiskScore"),
            Summary=obj.get("Summary"),
            Description=obj.get("Description"),
            ImpactedResources=obj.get("ImpactedResources"),
            EvidenceRefs=obj.get("EvidenceRefs"),
            Recommendation=obj.get("Recommendation"),
            Remediation=obj.get("Remediation"),
            Status=obj.get("Status") or 'Open',
            GeneratedAt=datetime.datetime.fromisoformat(obj.get("GeneratedAt")),
        )
        db.add(fd)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": str(e)}
    finally:
        db.close()

    FINDINGS_STORE[fid] = obj
    return {"FindingId": fid}

@app.get("/findings/{fid}")
async def get_finding(fid: str):
    return FINDINGS_STORE.get(fid, {})


@app.get("/findings")
async def list_findings():
    # Return all findings from DB (lightweight)
    db = SessionLocal()
    try:
        rows = db.query(Finding).all()
        out = []
        for r in rows:
            obj = {
                "FindingId": r.FindingId,
                "ControlId": r.ControlId,
                "Domain": r.Domain,
                "Severity": r.Severity.name if getattr(r.Severity, 'name', None) else str(r.Severity),
                "Summary": r.Summary,
                "GeneratedAt": r.GeneratedAt.isoformat() if r.GeneratedAt else None,
            }
            out.append(obj)
        return out
    finally:
        db.close()


@app.post('/remediation/preview')
async def remediation_preview(body: dict):
    # body: { findingId: "..." }
    fid = body.get('findingId')
    if not fid:
        return {"error": "findingId required"}
    f = FINDINGS_STORE.get(fid)
    if not f:
        # try DB
        db = SessionLocal()
        frow = db.query(Finding).filter(Finding.FindingId == fid).first()
        db.close()
        if frow:
            f = {"FindingId": frow.FindingId, "Summary": frow.Summary, "Remediation": frow.Remediation}
    if not f:
        return {"error": "finding not found"}
    # Simulate a dry-run preview
    return {"findingId": fid, "dryRun": True, "changes": f.get('Remediation',{}), "blastRadius": len(f.get('ImpactedResources',[]))}


@app.post('/remediation/execute')
async def remediation_execute(body: dict):
    # body: { findingId: "...", approve: true }
    fid = body.get('findingId')
    if not fid:
        return {"error": "findingId required"}
    # Simulated execution
    return {"findingId": fid, "status": "Executed", "outcome": "SimulatedSuccess"}

@app.get("/controls")
async def list_controls():
    # naive: read controls/starter_catalog.yaml and return
    try:
        import yaml
        with open("controls/starter_catalog.yaml","r",encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
            return doc.get("controls", [])
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {"message":"Azure Audit API running"}


@app.post("/evaluate")
async def evaluate(payload: dict):
    """Trigger an evaluator against stored evidence.

    Body expected: { "evidenceId": "<id>", "evaluator": "identity.check_users_without_mfa" }
    """
    evidence_id = payload.get("evidenceId")
    evaluator = payload.get("evaluator")
    if not evidence_id:
        return {"error": "evidenceId required"}

    # Try DB first, then in-memory
    db = SessionLocal()
    evidence = None
    try:
        ev = db.query(Evidence).filter(Evidence.EvidenceId == evidence_id).first()
        if ev:
            evidence = {
                "EvidenceId": ev.EvidenceId,
                "Source": ev.Source,
                "QueryOrRequest": ev.QueryOrRequest,
                "Timestamp": ev.Timestamp.isoformat() if ev.Timestamp else None,
                "RawResult": ev.RawResult,
                "Hash": ev.Hash,
            }
    finally:
        db.close()
    if not evidence:
        evidence = EVIDENCE_STORE.get(evidence_id)
    if not evidence:
        return {"error": "evidence not found"}
    if not evidence:
        return {"error": "evidence not found"}

    # If evaluator is a ControlId, map to evaluator via registry
    if evaluator and not "." in evaluator:
        try:
            fn = get_evaluator_by_control(evaluator)
            if fn:
                findings = fn(evidence)
                created = []
                for f in findings or []:
                    fid = f.get("FindingId", str(uuid.uuid4()))
                    f["FindingId"] = fid
                    f["GeneratedAt"] = datetime.datetime.utcnow().isoformat()
                    # persist finding
                    db = SessionLocal()
                    try:
                        fd = Finding(
                            FindingId=fid,
                            ControlId=f.get("ControlId"),
                            Domain=f.get("Domain"),
                            Severity=f.get("Severity"),
                            RiskScore=f.get("RiskScore"),
                            Summary=f.get("Summary"),
                            Description=f.get("Description"),
                            ImpactedResources=f.get("ImpactedResources"),
                            EvidenceRefs=f.get("EvidenceRefs"),
                            Recommendation=f.get("Recommendation"),
                            Remediation=f.get("Remediation"),
                            Status=f.get("Status") or 'Open',
                            GeneratedAt=datetime.datetime.fromisoformat(f.get("GeneratedAt")),
                        )
                        db.add(fd)
                        db.commit()
                    except Exception:
                        db.rollback()
                    finally:
                        db.close()
                    FINDINGS_STORE[fid] = f
                    created.append(fid)
                return {"created": created, "count": len(created)}
        except Exception as e:
            return {"error": f"registry/evaluator failed: {e}"}

    # Resolve module + function
    func_name = None
    module_name = None
    if evaluator and "." in evaluator:
        module_name, func_name = evaluator.split(".", 1)
    elif evaluator:
        func_name = evaluator
        # try to autodiscover which domain module contains the function
        for m in ["identity","networking","data","compute","monitoring","governance","cost"]:
            try:
                mod = __import__(f"evaluators.{m}", fromlist=[func_name])
                if hasattr(mod, func_name):
                    module_name = m
                    break
            except Exception:
                continue
    else:
        return {"error": "evaluator name or controlId required"}

    try:
        if module_name:
            mod = __import__(f"evaluators.{module_name}", fromlist=[func_name])
            fn = getattr(mod, func_name)
        else:
            # fallback: try evaluators.<func_name>
            mod = __import__(f"evaluators.{func_name}", fromlist=[func_name])
            fn = getattr(mod, func_name)
    except Exception as e:
        return {"error": f"evaluator resolution failed: {e}"}

    # Call evaluator
    try:
        findings = fn(evidence)
    except Exception as e:
        return {"error": f"evaluator execution failed: {e}"}

    created = []
    for f in findings or []:
        fid = f.get("FindingId", str(uuid.uuid4()))
        f["FindingId"] = fid
        f["GeneratedAt"] = datetime.datetime.utcnow().isoformat()
        FINDINGS_STORE[fid] = f
        created.append(fid)

    return {"created": created, "count": len(created)}
