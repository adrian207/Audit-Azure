# type: ignore
"""Main API entrypoint."""
# Pyright/Pylance: this module uses dynamic imports and runtime constructs that trigger many
# static type warnings; reduce noise in the Problems pane by silencing broad reports here.
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportGeneralTypeIssues=false

import sys
import json
import uuid
import yaml
import datetime
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Any, cast
import inspect

try:
    from fastapi import FastAPI, Depends, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
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
    from persistence.db import SessionLocal, get_db, init_db
    from persistence.models import Base, Evidence, Finding, ControlCatalog
    from evaluators import get_evaluator_by_control
except ImportError as e:
    print(f"Error importing project modules: {e}")
    print("Please check that all required modules are in the Python path")
    sys.exit(1)

# Utilities that require Azure SDKs are imported lazily inside endpoints to avoid import issues in local tools

def create_app():
    """Create FastAPI application."""
    app = FastAPI(title="Azure Audit API", version="0.1.0")
    
    # Add CORS middleware to allow browser requests
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    return app

app = create_app()

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    print("Initializing database...")
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        raise

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Azure Audit Platform API", "version": "0.1.0", "status": "running"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.datetime.now(datetime.UTC).isoformat()}

@app.get("/preflight")
async def preflight_check():
    """Check Azure auth, provider registration, and Resource Graph access.

    Returns a structured report with remediation guidance.
    """
    report: Dict[str, Any] = {"status": "ok", "checks": []}

    # Gather env context
    import os
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")

    try:
        # Azure auth token checks
        import importlib
        AzureAuthManager = importlib.import_module("azure_sdk.auth").AzureAuthManager
        auth = AzureAuthManager.from_environment()
        arm_token_ok = False
        graph_token_ok = False
        arm_err = None
        graph_err = None
        try:
            _ = auth.get_access_token("https://management.azure.com/.default")
            arm_token_ok = True
        except Exception as e:
            arm_err = str(e)
        try:
            _ = auth.get_access_token("https://graph.microsoft.com/.default")
            graph_token_ok = True
        except Exception as e:
            graph_err = str(e)

        report["checks"].append({
            "name": "azure_auth_tokens",
            "arm_token": "ok" if arm_token_ok else "error",
            "graph_token": "ok" if graph_token_ok else "error",
            "details": {"arm_error": arm_err, "graph_error": graph_err},
            "remediation": (
                "Ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are set (or Azure CLI login). "
                "For Graph-based identity checks, the app needs Microsoft Graph application permissions with admin consent."
            )
        })

        # Provider registration (subscription scoped)
        providers_state = {}
        providers_err = None
        if sub_id:
            try:
                import importlib
                resource_mod = importlib.import_module("azure.mgmt.resource")
                ResourceManagementClient = getattr(resource_mod, "ResourceManagementClient")
                credential = auth.get_credential()
                rm_client = ResourceManagementClient(credential, sub_id)
                for ns in ["Microsoft.ResourceGraph", "Microsoft.Network"]:
                    try:
                        p = rm_client.providers.get(ns)
                        providers_state[ns] = getattr(p, "registration_state", "Unknown")
                    except Exception as e:
                        providers_state[ns] = f"error: {e}"
            except Exception as e:
                providers_err = str(e)
        else:
            providers_err = "AZURE_SUBSCRIPTION_ID not set"

        report["checks"].append({
            "name": "providers",
            "subscription_id": sub_id,
            "states": providers_state,
            "details": providers_err,
            "remediation": "Register required providers: az provider register --namespace Microsoft.ResourceGraph; az provider register --namespace Microsoft.Network"
        })

        # Resource Graph access
        rg_ok = False
        rg_err = None
        rg_access = None
        if sub_id:
            try:
                import importlib
                rg_module = importlib.import_module("azure_sdk.resource_graph")
                ResourceGraphClient = getattr(rg_module, "ResourceGraphClient")
                AccessDeniedError = getattr(rg_module, "AccessDeniedError")
                rg = ResourceGraphClient(auth_manager=auth)
                res = rg.query(
                    query="Resources | take 1",
                    subscriptions=[sub_id]
                )
                rg_ok = True
                rg_access = {"count": res.get("count"), "total_records": res.get("total_records")}
            except AccessDeniedError as e:
                rg_err = (
                    "Access denied. Ensure the app/service principal has Reader role on the subscription. "
                    f"Scope: /subscriptions/{sub_id}"
                )
            except Exception as e:
                rg_err = str(e)
        else:
            rg_err = "AZURE_SUBSCRIPTION_ID not set"

        report["checks"].append({
            "name": "resource_graph",
            "ok": rg_ok,
            "access": rg_access,
            "error": rg_err,
            "remediation": (
                f"Assign Reader role at /subscriptions/{sub_id} to the app (clientId: {client_id}) and retry."
                if sub_id and client_id else "Assign Reader role at subscription scope and retry."
            )
        })

        # Overall status
        any_errors = any(
            (
                (c.get("arm_token") == "error" or c.get("graph_token") == "error") if c.get("name") == "azure_auth_tokens" else False
            ) or (
                c.get("name") == "resource_graph" and not c.get("ok")
            ) for c in report["checks"]
        )
        report["status"] = "error" if any_errors else "ok"
        report["context"] = {"tenant_id": tenant_id, "client_id": client_id, "subscription_id": sub_id}
        return report
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        # Defensive parse for GeneratedAt
        gen_at = obj.get("GeneratedAt")
        if isinstance(gen_at, str):
            try:
                parsed_gen_at = datetime.datetime.fromisoformat(gen_at)
            except Exception:
                parsed_gen_at = datetime.datetime.utcnow()
        else:
            parsed_gen_at = datetime.datetime.utcnow()

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
            GeneratedAt=parsed_gen_at,
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
            gen_at = getattr(r, 'GeneratedAt', None)
            obj = {
                "FindingId": r.FindingId,
                "ControlId": r.ControlId,
                "Domain": r.Domain,
                "Severity": r.Severity.name if getattr(r.Severity, 'name', None) else str(r.Severity),
                "Summary": r.Summary,
                "GeneratedAt": gen_at.isoformat() if gen_at is not None else None,
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
    """Get all ASB controls."""
    try:
        # Load from ASB controls Python modules and combine all
        all_controls_list = []
        
        # Import and combine controls from all modules
        try:
            import importlib
            mod = importlib.import_module("controls.asb_controls")
            get_base_controls = getattr(mod, "get_all_controls")
            base_controls = get_base_controls()
            all_controls_list.extend(base_controls)
        except Exception as e:
            print(f"Warning: Could not load asb_controls: {e}")
        
        try:
            import importlib
            mod_ext = importlib.import_module("controls.asb_controls_extended")
            DOMAIN_CONTROLS = getattr(mod_ext, "DOMAIN_CONTROLS")
            for domain_list in DOMAIN_CONTROLS.values():
                all_controls_list.extend(domain_list)
        except Exception as e:
            print(f"Warning: Could not load asb_controls_extended: {e}")
        
        try:
            import importlib
            mod_comp = importlib.import_module("controls.asb_complete")
            get_all_controls_flat = getattr(mod_comp, "get_all_controls_flat")
            complete_controls = get_all_controls_flat()
            all_controls_list.extend(complete_controls)
        except Exception as e:
            print(f"Warning: Could not load asb_complete: {e}")
        
        # Convert to API format and remove duplicates
        seen = set()
        unique_controls = []
        for control in all_controls_list:
            if control.control_id not in seen:
                seen.add(control.control_id)
                unique_controls.append({
                    "ControlId": control.control_id,
                    "Title": control.title,
                    "Domain": control.domain,
                    "Severity": control.severity,
                    "Description": control.description,
                    "Implementation": control.azure_guidance,
                })
        
        if unique_controls:
            return unique_controls
        else:
            raise Exception("No controls loaded from Python modules")
            
    except Exception as e:
        print(f"Error loading controls from Python: {e}")
        # Fallback to starter catalog
        try:
            import importlib
            yaml = importlib.import_module("yaml")
            with open("controls/starter_catalog.yaml","r",encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
                return doc.get("controls", [])
        except Exception as yaml_error:
            return {"error": f"Could not load controls: {str(e)}, fallback error: {str(yaml_error)}"}

# Root endpoint already declared earlier; avoid redeclaration.


@app.post("/run-evaluation")
async def run_evaluation(payload: dict):
    """Run evaluation directly against Azure for a given control.
    
    Body expected: { "control_id": "NS-1" }
    This endpoint will:
    1. Collect evidence from Azure (requires Azure credentials in .env)
    2. Run the evaluator for that control
    3. Return findings
    """
    control_id = payload.get("control_id")
    if not control_id:
        return {"error": "control_id required", "status": "error"}
    
    try:
        # Get the evaluator function for this control
        import importlib
        get_evaluator_by_control = importlib.import_module("evaluators").get_evaluator_by_control
        evaluator = get_evaluator_by_control(control_id)
        
        if not evaluator:
            return {
                "control_id": control_id,
                "status": "error",
                "message": f"No evaluator found for control {control_id}",
                "findings": []
            }
        
        # Check if it's a class instance (has evaluate_all method) or a function
        if hasattr(evaluator, 'evaluate_all'):
            # It's an evaluator class - call evaluate_all()
            result = evaluator.evaluate_all()
            # handle coroutine or direct
            if inspect.isawaitable(result):
                findings = await result
            else:
                findings = result
        elif callable(evaluator):
            # It's a function - call it directly
            result = evaluator({})
            # Handle both sync and async functions
            if inspect.isawaitable(result):
                findings = await result
            else:
                findings = result
        else:
            return {
                "control_id": control_id,
                "status": "error",
                "message": f"Invalid evaluator type for control {control_id}",
                "findings": []
            }
        
        # Helper to normalize evaluator finding dicts to DB schema
        def normalize_finding(f: Dict[str, Any], default_control_id: str) -> Dict[str, Any]:
            # Map common alternative keys to DB column names
            ctrl_id = f.get("ControlId") or f.get("control_id") or default_control_id
            severity = f.get("Severity") or f.get("severity")
            # Safe description handling
            _desc_val = f.get("description") or ""
            _desc = str(_desc_val)
            _short = (_desc[:140] + '...') if len(_desc) > 140 else _desc
            summary = f.get("Summary") or f.get("title") or _short or "Evaluation result"
            description = f.get("Description") or f.get("description") or summary
            recommendation = f.get("Recommendation") or f.get("recommendation")
            remediation = f.get("Remediation") or f.get("remediation")
            impacted = f.get("ImpactedResources") or f.get("impacted_resources") or f.get("affected_resources")
            evidence_refs = f.get("EvidenceRefs") or f.get("evidence_refs")
            domain = f.get("Domain") or f.get("domain")

            # Best-effort derive domain from control prefix if missing
            if not domain and isinstance(ctrl_id, str) and '-' in ctrl_id:
                prefix = ctrl_id.split('-')[0].upper()
                domain_map = {
                    'NS': 'Network Security', 'IM': 'Identity Management', 'PA': 'Privileged Access',
                    'DP': 'Data Protection', 'GS': 'Governance & Strategy', 'PV': 'Posture & Vulnerability',
                    'LT': 'Logging & Threat Detection', 'AM': 'Asset Management', 'IR': 'Incident Response',
                    'ES': 'Enterprise Security', 'BR': 'Backup & Recovery', 'DS': 'DevSecOps'
                }
                domain = domain_map.get(prefix)

            # Ensure impacted resources/evidence refs are stored as JSON strings if structured
            def to_json_or_none(val):
                if val is None:
                    return None
                if isinstance(val, (list, dict)):
                    try:
                        return json.dumps(val)
                    except Exception:
                        return str(val)
                return str(val)

            normalized = {
                "ControlId": ctrl_id,
                "Domain": domain,
                "Severity": severity,
                "RiskScore": f.get("RiskScore") or f.get("risk_score"),
                "Summary": summary or "Evaluation result",
                "Description": description or summary,
                "ImpactedResources": to_json_or_none(impacted),
                "EvidenceRefs": to_json_or_none(evidence_refs),
                "Recommendation": recommendation,
                "Remediation": remediation,
                "Status": f.get("Status") or f.get("status") or 'Open',
            }
            return normalized

        # Ensure findings is a list-like iterable
                if findings is None:
                    findings = []
                elif isinstance(findings, dict):
                    findings = [findings]
                elif isinstance(findings, (list, tuple, set)):
                    findings = list(findings)
                else:
                    try:
                        findings = list(findings)
                    except Exception:
                        findings = [findings]
                # Cast to a concrete typed list for static analysis
                findings = cast(List[Dict[str, Any]], findings)

        # Store findings in database
        db = SessionLocal()
        try:
                for finding in findings:
                    finding = cast(Dict[str, Any], finding)
                    finding_id = finding.get("FindingId", str(uuid.uuid4()))
                    finding["FindingId"] = finding_id
                    finding["GeneratedAt"] = datetime.datetime.utcnow().isoformat()
                    # Normalize to DB schema
                    nf = normalize_finding(finding, control_id)
                # Create Finding record
                db_finding = Finding(
                    FindingId=finding_id,
                    ControlId=nf.get("ControlId", control_id),
                    Domain=nf.get("Domain"),
                    Severity=nf.get("Severity"),
                    RiskScore=nf.get("RiskScore"),
                    Summary=nf.get("Summary"),
                    Description=nf.get("Description"),
                    ImpactedResources=nf.get("ImpactedResources"),
                    EvidenceRefs=nf.get("EvidenceRefs"),
                    Recommendation=nf.get("Recommendation"),
                    Remediation=nf.get("Remediation"),
                    Status=nf.get("Status", "Open"),
                    GeneratedAt=datetime.datetime.utcnow()
                )
                db.add(db_finding)
            
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error storing findings: {e}")
        finally:
            db.close()
        
        return {
            "control_id": control_id,
            "status": "success",
            "message": f"Evaluation completed: {len(findings) if hasattr(findings, '__len__') else 0} finding(s) generated",
            "findings": findings
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "control_id": control_id,
            "status": "error",
            "message": str(e),
            "findings": []
        }


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
            ts = getattr(ev, 'Timestamp', None)
            evidence = {
                "EvidenceId": ev.EvidenceId,
                "Source": ev.Source,
                "QueryOrRequest": ev.QueryOrRequest,
                "Timestamp": ts.isoformat() if ts is not None else None,
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
                # Handle evaluator being a class instance or a callable
                if hasattr(fn, 'evaluate_all'):
                    res = fn.evaluate_all()
                    if inspect.isawaitable(res):
                        findings = await res
                    else:
                        findings = res
                elif callable(fn):
                    res = fn(evidence)
                    if inspect.isawaitable(res):
                        findings = await res
                    else:
                        findings = res
                else:
                    return {"error": "evaluator is not callable or a class with evaluate_all"}

                # Coerce findings to list
                if findings is None:
                    findings = []
                elif isinstance(findings, dict):
                    findings = [findings]
                elif not isinstance(findings, (list, tuple, set)):
                    try:
                        findings = list(findings)
                    except Exception:
                        findings = [findings]

                created = []
                for f in findings or []:
                    fid = f.get("FindingId", str(uuid.uuid4()))
                    f["FindingId"] = fid
                    f["GeneratedAt"] = datetime.datetime.utcnow().isoformat()
                    # persist finding
                    db = SessionLocal()
                    try:
                        # Defensive parse
                        gen_at = f.get("GeneratedAt")
                        if isinstance(gen_at, str):
                            try:
                                parsed = datetime.datetime.fromisoformat(gen_at)
                            except Exception:
                                parsed = datetime.datetime.utcnow()
                        else:
                            parsed = datetime.datetime.utcnow()

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
                            GeneratedAt=parsed,
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
