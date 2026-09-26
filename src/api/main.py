import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os
from pathlib import Path

from src.core.baseline import BaselineManager
from src.core.engine import AuditEngine
from src.core.scoring import ScoringEngine
from src.hardening.manager import HardeningManager

app = FastAPI(title="SecureAudit REST API", version="1.0.0")

# Setup templates
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# A helper function to get our baseline manager
def get_baseline_manager():
    config_path = "config/security_baseline.yaml"
    # Ensure relative to the CWD
    return BaselineManager(config_path)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    # Render the dashboard
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/audit")
async def run_audit():
    baseline_mgr = get_baseline_manager()
    engine = AuditEngine(baseline_mgr)
    raw_report = engine.run_audit("all")
    scoring = ScoringEngine(baseline_mgr)
    report = scoring.evaluate_report(raw_report)
    
    return {
        "status": "success",
        "overall_score": report.overall_score,
        "risk_level": report.risk_level.value,
        "summary": report.summary,
        "category_scores": {
            cat_id: {
                "name": cs.category_name,
                "score": cs.score,
                "passed": cs.passed_checks,
                "total": cs.total_checks
            } for cat_id, cs in report.category_scores.items()
        }
    }

@app.get("/api/score")
async def get_score():
    baseline_mgr = get_baseline_manager()
    engine = AuditEngine(baseline_mgr)
    raw_report = engine.run_audit("all")
    scoring = ScoringEngine(baseline_mgr)
    report = scoring.evaluate_report(raw_report)
    
    return {
        "status": "success",
        "overall_score": report.overall_score,
        "risk_level": report.risk_level.value,
        "summary": report.summary
    }

class HardenRequest(BaseModel):
    dry_run: bool = True

@app.post("/api/harden")
async def run_harden(req: HardenRequest):
    baseline_mgr = get_baseline_manager()
    hardener = HardeningManager(baseline_mgr)
    try:
        actions, pre_rep, post_rep = hardener.execute_hardening(dry_run=req.dry_run, auto_confirm=True)
        return {
            "status": "success",
            "actions_planned": len(actions),
            "pre_score": pre_rep.overall_score if pre_rep else None,
            "post_score": post_rep.overall_score if post_rep else None,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def run_server(host="0.0.0.0", port=8000):
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False)
