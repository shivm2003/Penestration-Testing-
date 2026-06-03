from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
import models, schemas
from database import engine, get_db, Base
from agents.recon import start_recon
from agents.scanner import start_scan
from agents.validator import start_validate
from agents.analyzer import start_analyze
from agents.report import generate_report
from agents.orchestrator import start_mythos, start_mythos_task
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB on startup
    async with engine.begin() as conn:
        # await conn.run_sync(Base.metadata.drop_all) # DANGER: DO NOT DROP IN PRODUCTION/HISTORY MODE
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(title="VAPT Agent Orchestrator", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/targets", response_model=schemas.TargetResponse)
async def create_target(target: schemas.TargetCreate, db: AsyncSession = Depends(get_db)):
    db_target = models.Target(url=target.url)
    db.add(db_target)
    await db.commit()
    await db.refresh(db_target)
    return db_target

@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()
    return {"message": "Scan history deleted successfully"}

# Tracking stopped scans
STOPPED_TARGETS = set()

@app.post("/api/targets/{target_id}/stop")
async def stop_scanning(target_id: int):
    STOPPED_TARGETS.add(target_id)
    return {"message": "Stop command sent to agents"}

@app.get("/api/targets", response_model=list[schemas.TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target))
    return result.scalars().all()

@app.post("/api/targets/{target_id}/start_mythos")
async def trigger_mythos(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # 1. Try to queue via Celery (Distributed Mode)
    try:
        from core.celery_app import celery_app
        # Check if we can reach the broker (Redis)
        with celery_app.connection_or_acquire() as conn:
            conn.ensure_connection(max_retries=1)
            start_mythos_task.delay(target_id)
            print(f"[ORCHESTRATOR] Task queued in distributed Celery cluster for ID: {target_id}")
            return {"message": "Mythos Orchestrator task queued in distributed cluster"}
    except Exception as e:
        # 2. Fallback to Local BackgroundTasks if Redis is down (Standalone Mode)
        print(f"[ORCHESTRATOR] Distributed mode unavailable ({e}). Falling back to Local Standalone Mode.")
        
        async def bg_mythos(tid: int):
            from database import AsyncSessionLocal
            from agents.orchestrator import start_mythos
            async with AsyncSessionLocal() as session:
                await start_mythos(tid, session)
        
        background_tasks.add_task(bg_mythos, target_id)
        return {"message": "Mythos Orchestrator started in Local Standalone Mode (Redis Down)"}

@app.post("/api/targets/{target_id}/recon")
async def trigger_recon(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # We pass a new session generator for background tasks normally, 
    # but since this is async, we need a separate session lifecycle.
    from database import AsyncSessionLocal
    async def bg_recon(tid: int):
        async with AsyncSessionLocal() as session:
            await start_recon(tid, session)

    background_tasks.add_task(bg_recon, target_id)
    return {"message": "Recon started in background"}

@app.post("/api/targets/{target_id}/scan")
async def trigger_scan(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from database import AsyncSessionLocal
    async def bg_scan(tid: int):
        async with AsyncSessionLocal() as session:
            await start_scan(tid, session)

    background_tasks.add_task(bg_scan, target_id)
    return {"message": "Scanner started in background"}

@app.post("/api/targets/{target_id}/validate")
async def trigger_validate(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from database import AsyncSessionLocal
    async def bg_validate(tid: int):
        async with AsyncSessionLocal() as session:
            await start_validate(tid, session)

    background_tasks.add_task(bg_validate, target_id)
    return {"message": "Validator started in background"}

@app.post("/api/targets/{target_id}/retest")
async def trigger_retest(target_id: int, vuln_data: list[dict], background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    # This endpoint takes a list of {vuln_type, path} to re-verify
    from database import AsyncSessionLocal
    from agents.validator import ValidatorAgent
    from models import Target, ReconData, Vulnerability
    
    async def bg_retest(tid: int, data: list):
        async with AsyncSessionLocal() as session:
            # For each item, try to find a matching ReconData and create a temp Vulnerability for validation
            for item in data:
                # 1. Find ReconData
                res = await session.execute(
                    select(models.ReconData).where(
                        models.ReconData.target_id == tid,
                        models.ReconData.path == item['path']
                    )
                )
                recon = res.scalar_one_or_none()
                if recon:
                    # 2. Trigger Validator on this path specifically (heuristic)
                    print(f"[RETEST] Validating {item['vuln_type']} on {item['path']}")
                    # (Simplified for now: we just log it and run the validator agent on all pending)
            
            # Run the normal validator loop which checks confirmed vs rejected
            await start_validate(tid, session)

    background_tasks.add_task(bg_retest, target_id, vuln_data)
    return {"message": "Targeted Retest initiated"}

@app.post("/api/targets/{target_id}/analyze")
async def trigger_analyze(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from database import AsyncSessionLocal
    async def bg_analyze(tid: int):
        async with AsyncSessionLocal() as session:
            await start_analyze(tid, session)

    background_tasks.add_task(bg_analyze, target_id)
    return {"message": "Analyzer started in background"}

@app.get("/api/targets/{target_id}/report/download")
async def download_report(target_id: int, db: AsyncSession = Depends(get_db)):
    # Simple JSON download
    report = await generate_report(target_id, db)
    return report

@app.get("/api/vulnerabilities/{vuln_id}", response_model=schemas.VulnerabilityResponse)
async def get_vulnerability(vuln_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Vulnerability).where(models.Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln

@app.post("/api/vulnerabilities/{vuln_id}/advanced_analyze")
async def trigger_advanced_analyze(vuln_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Vulnerability).where(models.Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from agents.analyzer import generate_advanced_report
    from database import AsyncSessionLocal

    async def bg_advanced(vid: int):
        async with AsyncSessionLocal() as session:
            await generate_advanced_report(vid, session)

    background_tasks.add_task(bg_advanced, vuln_id)
    return {"message": "Advanced AI report generation started", "status": "generating"}

@app.get("/api/targets/{target_id}/code_reviews", response_model=list[schemas.CodeReviewResponse])
async def get_code_reviews(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.CodeReview).where(models.CodeReview.target_id == target_id))
    reviews = result.scalars().all()
    return reviews

@app.get("/api/ai/status")
async def get_ai_status():
    import os
    import httpx
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(base_url)
            if resp.status_code == 200:
                return {"status": "online", "model": "gemma:2b"}
    except:
        pass
    return {"status": "offline", "model": "gemma:2b"}

@app.get("/api/ai/reports")
async def get_ai_reports(db: AsyncSession = Depends(get_db)):
    # Get recent analyzed vulns and code reviews
    v_result = await db.execute(select(models.Vulnerability).where(models.Vulnerability.status == "analyzed").limit(10))
    cr_result = await db.execute(select(models.CodeReview).limit(10))
    
    return {
        "vulnerabilities": v_result.scalars().all(),
        "code_reviews": cr_result.scalars().all()
    }

@app.get("/api/targets/{target_id}/chains", response_model=list[schemas.ChainFindingResponse])
async def get_chains(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.ChainFinding).where(models.ChainFinding.target_id == target_id))
    chains = result.scalars().all()
    return chains

@app.get("/api/targets/{target_id}/brute_findings", response_model=list[schemas.BruteFindingResponse])
async def get_brute_findings(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.BruteFinding).where(models.BruteFinding.target_id == target_id))
    findings = result.scalars().all()
    return findings

@app.get("/api/map-data")
async def get_map_data():
    # Placeholder for geographical intelligence map
    return {"type": "FeatureCollection", "features": []}

@app.get("/api/reports")
async def list_reports(db: AsyncSession = Depends(get_db)):
    # Alias for AI reports summary
    v_result = await db.execute(select(models.Vulnerability).where(models.Vulnerability.ai_report_status == "completed"))
    return v_result.scalars().all()

@app.get("/.well-known/appspecific/com.chrome.devtools.json")
async def chrome_devtools_json():
    return {}


@app.get("/api/targets/{target_id}/report", response_model=schemas.TargetReport)
async def get_target_report(target_id: int, db: AsyncSession = Depends(get_db)):
    # Load target with recon_data and vulnerabilities using eager loading
    result = await db.execute(
        select(models.Target)
        .options(selectinload(models.Target.recon_data), selectinload(models.Target.vulnerabilities))
        .where(models.Target.id == target_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@app.get("/api/targets/{target_id}/logs", response_model=list[schemas.LogResponse])
async def get_logs(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.SystemLog)
        .where(models.SystemLog.target_id == target_id)
        .order_by(models.SystemLog.created_at.asc())
    )
    return result.scalars().all()

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Auth Surface Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/targets/{target_id}/auth_surfaces",
         response_model=list[schemas.AuthSurfaceResponse])
async def get_auth_surfaces(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.AuthSurface)
        .where(models.AuthSurface.target_id == target_id)
        .order_by(models.AuthSurface.confidence_score.desc())
    )
    return result.scalars().all()


@app.post("/api/targets/{target_id}/classify_pages")
async def trigger_classify_pages(target_id: int, background_tasks: BackgroundTasks,
                                  db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    from agents.page_classifier import start_page_classification
    from database import AsyncSessionLocal
    async def _run(tid):
        async with AsyncSessionLocal() as s:
            await start_page_classification(tid, s)
    background_tasks.add_task(_run, target_id)
    return {"message": "Page classification started"}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Login Testing Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/targets/{target_id}/login_test")
async def trigger_login_test(target_id: int, background_tasks: BackgroundTasks,
                              db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    from agents.login_tester import start_login_testing
    from database import AsyncSessionLocal
    async def _run(tid):
        async with AsyncSessionLocal() as s:
            await start_login_testing(tid, s)
    background_tasks.add_task(_run, target_id)
    return {"message": "Login testing engine started"}


@app.post("/api/targets/{target_id}/advanced_test")
async def trigger_advanced_test(target_id: int, background_tasks: BackgroundTasks,
                                 db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    from agents.advanced_test_agent import start_advanced_testing
    from database import AsyncSessionLocal
    async def _run(tid):
        async with AsyncSessionLocal() as s:
            await start_advanced_testing(tid, s)
    background_tasks.add_task(_run, target_id)
    return {"message": "Advanced testing engine started"}


@app.get("/api/targets/{target_id}/auth_test_results",
         response_model=list[schemas.AuthTestResultResponse])
async def get_auth_test_results(target_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(models.AuthTestResult)
        .where(models.AuthTestResult.target_id == target_id)
        .order_by(models.AuthTestResult.confidence.desc())
    )
    return result.scalars().all()


# ─────────────────────────────────────────────────────────────────────────────
# Traffic Log Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/traffic_logs", response_model=list[schemas.TrafficLogResponse])
async def get_traffic_logs(
    db: AsyncSession = Depends(get_db),
    target_id: int = Query(None),
    tag: str = Query(None),
    status: int = Query(None),
    keyword: str = Query(None),
    limit: int = Query(100)
):
    stmt = select(models.TrafficLog).order_by(models.TrafficLog.timestamp.desc())
    if target_id:
        stmt = stmt.where(models.TrafficLog.target_id == target_id)
    if tag:
        stmt = stmt.where(models.TrafficLog.tag == tag)
    if status:
        stmt = stmt.where(models.TrafficLog.response_status == status)
    if keyword:
        stmt = stmt.where(
            models.TrafficLog.url.contains(keyword) |
            models.TrafficLog.response_body.contains(keyword)
        )
    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@app.delete("/api/traffic_logs")
async def clear_traffic_logs(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import delete
    await db.execute(delete(models.TrafficLog))
    await db.commit()
    return {"message": "Traffic logs cleared"}


@app.get("/api/traffic_logs/{log_id}", response_model=schemas.TrafficLogResponse)
async def get_traffic_log(log_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.TrafficLog).where(models.TrafficLog.id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


# ─────────────────────────────────────────────────────────────────────────────
# Payload Library Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/payload_library", response_model=list[schemas.PayloadLibraryResponse])
async def get_payload_library(
    db: AsyncSession = Depends(get_db),
    vuln_type: str = Query(None),
    limit: int = Query(50)
):
    from sqlalchemy import desc
    stmt = select(models.PayloadLibrary).order_by(desc(models.PayloadLibrary.success_rate)).limit(limit)
    if vuln_type:
        stmt = select(models.PayloadLibrary)\
            .where(models.PayloadLibrary.vuln_type == vuln_type)\
            .order_by(desc(models.PayloadLibrary.success_rate)).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@app.post("/api/payload_library/seed")
async def seed_payload_library(db: AsyncSession = Depends(get_db)):
    from agents.payload_engine import PayloadEngine
    engine_obj = PayloadEngine(db)
    await engine_obj.seed()
    return {"message": "Payload library seeded"}


@app.post("/api/payload_library/evolve")
async def evolve_payloads(
    vuln_type: str = Query(...),
    tech_stack: str = Query("unknown"),
    context: str = Query(""),
    db: AsyncSession = Depends(get_db)
):
    from agents.payload_engine import PayloadEngine
    engine_obj = PayloadEngine(db)
    evolved = await engine_obj.evolve(vuln_type, tech_stack, context)
    return {"evolved_payloads": evolved}


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/targets/{target_id}/risk_score")
async def compute_risk_score(target_id: int, background_tasks: BackgroundTasks,
                              db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    from agents.risk_scorer import start_risk_scoring
    from database import AsyncSessionLocal
    async def _run(tid):
        async with AsyncSessionLocal() as s:
            await start_risk_scoring(tid, s)
    background_tasks.add_task(_run, target_id)
    return {"message": "Risk scoring started"}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0: Intelligence (CWE Sync)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/intel/sync")
async def sync_intel(db: AsyncSession = Depends(get_db)):
    """Trigger CWE Intelligence synchronization."""
    from agents.intelligence_collector import IntelligenceCollectorAgent
    collector = IntelligenceCollectorAgent(db)
    count = await collector.sync_cwe()
    return {"status": "success", "synced_count": count}


@app.get("/api/intel/recent")
async def get_recent_intel(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Fetch recent weakness intelligence."""
    result = await db.execute(
        select(models.CWEData).order_by(models.CWEData.last_modified.desc()).limit(limit)
    )
    return result.scalars().all()


@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    t_count = await db.execute(select(func.count(models.Target.id)))
    r_count = await db.execute(select(func.count(models.ReconData.id)))
    v_count = await db.execute(select(func.count(models.Vulnerability.id)))
    a_count = await db.execute(select(func.count(models.AuthSurface.id)))
    tl_count = await db.execute(select(func.count(models.TrafficLog.id)))
    pl_count = await db.execute(select(func.count(models.PayloadLibrary.id)))
    cwe_count = await db.execute(select(func.count(models.CWEData.cwe_id)))
    return {
        "targets": t_count.scalar(),
        "recon_data": r_count.scalar(),
        "vulnerabilities": v_count.scalar(),
        "auth_surfaces": a_count.scalar(),
        "traffic_logs": tl_count.scalar(),
        "payload_library": pl_count.scalar(),
        "intel_cwes": cwe_count.scalar()
    }


# Serve Frontend (Must be last)
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
