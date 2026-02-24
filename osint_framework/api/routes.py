from fastapi import APIRouter, HTTPException, Request
from typing import List
from osint_framework.api.schemas import (
    ScanRequest, ScanResponse, StatusResponse, 
    ResultResponse, ModuleInfo, SystemStatusResponse, AuditLogListResponse,
    AuthTokenRequest, AuthTokenResponse, AuthMeResponse
)
from osint_framework.core.audit import audit_logger
from osint_framework.core.auth import authenticate_local_user, issue_access_token, jwt_enabled
from osint_framework.core.engine import engine

router = APIRouter()


@router.post("/auth/token", response_model=AuthTokenResponse)
async def create_access_token(payload: AuthTokenRequest):
    """Issue a JWT access token if JWT auth is enabled and credentials are valid."""
    if not jwt_enabled():
        raise HTTPException(status_code=400, detail="JWT auth is not enabled")

    user = authenticate_local_user(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token, expires_in = issue_access_token(user["username"], user["roles"])
    return AuthTokenResponse(
        access_token=token,
        expires_in=expires_in,
        roles=user["roles"],
        username=user["username"],
    )


@router.get("/auth/me", response_model=AuthMeResponse)
async def get_current_auth_context(request: Request):
    """Returns current auth context resolved by middleware."""
    ctx = getattr(request.state, "auth_context", None)
    if not ctx:
        return AuthMeResponse(authenticated=False)

    return AuthMeResponse(
        authenticated=True,
        auth_type=ctx.get("auth_type"),
        subject=ctx.get("subject"),
        roles=list(ctx.get("roles") or []),
    )

@router.post("/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    """Initiate a new OSINT scan."""
    try:
        if not engine.registry.get_modules_for(request.target_type):
            raise HTTPException(
                status_code=400,
                detail=f"No modules registered for target_type '{request.target_type}'",
            )
        job_id = await engine.queue_scan(request.target, request.target_type)
        job = await engine.queue.get_job(job_id)
        return ScanResponse(job_id=job_id, status=(job or {}).get("status", "queued"))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{job_id}", response_model=StatusResponse)
async def get_scan_status(job_id: str):
    """Get the status of an ongoing or completed scan."""
    job = await engine.queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    return StatusResponse(
        job_id=job["id"],
        target=job["target"],
        target_type=job["target_type"],
        status=job["status"],
        modules_done=job["modules_done"],
        modules_total=job["modules_total"],
        error_message=job.get("error_message"),
    )

@router.get("/result/{job_id}", response_model=ResultResponse)
async def get_scan_results(job_id: str):
    """Retrieve the results of a scan."""
    job = await engine.get_merged_results(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    return ResultResponse(
        job_id=job["id"],
        target=job["target"],
        target_type=job["target_type"],
        status=job["status"],
        modules_done=job.get("modules_done", 0),
        modules_total=job.get("modules_total", 0),
        results=job.get("results", []),
        correlated_intel=job.get("correlated_intel"),
        error_message=job.get("error_message"),
    )

@router.get("/modules", response_model=List[ModuleInfo])
async def list_modules():
    """List all registered and active modules."""
    return engine.registry.list_all()

@router.get("/status", response_model=SystemStatusResponse)
async def get_system_status():
    """Get internal framework metrics."""
    jobs = await engine.queue.get_all_jobs()
    running_jobs = sum(1 for j in jobs if j["status"] == "running")
    return SystemStatusResponse(
        status="operational",
        workers_active=len([w for w in engine.pool.workers if not w.done()]),
        jobs_running=running_jobs,
        modules_loaded=len(engine.registry.list_all())
    )


@router.get("/audit", response_model=AuditLogListResponse)
async def get_audit_logs(limit: int = 100):
    """List recent HTTP API audit logs."""
    items = await audit_logger.list_recent(limit=limit)
    return AuditLogListResponse(items=items, count=len(items))
