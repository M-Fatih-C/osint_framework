import datetime
import re
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from osint_framework.api.schemas import (
    AuditLogListResponse,
    AuthMeResponse,
    AuthTokenRequest,
    AuthTokenResponse,
    CaseCreateRequest,
    CaseDetailResponse,
    CaseListResponse,
    CaseNoteCreateRequest,
    CaseNoteResponse,
    CaseSummary,
    ModuleInfo,
    ResultResponse,
    ScanRequest,
    ScanResponse,
    StatusResponse,
    SystemStatusResponse,
)
from osint_framework.core.audit import audit_logger
from osint_framework.core.auth import authenticate_local_user, issue_access_token, jwt_enabled
from osint_framework.core.case_manager import case_manager
from osint_framework.core.config import settings
from osint_framework.core.engine import engine
from osint_framework.core.logger import logger

router = APIRouter()

_ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff"}


def _resolve_vision_upload_dir() -> Path:
    configured = settings.integrations.vision.upload_dir
    base = Path(configured)
    if base.is_absolute():
        return base
    return Path(__file__).resolve().parents[2] / configured


def _sanitize_filename(name: str) -> str:
    stem = Path(name).stem or "image"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return safe or "image"


def _cleanup_uploaded_image(path: Optional[Path]) -> None:
    if not path:
        return
    try:
        path.unlink(missing_ok=True)
    except Exception as exc:
        logger.warning("Failed to cleanup uploaded image %s: %s", path, exc)


async def _persist_uploaded_image(upload: UploadFile) -> Path:
    original_name = (upload.filename or "upload.bin").strip()
    ext = Path(original_name).suffix.lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        raise ValueError(f"Unsupported image extension '{ext or 'none'}'.")

    content_type = (upload.content_type or "").strip().lower()
    if content_type and not content_type.startswith("image/"):
        raise ValueError(f"Invalid content type '{content_type}'.")

    upload_dir = _resolve_vision_upload_dir()
    upload_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    safe_name = _sanitize_filename(original_name)
    unique = uuid.uuid4().hex[:12]
    file_name = f"{stamp}_{safe_name}_{unique}{ext}"
    destination = upload_dir / file_name

    size_limit_mb = max(1, int(settings.integrations.vision.max_upload_mb))
    max_bytes = size_limit_mb * 1024 * 1024

    size = 0
    try:
        with destination.open("wb") as fh:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"Image exceeds size limit ({size_limit_mb} MB).")
                fh.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()

    return destination.resolve()


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
        job_id = await engine.queue_scan(
            request.target,
            request.target_type,
            case_id=request.case_id,
        )
        job = await engine.queue.get_job(job_id)
        return ScanResponse(
            job_id=job_id,
            status=(job or {}).get("status", "queued"),
            case_id=(job or {}).get("case_id"),
        )
    except HTTPException:
        raise
    except ValueError as exc:
        if "Case" in str(exc) and "not found" in str(exc):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/scan/image", response_model=ScanResponse)
async def create_image_scan(
    file: UploadFile = File(...),
    case_id: Optional[int] = Form(default=None),
):
    """Initiate image-based OSINT scan from multipart file upload."""
    if not settings.integrations.vision.enabled:
        raise HTTPException(status_code=400, detail="Vision integration is disabled")

    image_path: Optional[Path] = None
    try:
        if case_id is not None and int(case_id) <= 0:
            raise HTTPException(status_code=422, detail="case_id must be >= 1")

        image_path = await _persist_uploaded_image(file)
        logger.info("Stored image upload for scan: %s", image_path)

        if not engine.registry.get_modules_for("image"):
            raise HTTPException(
                status_code=400,
                detail="No modules registered for target_type 'image'",
            )

        job_id = await engine.queue_scan(str(image_path), "image", case_id=case_id)
        job = await engine.queue.get_job(job_id)
        return ScanResponse(
            job_id=job_id,
            status=(job or {}).get("status", "queued"),
            case_id=(job or {}).get("case_id"),
        )
    except HTTPException:
        _cleanup_uploaded_image(image_path)
        raise
    except ValueError as exc:
        _cleanup_uploaded_image(image_path)
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _cleanup_uploaded_image(image_path)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scan/{job_id}", response_model=StatusResponse)
async def get_scan_status(job_id: str):
    """Get the status of an ongoing or completed scan."""
    job = await engine.queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return StatusResponse(
        job_id=job["id"],
        case_id=job.get("case_id"),
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
        case_id=job.get("case_id"),
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
    queue_metrics = await engine.get_queue_metrics()
    return SystemStatusResponse(
        status="operational",
        workers_active=len([w for w in engine.pool.workers if not w.done()]),
        jobs_running=running_jobs,
        modules_loaded=len(engine.registry.list_all()),
        queue_mode=queue_metrics.get("mode"),
        queue_pending=queue_metrics.get("pending"),
        queue_processing=queue_metrics.get("processing"),
        queue_error=queue_metrics.get("error"),
    )


@router.get("/audit", response_model=AuditLogListResponse)
async def get_audit_logs(limit: int = 100):
    """List recent HTTP API audit logs."""
    items = await audit_logger.list_recent(limit=limit)
    return AuditLogListResponse(items=items, count=len(items))


@router.post("/cases", response_model=CaseSummary)
async def create_case(payload: CaseCreateRequest):
    """Create an investigation case container for grouping scans, notes, and pivots."""
    case = await case_manager.create_case(
        title=payload.title,
        description=payload.description,
        tags=payload.tags,
        priority=payload.priority,
        status=payload.status,
    )
    return case


@router.get("/cases", response_model=CaseListResponse)
async def list_cases(limit: int = 50, status: Optional[str] = None):
    """List investigation cases."""
    items = await case_manager.list_cases(limit=limit, status=status)
    return CaseListResponse(items=items, count=len(items))


@router.get("/cases/{case_id}", response_model=CaseDetailResponse)
async def get_case(case_id: int):
    """Get a case with tracked targets, recent jobs, and notes."""
    case = await case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases/{case_id}/notes", response_model=CaseNoteResponse)
async def add_case_note(case_id: int, payload: CaseNoteCreateRequest):
    """Append an analyst note to a case."""
    note = await case_manager.add_note(case_id, payload.content, author=payload.author)
    if not note:
        raise HTTPException(status_code=404, detail="Case not found")
    return note
