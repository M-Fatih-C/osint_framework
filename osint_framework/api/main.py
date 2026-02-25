import os
import time
import uuid

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from osint_framework.api.routes import router
from osint_framework.api.redis_ws_bridge import redis_ws_bridge
from osint_framework.api.ws import ws_manager
from osint_framework.core.audit import audit_logger
from osint_framework.core.config import settings
from osint_framework.core.database import db_manager
from osint_framework.core.engine import engine
from osint_framework.core.logger import logger
from osint_framework.core.security import api_security
from osint_framework.plugins.registry import registry

app = FastAPI(
    title="Professional OSINT Framework",
    description="Modular, Scalable and Extensible Intelligence Gathering Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_audit_middleware(request: Request, call_next):
    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    request.state.auth_context = None
    start = time.perf_counter()
    path = request.url.path
    client_ip = api_security.get_client_ip(request)
    user_agent = request.headers.get("user-agent")
    api_key_used = False
    note = None
    status_code = 500

    async def finalize_and_return(response):
        response.headers["X-Request-ID"] = request_id
        nonlocal status_code
        status_code = response.status_code
        if path.startswith("/api/"):
            duration_ms = int((time.perf_counter() - start) * 1000)
            if settings.security.audit_logging:
                await audit_logger.log_http_request(
                    request_id=request_id,
                    method=request.method,
                    path=path,
                    status_code=status_code,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    duration_ms=duration_ms,
                    api_key_used=api_key_used,
                    note=note,
                )
        return response

    rate_ok, retry_after = await api_security.enforce_rate_limit(request)
    if not rate_ok:
        note = f"rate_limited retry_after={retry_after}s"
        response = JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "retry_after": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
        return await finalize_and_return(response)

    auth_ok, auth_context, api_key_used, auth_detail, auth_status = api_security.authenticate_request(request)
    request.state.auth_context = auth_context
    if not auth_ok:
        note = "auth_failed" if auth_status == 401 else "auth_forbidden"
        response = JSONResponse(
            status_code=auth_status,
            content={"detail": auth_detail or "Unauthorized"},
        )
        return await finalize_and_return(response)

    try:
        response = await call_next(request)
        return await finalize_and_return(response)
    except Exception as exc:
        logger.exception("Unhandled request error for %s %s", request.method, path)
        note = f"exception:{type(exc).__name__}"
        response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
        return await finalize_and_return(response)

app.include_router(router, prefix="/api/v1")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "..", "web", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the main dashboard HTML."""
    template_path = os.path.join(os.path.dirname(__file__), "..", "web", "templates", "dashboard.html")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Dashboard template not found. Please create web/templates/dashboard.html</h1>"

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, client_id: str = "guest"):
    """WebSocket endpoint for real-time notifications."""
    await ws_manager.connect(websocket, client_id)
    try:
        while True:
            # Keep alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, client_id)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up OSINT Framework...")
    try:
        await db_manager.init_db()
        registry.discover()
        await engine.start(mode="api")
        await redis_ws_bridge.start()
        logger.info("Application started successfully.")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down OSINT Framework...")
    await api_security.shutdown()
    await redis_ws_bridge.stop()
    await engine.stop()
    logger.info("Shutdown complete.")
