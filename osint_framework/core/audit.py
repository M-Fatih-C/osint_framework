from typing import Any, Dict, List, Optional

from sqlalchemy import select

from osint_framework.core.database import db_manager
from osint_framework.core.logger import logger
from osint_framework.core.models import AuditLog


class AuditLogger:
    async def log_http_request(
        self,
        *,
        request_id: str,
        method: str,
        path: str,
        status_code: int,
        client_ip: Optional[str],
        user_agent: Optional[str],
        duration_ms: int,
        api_key_used: bool,
        note: Optional[str] = None,
    ) -> None:
        try:
            async with db_manager.async_session_maker() as session:
                entry = AuditLog(
                    request_id=request_id,
                    method=method,
                    path=path,
                    status_code=int(status_code),
                    client_ip=client_ip,
                    user_agent=user_agent[:255] if user_agent else None,
                    duration_ms=max(0, int(duration_ms)),
                    api_key_used=bool(api_key_used),
                    note=note[:500] if note else None,
                )
                session.add(entry)
                await session.commit()
        except Exception as exc:
            logger.warning("Failed to write audit log entry: %s", exc)

    async def list_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        async with db_manager.async_session_maker() as session:
            stmt = (
                select(AuditLog)
                .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                .limit(limit)
            )
            res = await session.execute(stmt)
            rows = res.scalars().all()
            return [
                {
                    "id": row.id,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                    "request_id": row.request_id,
                    "method": row.method,
                    "path": row.path,
                    "status_code": row.status_code,
                    "client_ip": row.client_ip,
                    "user_agent": row.user_agent,
                    "duration_ms": row.duration_ms,
                    "api_key_used": row.api_key_used,
                    "note": row.note,
                }
                for row in rows
            ]


audit_logger = AuditLogger()

