import uuid
import datetime
from typing import Any, Dict, List

from sqlalchemy import select

from osint_framework.core.database import db_manager
from osint_framework.core.logger import logger
from osint_framework.core.models import Case, CaseTarget, Result, Scan, Target


def utc_now_naive() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

class JobManager:
    @staticmethod
    def _parse_uuid(job_id: str):
        try:
            return uuid.UUID(job_id)
        except (ValueError, TypeError):
            return None

    async def create_job(self, target_val: str, target_type: str, case_id: int = None) -> str:
        async with db_manager.async_session_maker() as session:
            case_obj = None
            now = utc_now_naive()
            if case_id is not None:
                case_stmt = select(Case).where(Case.id == int(case_id))
                case_res = await session.execute(case_stmt)
                case_obj = case_res.scalar_one_or_none()
                if not case_obj:
                    raise ValueError(f"Case {case_id} not found")

            # Get or create target
            stmt = select(Target).where(Target.value == target_val, Target.type == target_type)
            result = await session.execute(stmt)
            target_obj = result.scalar_one_or_none()
            
            if not target_obj:
                target_obj = Target(value=target_val, type=target_type)
                session.add(target_obj)
                await session.flush()
                
            job_id = uuid.uuid4()
            scan = Scan(
                id=job_id,
                target_id=target_obj.id,
                case_id=case_obj.id if case_obj else None,
                status="pending",
                modules_total=0,
                correlated_intel=None,
                error_message=None,
            )
            session.add(scan)

            if case_obj:
                case_obj.updated_at = now
                ct_stmt = select(CaseTarget).where(
                    CaseTarget.case_id == case_obj.id,
                    CaseTarget.target_value == target_val,
                    CaseTarget.target_type == target_type,
                )
                ct_res = await session.execute(ct_stmt)
                case_target = ct_res.scalar_one_or_none()
                if case_target:
                    case_target.last_seen_at = now
                else:
                    session.add(
                        CaseTarget(
                            case_id=case_obj.id,
                            target_value=target_val,
                            target_type=target_type,
                            first_seen_at=now,
                            last_seen_at=now,
                        )
                    )
            await session.commit()
            
            logger.info(f"Created new job {str(job_id)} for target {target_val}")
            return str(job_id)
            
    async def get_job(self, job_id: str) -> Dict[str, Any]:
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return None
                
            stmt = select(Scan).where(Scan.id == job_uuid)
            res = await session.execute(stmt)
            scan = res.scalar_one_or_none()
            
            if not scan:
                return None
                
            # Fetch target
            t_stmt = select(Target).where(Target.id == scan.target_id)
            t_res = await session.execute(t_stmt)
            target_obj = t_res.scalar_one_or_none()
            
            # Fetch results
            r_stmt = (
                select(Result)
                .where(Result.scan_id == job_uuid)
                .order_by(Result.timestamp.asc(), Result.id.asc())
            )
            r_res = await session.execute(r_stmt)
            results = r_res.scalars().all()
            
            return {
                "id": str(scan.id),
                "target": target_obj.value if target_obj else "unknown",
                "target_type": target_obj.type if target_obj else "unknown",
                "status": scan.status,
                "case_id": scan.case_id,
                "modules_total": scan.modules_total or 0,
                "modules_done": len(results),
                "results": [{"module": r.module_name, "data": r.data} for r in results],
                "correlated_intel": scan.correlated_intel,
                "error_message": scan.error_message,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            }

    async def update_job_status(self, job_id: str, status: str, error_message: str = None):
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return
            stmt = select(Scan).where(Scan.id == job_uuid)
            res = await session.execute(stmt)
            scan = res.scalar_one_or_none()
            if scan:
                scan.status = status
                if error_message is not None:
                    scan.error_message = error_message
                elif status != "error":
                    scan.error_message = None
                if status in ["completed", "error"]:
                    scan.completed_at = utc_now_naive()
                await session.commit()
                logger.info(f"Job {job_id} status changed to {status}")
            
    async def add_result(self, job_id: str, module_name: str, data: dict):
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return
            res = Result(scan_id=job_uuid, module_name=module_name, data=data)
            session.add(res)
            await session.commit()
            logger.debug(f"Job {job_id}: Result added from {module_name}")
            
    async def set_modules_total(self, job_id: str, total: int):
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return
            stmt = select(Scan).where(Scan.id == job_uuid)
            res = await session.execute(stmt)
            scan = res.scalar_one_or_none()
            if scan:
                scan.modules_total = max(0, int(total))
                await session.commit()
            
    async def get_modules_total(self, job_id: str) -> int:
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return 0
            stmt = select(Scan.modules_total).where(Scan.id == job_uuid)
            res = await session.execute(stmt)
            value = res.scalar_one_or_none()
            return int(value or 0)

    async def set_correlated_intel(self, job_id: str, correlated_intel: Dict[str, Any]):
        async with db_manager.async_session_maker() as session:
            job_uuid = self._parse_uuid(job_id)
            if not job_uuid:
                return
            stmt = select(Scan).where(Scan.id == job_uuid)
            res = await session.execute(stmt)
            scan = res.scalar_one_or_none()
            if scan:
                scan.correlated_intel = correlated_intel
                await session.commit()
        
    async def get_all_jobs(self) -> List[Dict[str, Any]]:
        async with db_manager.async_session_maker() as session:
            stmt = select(Scan).order_by(Scan.created_at.desc()).limit(100)
            res = await session.execute(stmt)
            scans = res.scalars().all()
            
            jobs = []
            for s in scans:
                jobs.append({
                    "id": str(s.id),
                    "target_id": s.target_id,
                    "status": s.status,
                    "case_id": s.case_id,
                    "modules_total": s.modules_total or 0,
                    "error_message": s.error_message,
                    "created_at": s.created_at.isoformat() if s.created_at else None
                })
            return jobs

job_manager = JobManager()
