from typing import Any, Dict, List, Optional

from sqlalchemy import func, select

from osint_framework.core.database import db_manager
from osint_framework.core.models import Case, CaseNote, CaseTarget, Scan, Target, utc_now_naive


class CaseManager:
    @staticmethod
    def _serialize_case(
        case: Case,
        scans_count: int = 0,
        targets_count: int = 0,
        notes_count: int = 0,
    ) -> Dict[str, Any]:
        return {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "priority": case.priority,
            "tags": list(case.tags or []),
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            "counts": {
                "scans": int(scans_count or 0),
                "targets": int(targets_count or 0),
                "notes": int(notes_count or 0),
            },
        }

    async def case_exists(self, case_id: int) -> bool:
        async with db_manager.async_session_maker() as session:
            stmt = select(Case.id).where(Case.id == case_id)
            res = await session.execute(stmt)
            return res.scalar_one_or_none() is not None

    async def create_case(
        self,
        title: str,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        priority: str = "normal",
        status: str = "open",
    ) -> Dict[str, Any]:
        now = utc_now_naive()
        async with db_manager.async_session_maker() as session:
            case = Case(
                title=title.strip(),
                description=(description.strip() if isinstance(description, str) else None),
                tags=list(tags or []),
                priority=priority,
                status=status,
                created_at=now,
                updated_at=now,
            )
            session.add(case)
            await session.commit()
            await session.refresh(case)
            return self._serialize_case(case)

    async def list_cases(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        async with db_manager.async_session_maker() as session:
            stmt = select(Case).order_by(Case.updated_at.desc(), Case.id.desc()).limit(max(1, min(limit, 200)))
            if status:
                stmt = stmt.where(Case.status == status)
            res = await session.execute(stmt)
            cases = res.scalars().all()
            if not cases:
                return []

            case_ids = [c.id for c in cases]
            scan_counts = await self._group_counts(session, Scan.case_id, Scan.id, case_ids)
            target_counts = await self._group_counts(session, CaseTarget.case_id, CaseTarget.id, case_ids)
            note_counts = await self._group_counts(session, CaseNote.case_id, CaseNote.id, case_ids)

            return [
                self._serialize_case(
                    case,
                    scans_count=scan_counts.get(case.id, 0),
                    targets_count=target_counts.get(case.id, 0),
                    notes_count=note_counts.get(case.id, 0),
                )
                for case in cases
            ]

    async def _group_counts(
        self,
        session,
        group_col,
        count_col,
        case_ids: List[int],
    ) -> Dict[int, int]:
        stmt = (
            select(group_col, func.count(count_col))
            .where(group_col.in_(case_ids))
            .group_by(group_col)
        )
        res = await session.execute(stmt)
        return {int(case_id): int(count) for case_id, count in res.all() if case_id is not None}

    async def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        async with db_manager.async_session_maker() as session:
            case_stmt = select(Case).where(Case.id == case_id)
            case_res = await session.execute(case_stmt)
            case = case_res.scalar_one_or_none()
            if not case:
                return None

            scan_counts = await self._group_counts(session, Scan.case_id, Scan.id, [case_id])
            target_counts = await self._group_counts(session, CaseTarget.case_id, CaseTarget.id, [case_id])
            note_counts = await self._group_counts(session, CaseNote.case_id, CaseNote.id, [case_id])

            targets_stmt = (
                select(CaseTarget)
                .where(CaseTarget.case_id == case_id)
                .order_by(CaseTarget.last_seen_at.desc(), CaseTarget.id.desc())
                .limit(100)
            )
            targets_res = await session.execute(targets_stmt)
            tracked_targets = [
                {
                    "id": t.id,
                    "target": t.target_value,
                    "target_type": t.target_type,
                    "first_seen_at": t.first_seen_at.isoformat() if t.first_seen_at else None,
                    "last_seen_at": t.last_seen_at.isoformat() if t.last_seen_at else None,
                }
                for t in targets_res.scalars().all()
            ]

            jobs_stmt = (
                select(Scan, Target)
                .join(Target, Target.id == Scan.target_id)
                .where(Scan.case_id == case_id)
                .order_by(Scan.created_at.desc(), Scan.id.desc())
                .limit(100)
            )
            jobs_res = await session.execute(jobs_stmt)
            recent_jobs = []
            for scan, target in jobs_res.all():
                recent_jobs.append(
                    {
                        "job_id": str(scan.id),
                        "target": target.value,
                        "target_type": target.type,
                        "status": scan.status,
                        "modules_total": int(scan.modules_total or 0),
                        "created_at": scan.created_at.isoformat() if scan.created_at else None,
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    }
                )

            notes_stmt = (
                select(CaseNote)
                .where(CaseNote.case_id == case_id)
                .order_by(CaseNote.created_at.desc(), CaseNote.id.desc())
                .limit(100)
            )
            notes_res = await session.execute(notes_stmt)
            notes = [
                {
                    "id": note.id,
                    "content": note.content,
                    "author": note.author,
                    "created_at": note.created_at.isoformat() if note.created_at else None,
                }
                for note in notes_res.scalars().all()
            ]

            payload = self._serialize_case(
                case,
                scans_count=scan_counts.get(case_id, 0),
                targets_count=target_counts.get(case_id, 0),
                notes_count=note_counts.get(case_id, 0),
            )
            payload["tracked_targets"] = tracked_targets
            payload["recent_jobs"] = recent_jobs
            payload["notes"] = notes
            return payload

    async def add_note(
        self,
        case_id: int,
        content: str,
        author: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        async with db_manager.async_session_maker() as session:
            stmt = select(Case).where(Case.id == case_id)
            res = await session.execute(stmt)
            case = res.scalar_one_or_none()
            if not case:
                return None

            note = CaseNote(
                case_id=case_id,
                content=content.strip(),
                author=(author.strip() if isinstance(author, str) and author.strip() else None),
                created_at=utc_now_naive(),
            )
            case.updated_at = utc_now_naive()
            session.add(note)
            await session.commit()
            await session.refresh(note)
            return {
                "id": note.id,
                "content": note.content,
                "author": note.author,
                "created_at": note.created_at.isoformat() if note.created_at else None,
            }


case_manager = CaseManager()
