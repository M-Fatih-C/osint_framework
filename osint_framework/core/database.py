from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from osint_framework.core.config import settings
from osint_framework.core.logger import logger
from osint_framework.core.models import Base

class DatabaseManager:
    def __init__(self):
        kwargs = {"echo": False, "future": True}
        if not settings.database.url.startswith("sqlite"):
            kwargs["pool_size"] = settings.engine.threads
            kwargs["max_overflow"] = 10
            
        self.engine = create_async_engine(
            settings.database.url,
            **kwargs
        )
        self.async_session_maker = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def init_db(self):
        """Initialize database tables"""
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            await self._run_compat_migrations()
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise e

    async def _run_compat_migrations(self):
        """Apply lightweight schema upgrades for existing local SQLite databases."""
        if not settings.database.url.startswith("sqlite"):
            return

        async with self.engine.begin() as conn:
            rows = await conn.execute(text("PRAGMA table_info(scans)"))
            columns = {row[1] for row in rows.fetchall()}

            migrations = []
            if "modules_total" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN modules_total INTEGER NOT NULL DEFAULT 0"
                )
            if "correlated_intel" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN correlated_intel TEXT NULL"
                )
            if "error_message" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN error_message TEXT NULL"
                )
            if "case_id" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN case_id INTEGER NULL"
                )
            if "worker_lease_owner" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN worker_lease_owner TEXT NULL"
                )
            if "worker_heartbeat_at" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN worker_heartbeat_at DATETIME NULL"
                )
            if "worker_lease_expires_at" not in columns:
                migrations.append(
                    "ALTER TABLE scans ADD COLUMN worker_lease_expires_at DATETIME NULL"
                )

            for stmt in migrations:
                await conn.execute(text(stmt))

            if "modules_total" in columns or any("modules_total" in m for m in migrations):
                await conn.execute(
                    text("UPDATE scans SET modules_total = 0 WHERE modules_total IS NULL")
                )

            if migrations:
                logger.info("Applied %d SQLite compatibility migrations.", len(migrations))

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Dependency for FastAPI"""
        async with self.async_session_maker() as session:
            try:
                yield session
            finally:
                await session.close()
                
db_manager = DatabaseManager()
