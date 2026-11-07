"""Keep each regression independent of persisted jobs and previous API lifespans."""
import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from osint_framework.core.config import settings
from osint_framework.core.database import db_manager


@pytest.fixture(autouse=True)
def isolated_test_database(tmp_path, monkeypatch):
    url = f"sqlite+aiosqlite:///{tmp_path / 'regression.sqlite'}"
    engine = create_async_engine(url, poolclass=NullPool)
    monkeypatch.setattr(settings.database, "url", url)
    monkeypatch.setattr(db_manager, "engine", engine)
    monkeypatch.setattr(
        db_manager, "async_session_maker",
        async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
    )
    try:
        yield
    finally:
        asyncio.run(engine.dispose())
