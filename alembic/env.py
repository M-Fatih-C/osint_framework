from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from osint_framework.core.config import settings
from osint_framework.core.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def cleanup_appledouble_files() -> None:
    """Remove macOS AppleDouble metadata files that break Alembic revision loading."""
    script_location = config.get_main_option("script_location") or "alembic"
    root = Path(script_location)
    if not root.is_absolute():
        root = Path(__file__).resolve().parents[1] / root
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.name.startswith("._") or path.name.startswith(".__"):
            try:
                if path.is_dir():
                    # Alembic only cares about Python files; removing metadata dirs is safe.
                    import shutil

                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
            except Exception:
                pass


cleanup_appledouble_files()


def get_url() -> str:
    return os.getenv("ALEMBIC_DATABASE_URL") or settings.database.url


config.set_main_option("sqlalchemy.url", get_url())
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    import asyncio

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
