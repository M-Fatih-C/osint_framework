import asyncio
import signal

from osint_framework.core.database import db_manager
from osint_framework.core.engine import engine
from osint_framework.core.logger import logger
from osint_framework.job_queue.redis_worker_service import RedisWorkerService
from osint_framework.plugins.registry import registry


async def run_worker_forever():
    logger.info("Starting OSINT Redis worker process...")
    await db_manager.init_db()
    registry.discover()
    await engine.start(mode="worker")

    service = RedisWorkerService(engine)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, service.request_stop)
        except NotImplementedError:
            # Some environments (e.g. Windows) do not support add_signal_handler.
            pass

    try:
        await service.run_forever()
    finally:
        await engine.stop()
        logger.info("OSINT Redis worker shutdown complete.")


def main():
    asyncio.run(run_worker_forever())


if __name__ == "__main__":
    main()
