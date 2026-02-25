import asyncio
from typing import Optional

from osint_framework.core.logger import logger
from osint_framework.job_queue.redis_queue_backend import RedisQueueBackend, redis_queue_backend


class RedisWorkerService:
    def __init__(self, engine, queue_backend: Optional[RedisQueueBackend] = None):
        self.engine = engine
        self.queue_backend = queue_backend or redis_queue_backend
        self._stop_event = asyncio.Event()

    def request_stop(self):
        self._stop_event.set()

    async def run_once(self) -> bool:
        """Reserve and process one queued job. Returns True if a job was processed."""
        item = await self.queue_backend.reserve()
        if item is None:
            return False

        job_id = item.job_id
        if not job_id:
            logger.error("Redis queue item missing job_id; acking and discarding.")
            await self.queue_backend.ack(item)
            return False

        try:
            await self.engine.process_persisted_job(job_id)
        except Exception as exc:
            logger.exception("Worker failed processing queued job %s", job_id)
            await self.engine.queue.update_job_status(job_id, "error", error_message=str(exc))
        finally:
            await self.queue_backend.ack(item)
        return True

    async def run_forever(self):
        if not self.queue_backend.enabled:
            raise RuntimeError("Redis worker service requires queue.mode=redis")

        await self.queue_backend.connect()
        if getattr(self.engine.config.queue, "requeue_inflight_on_worker_start", False):
            await self.queue_backend.requeue_all_inflight()

        logger.info("Redis worker service started (consumer=%s)", self.queue_backend.consumer_name)
        while not self._stop_event.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Redis worker service loop error")
                await asyncio.sleep(1)
        logger.info("Redis worker service stopped.")
