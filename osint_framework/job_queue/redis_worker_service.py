import asyncio
from typing import Optional

from osint_framework.core.logger import logger
from osint_framework.job_queue.redis_queue_backend import RedisQueueBackend, redis_queue_backend


class RedisWorkerService:
    def __init__(self, engine, queue_backend: Optional[RedisQueueBackend] = None):
        self.engine = engine
        self.queue_backend = queue_backend or redis_queue_backend
        self._stop_event = asyncio.Event()

    @property
    def worker_id(self) -> str:
        return self.queue_backend.consumer_name

    async def _heartbeat_loop(self, job_id: str):
        interval = max(1, int(getattr(self.engine.config.queue, "worker_heartbeat_interval_seconds", 10)))
        lease_seconds = max(5, int(getattr(self.engine.config.queue, "worker_lease_seconds", 45)))
        while not self._stop_event.is_set():
            await asyncio.sleep(interval)
            ok = await self.engine.queue.heartbeat_worker_lease(
                job_id,
                worker_id=self.worker_id,
                lease_seconds=lease_seconds,
            )
            if not ok:
                logger.warning("Lease heartbeat stopped for job %s (lease no longer owned).", job_id)
                break

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

        lease_seconds = max(5, int(getattr(self.engine.config.queue, "worker_lease_seconds", 45)))
        claimed = await self.engine.queue.claim_worker_lease(
            job_id,
            worker_id=self.worker_id,
            lease_seconds=lease_seconds,
        )
        if not claimed:
            logger.warning("Could not claim worker lease for job %s; acking queue item.", job_id)
            await self.queue_backend.ack(item)
            return False

        heartbeat_task = asyncio.create_task(self._heartbeat_loop(job_id))
        try:
            await self.engine.queue.reset_job_for_retry(job_id)
            await self.engine.process_persisted_job(job_id)
        except Exception as exc:
            logger.exception("Worker failed processing queued job %s", job_id)
            await self.engine.queue.update_job_status(job_id, "error", error_message=str(exc))
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
            await self.engine.queue.clear_worker_lease(job_id)
            await self.queue_backend.ack(item)
        return True

    async def run_forever(self):
        if not self.queue_backend.enabled:
            raise RuntimeError("Redis worker service requires queue.mode=redis")

        await self.queue_backend.connect()
        if getattr(self.engine.config.queue, "requeue_inflight_on_worker_start", False):
            await self.queue_backend.requeue_all_inflight()
        if getattr(self.engine.config.queue, "stale_job_recovery_on_worker_start", False):
            action = getattr(self.engine.config.queue, "stale_job_recovery_action", "requeue")
            recovery = await self.engine.queue.recover_stale_running_jobs(action=action)
            if recovery.get("count") and action == "requeue":
                enqueued = 0
                for item in recovery.get("jobs") or []:
                    job_id = item.get("job_id")
                    if not job_id:
                        continue
                    if await self.queue_backend.enqueue_if_missing(job_id):
                        enqueued += 1
                if enqueued:
                    logger.warning("Enqueued %d recovered stale jobs back into Redis pending queue.", enqueued)
            if recovery.get("count"):
                logger.warning(
                    "Stale running job recovery applied on worker startup: %s",
                    recovery,
                )

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
