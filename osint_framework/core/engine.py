import asyncio
from typing import Any, Dict, Iterable, List, Tuple

from osint_framework.api.ws import ws_manager
from osint_framework.core.config import settings
from osint_framework.core.correlation import Correlator
from osint_framework.core.logger import logger
from osint_framework.core.redis_event_bus import redis_event_bus
from osint_framework.job_queue.job_manager import job_manager
from osint_framework.job_queue.redis_queue_backend import redis_queue_backend
from osint_framework.job_queue.worker_pool import WorkerPool
from osint_framework.plugins.registry import registry
from osint_framework.reports.ai_summary import ai_reporter

class CoreEngine:
    def __init__(self):
        self.config = settings
        self.registry = registry
        self.pool = WorkerPool(concurrency=self.config.engine.threads)
        self.queue = job_manager
        self.distributed_queue = redis_queue_backend
        self.event_bus = redis_event_bus
        self._background_tasks: set[asyncio.Task] = set()
        self._mode: str = "api"
        self._pool_started = False

    @property
    def queue_mode(self) -> str:
        return (self.config.queue.mode or "in_process").lower()

    async def _emit_event(self, event: Dict[str, Any]):
        """Broadcast locally and publish to Redis event bus in distributed mode."""
        await ws_manager.broadcast(event)
        if self.queue_mode == "redis":
            try:
                await self.event_bus.publish(event)
            except Exception:
                logger.exception("Failed to publish Redis event bus message: %s", event)
        
    async def start(self, mode: str = "api"):
        self._mode = mode

        if self.queue_mode == "redis":
            await self.distributed_queue.connect()

        should_start_local_pool = self.queue_mode != "redis" or mode == "worker"
        if should_start_local_pool:
            await self.pool.start()
            self._pool_started = True
        else:
            self._pool_started = False
            logger.info("Core Engine API mode running without local pool (Redis queue enabled).")
        logger.info("Core Engine started (mode=%s, queue_mode=%s).", mode, self.queue_mode)
        
    async def stop(self):
        for task in list(self._background_tasks):
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()
        if self._pool_started:
            await self.pool.stop()
            self._pool_started = False
        if self.queue_mode == "redis":
            await self.distributed_queue.close()
        logger.info("Core Engine stopped (mode=%s, queue_mode=%s).", self._mode, self.queue_mode)

    async def queue_scan(self, target: str, target_type: str, case_id: int = None) -> str:
        """
        Receives target, registers job, and enqueues module tasks.
        """
        job_id = await self.queue.create_job(target, target_type, case_id=case_id)
        modules = self.registry.get_modules_for(target_type)
        
        if not modules:
            logger.warning(f"No modules found for target type: {target_type}")
            await self.queue.update_job_status(
                job_id,
                "error",
                error_message=f"No modules available for target type '{target_type}'",
            )
            await self._emit_event({"type": "job_update", "job_id": job_id, "status": "error"})
            return job_id

        await self.queue.set_modules_total(job_id, len(modules))

        if self.queue_mode == "redis" and self._mode == "api":
            await self.queue.update_job_status(job_id, "queued")
            await self.distributed_queue.enqueue(job_id)
            await self._emit_event({"type": "job_update", "job_id": job_id, "status": "queued"})
            return job_id

        await self.queue.update_job_status(job_id, "running")
        await self._emit_event({"type": "job_update", "job_id": job_id, "status": "running"})

        # Start background processing and keep a reference to surface exceptions.
        task = asyncio.create_task(self._execute_scan(job_id, target, modules))
        self._background_tasks.add(task)
        task.add_done_callback(self._on_background_task_done)
        
        return job_id

    async def process_persisted_job(self, job_id: str):
        """Execute a queued job by loading target metadata from persistence."""
        job = await self.queue.get_job(job_id)
        if not job:
            raise RuntimeError(f"Job {job_id} not found")

        target = job.get("target")
        target_type = job.get("target_type")
        if not target or not target_type:
            raise RuntimeError(f"Job {job_id} missing target metadata")

        modules = self.registry.get_modules_for(target_type)
        if not modules:
            await self.queue.update_job_status(
                job_id,
                "error",
                error_message=f"No modules available for target type '{target_type}'",
            )
            return

        await self.queue.set_modules_total(job_id, len(modules))
        await self.queue.update_job_status(job_id, "running")
        await self._emit_event({"type": "job_update", "job_id": job_id, "status": "running"})
        await self._execute_scan(job_id, target, modules)

    def _on_background_task_done(self, task: asyncio.Task):
        self._background_tasks.discard(task)
        try:
            task.result()
        except asyncio.CancelledError:
            logger.debug("Background scan task cancelled.")
        except Exception:
            logger.exception("Unhandled exception in background scan task.")

    async def _await_named_result(
        self, module_name: str, future: asyncio.Future
    ) -> Tuple[str, Any, Exception]:
        try:
            result = await future
            return module_name, result, None
        except Exception as exc:
            return module_name, None, exc

    async def _execute_scan(self, job_id: str, target: str, modules: Iterable[type]):
        """
        Background task to distribute module runs to the worker pool and wait for completion.
        """
        module_list = list(modules)
        logger.info(f"Starting execution for job {job_id} with {len(module_list)} modules.")

        try:
            submissions: List[Tuple[str, asyncio.Future]] = []
            for mod_cls in module_list:
                module_instance = mod_cls()
                coro = asyncio.wait_for(
                    module_instance.run(target),
                    timeout=module_instance.timeout,
                )
                future = await self.pool.submit(coro)
                submissions.append((module_instance.name, future))

            # Persist results as they finish to keep progress indicators accurate.
            waiters = [
                self._await_named_result(module_name, future)
                for module_name, future in submissions
            ]
            for waiter in asyncio.as_completed(waiters):
                module_name, result, error = await waiter
                if error:
                    logger.error("Module %s failed: %s", module_name, error)
                    payload = {"error": str(error)}
                else:
                    payload = result if isinstance(result, dict) else {"result": result}

                await self.queue.add_result(job_id, module_name, payload)
                await self._broadcast_module_progress(job_id, module_name)

            # Correlate results and trigger AI summary.
            job_data = await self.queue.get_job(job_id)
            if not job_data:
                raise RuntimeError("Job record missing after module execution")

            correlated = Correlator.analyze(
                job_data["results"],
                target=job_data.get("target"),
                target_type=job_data.get("target_type"),
            )
            job_data["correlated_intel"] = correlated

            logger.info(f"Generating Executive Summary for {job_id}...")
            ai_summary_text = await ai_reporter.generate_summary(job_data)
            correlated["summary"] = ai_summary_text

            await self.queue.set_correlated_intel(job_id, correlated)
            await self.queue.update_job_status(job_id, "completed")
            await self._emit_event(
                {"type": "job_update", "job_id": job_id, "status": "completed"}
            )
            logger.info(f"Job {job_id} finished execution.")
        except asyncio.CancelledError:
            logger.warning("Scan job %s was cancelled.", job_id)
            try:
                await self.queue.update_job_status(
                    job_id,
                    "error",
                    error_message="Scan cancelled before completion",
                )
                await self._emit_event(
                    {
                        "type": "job_update",
                        "job_id": job_id,
                        "status": "error",
                        "error": "Scan cancelled before completion",
                    }
                )
            except Exception:
                logger.exception("Failed to persist cancelled state for job %s", job_id)
            raise
        except Exception as exc:
            logger.exception("Job %s failed during execution", job_id)
            await self.queue.update_job_status(job_id, "error", error_message=str(exc))
            await self._emit_event(
                {
                    "type": "job_update",
                    "job_id": job_id,
                    "status": "error",
                    "error": str(exc),
                }
            )
            
    async def _broadcast_module_progress(self, job_id: str, mod_name: str):
        job = await self.queue.get_job(job_id)
        if job:
            await self._emit_event({
                "type": "module_result",
                "job_id": job_id,
                "module": mod_name,
                "modules_done": job["modules_done"],
                "modules_total": job["modules_total"]
            })

    async def get_status(self, job_id: str) -> str:
        job = await self.queue.get_job(job_id)
        return job["status"] if job else "not_found"

    async def get_merged_results(self, job_id: str) -> Dict[str, Any]:
        job = await self.queue.get_job(job_id)
        if not job:
            return {}
        return job

    async def get_queue_metrics(self) -> Dict[str, Any]:
        if self.queue_mode != "redis":
            return {"mode": self.queue_mode}
        try:
            lengths = await self.distributed_queue.lengths()
            return {"mode": "redis", **lengths}
        except Exception as exc:
            return {"mode": "redis", "error": str(exc)}

engine = CoreEngine()
