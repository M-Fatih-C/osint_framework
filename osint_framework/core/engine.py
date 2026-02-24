import asyncio
from typing import Any, Dict, Iterable, List, Tuple

from osint_framework.api.ws import ws_manager
from osint_framework.core.config import settings
from osint_framework.core.correlation import Correlator
from osint_framework.core.logger import logger
from osint_framework.job_queue.job_manager import job_manager
from osint_framework.job_queue.worker_pool import WorkerPool
from osint_framework.plugins.registry import registry
from osint_framework.reports.ai_summary import ai_reporter

class CoreEngine:
    def __init__(self):
        self.config = settings
        self.registry = registry
        self.pool = WorkerPool(concurrency=self.config.engine.threads)
        self.queue = job_manager
        self._background_tasks: set[asyncio.Task] = set()
        
    async def start(self):
        await self.pool.start()
        logger.info("Core Engine started.")
        
    async def stop(self):
        for task in list(self._background_tasks):
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()
        await self.pool.stop()
        logger.info("Core Engine stopped.")

    async def queue_scan(self, target: str, target_type: str) -> str:
        """
        Receives target, registers job, and enqueues module tasks.
        """
        job_id = await self.queue.create_job(target, target_type)
        modules = self.registry.get_modules_for(target_type)
        
        if not modules:
            logger.warning(f"No modules found for target type: {target_type}")
            await self.queue.update_job_status(
                job_id,
                "error",
                error_message=f"No modules available for target type '{target_type}'",
            )
            await ws_manager.broadcast({"type": "job_update", "job_id": job_id, "status": "error"})
            return job_id

        await self.queue.set_modules_total(job_id, len(modules))
        await self.queue.update_job_status(job_id, "running")
        await ws_manager.broadcast({"type": "job_update", "job_id": job_id, "status": "running"})

        # Start background processing and keep a reference to surface exceptions.
        task = asyncio.create_task(self._execute_scan(job_id, target, modules))
        self._background_tasks.add(task)
        task.add_done_callback(self._on_background_task_done)
        
        return job_id

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

            correlated = Correlator.analyze(job_data["results"])
            job_data["correlated_intel"] = correlated

            logger.info(f"Generating Executive Summary for {job_id}...")
            ai_summary_text = await ai_reporter.generate_summary(job_data)
            correlated["summary"] = ai_summary_text

            await self.queue.set_correlated_intel(job_id, correlated)
            await self.queue.update_job_status(job_id, "completed")
            await ws_manager.broadcast(
                {"type": "job_update", "job_id": job_id, "status": "completed"}
            )
            logger.info(f"Job {job_id} finished execution.")
        except asyncio.CancelledError:
            logger.warning("Scan job %s was cancelled.", job_id)
            raise
        except Exception as exc:
            logger.exception("Job %s failed during execution", job_id)
            await self.queue.update_job_status(job_id, "error", error_message=str(exc))
            await ws_manager.broadcast(
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
            await ws_manager.broadcast({
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

engine = CoreEngine()
