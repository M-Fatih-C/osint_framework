import asyncio
from typing import Any, Callable, Coroutine, List, Optional

from osint_framework.core.logger import logger

class WorkerPool:
    def __init__(self, concurrency: int = 20):
        self.concurrency = concurrency
        self.queue: Optional[asyncio.Queue] = None
        self.workers: List[asyncio.Task] = []
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _ensure_loop_queue(self):
        loop = asyncio.get_running_loop()
        if self.queue is None or self._loop is not loop:
            self.queue = asyncio.Queue()
            self._loop = loop
        
    async def start(self):
        """Start the worker pool"""
        if self._running:
            return

        self._ensure_loop_queue()
        self._running = True
        for i in range(self.concurrency):
            task = asyncio.create_task(self._worker(i))
            self.workers.append(task)
        logger.info(f"Worker pool started with {self.concurrency} workers.")

    async def stop(self):
        """Stop processing new tasks and wait for current ones to finish if possible."""
        if not self._running and not self.workers:
            return

        self._running = False
        if self.queue is not None:
            for _ in range(self.concurrency):
                await self.queue.put(None)  # Sentinel value to stop workers

        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        logger.info("Worker pool stopped.")

    async def submit(
        self, coroutine: Coroutine, callback: Callable[[Any, Exception], None] = None
    ) -> asyncio.Future:
        """Submit a coroutine for async execution."""
        if not self._running:
            raise RuntimeError("Worker pool is not running")
        self._ensure_loop_queue()
        if self.queue is None:
            raise RuntimeError("Worker queue is unavailable")
        future = asyncio.get_running_loop().create_future()
        await self.queue.put((coroutine, future, callback))
        return future

    async def _worker(self, worker_id: int):
        while self._running:
            try:
                if self.queue is None:
                    break

                item = await self.queue.get()
                if item is None:
                    self.queue.task_done()
                    break
                    
                coroutine, future, callback = item
                
                try:
                    result = await coroutine
                    if not future.done():
                        future.set_result(result)
                    if callback:
                        callback(result, None)
                except Exception as e:
                    logger.error(f"Worker {worker_id} error executing task: {e}")
                    if not future.done():
                        future.set_exception(e)
                    if callback:
                        callback(None, e)
                finally:
                    self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} critical error: {e}")
                if "different event loop" in str(e):
                    break
