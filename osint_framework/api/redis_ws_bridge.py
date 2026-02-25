import asyncio
from typing import Optional

from osint_framework.api.ws import ws_manager
from osint_framework.core.config import settings
from osint_framework.core.logger import logger
from osint_framework.core.redis_event_bus import RedisEventBus, redis_event_bus


class RedisWebSocketBridge:
    def __init__(self, event_bus: Optional[RedisEventBus] = None):
        self.event_bus = event_bus or redis_event_bus
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    @property
    def enabled(self) -> bool:
        return (settings.queue.mode or "").lower() == "redis"

    async def _handle_event(self, event, envelope):
        await ws_manager.broadcast(event)

    async def start(self):
        if not self.enabled:
            return
        if self._task and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(
            self.event_bus.listen_forever(
                handler=self._handle_event,
                stop_event=self._stop_event,
                ignore_sources={self.event_bus.instance_id},
            )
        )
        logger.info("Redis WebSocket bridge started.")

    async def stop(self):
        if not self._task:
            return
        self._stop_event.set()
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)
        self._task = None
        await self.event_bus.close()
        logger.info("Redis WebSocket bridge stopped.")


redis_ws_bridge = RedisWebSocketBridge()
