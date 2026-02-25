import asyncio
import time
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
        forwarded_event = dict(event or {})
        sent_at_ms = envelope.get("sent_at_ms")
        now_ms = int(time.time() * 1000)
        try:
            sent_int = int(sent_at_ms) if sent_at_ms is not None else None
        except Exception:
            sent_int = None

        existing_meta = forwarded_event.get("_event_meta")
        meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
        meta.update(
            {
                "transport": "redis_pubsub",
                "source": envelope.get("source"),
                "channel": self.event_bus.channel,
                "sent_at_ms": sent_int,
                "bridge_received_at_ms": now_ms,
                "bridge_instance": self.event_bus.instance_id,
            }
        )
        if sent_int is not None:
            meta["bridge_delay_ms"] = max(0, now_ms - sent_int)
        forwarded_event["_event_meta"] = {k: v for k, v in meta.items() if v is not None}
        await ws_manager.broadcast(forwarded_event)

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
