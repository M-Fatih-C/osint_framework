import asyncio
import json
import socket
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional, Set

from redis.asyncio import Redis

from osint_framework.core.config import settings
from osint_framework.core.logger import logger


EventHandler = Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[None]]


class RedisEventBus:
    def __init__(self, client: Redis = None):
        self._client = client
        self._owns_client = client is None
        self.instance_id = f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}"
        self.channel = settings.queue.redis_events_channel

    @property
    def enabled(self) -> bool:
        return (settings.queue.mode or "").lower() == "redis"

    async def connect(self):
        if self._client is not None:
            return
        self._client = Redis.from_url(settings.queue.redis_url, decode_responses=True)
        await self._client.ping()
        logger.info(
            "Redis event bus connected (%s, channel=%s, instance=%s)",
            settings.queue.redis_url,
            self.channel,
            self.instance_id,
        )

    async def close(self):
        if self._client is None:
            return
        if self._owns_client:
            try:
                closer = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
                if closer:
                    maybe_coro = closer()
                    if maybe_coro is not None:
                        await maybe_coro
            except Exception:
                logger.debug("Redis event bus close failed", exc_info=True)
        self._client = None

    def _encode_envelope(self, event: Dict[str, Any], source: Optional[str] = None) -> str:
        envelope = {
            "source": source or self.instance_id,
            "sent_at_ms": int(time.time() * 1000),
            "event": event,
        }
        return json.dumps(envelope, separators=(",", ":"))

    @staticmethod
    def decode_envelope(raw: Any) -> Optional[Dict[str, Any]]:
        if raw is None:
            return None
        if isinstance(raw, dict) and "event" in raw:
            return raw
        try:
            parsed = json.loads(raw)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) and isinstance(parsed.get("event"), dict) else None

    async def publish(self, event: Dict[str, Any], source: Optional[str] = None):
        if not self.enabled:
            return
        await self.connect()
        payload = self._encode_envelope(event, source=source)
        await self._client.publish(self.channel, payload)

    async def listen_forever(
        self,
        handler: EventHandler,
        stop_event: asyncio.Event,
        ignore_sources: Optional[Set[str]] = None,
        poll_interval_seconds: float = 0.25,
    ):
        await self.connect()
        ignore_sources = set(ignore_sources or set())
        pubsub = self._client.pubsub()
        await pubsub.subscribe(self.channel)
        logger.info(
            "Redis event bus subscriber started (channel=%s, ignore_sources=%s)",
            self.channel,
            sorted(ignore_sources),
        )
        try:
            while not stop_event.is_set():
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=poll_interval_seconds,
                )
                if not msg:
                    continue
                if msg.get("type") != "message":
                    continue
                envelope = self.decode_envelope(msg.get("data"))
                if not envelope:
                    logger.debug("Skipping invalid Redis event bus message: %r", msg)
                    continue
                source = str(envelope.get("source") or "")
                if source in ignore_sources:
                    continue
                event = envelope.get("event") or {}
                try:
                    await handler(event, envelope)
                except Exception:
                    logger.exception("Redis event bus handler failed for event: %s", event)
        finally:
            try:
                await pubsub.unsubscribe(self.channel)
                await pubsub.close()
            except Exception:
                logger.debug("Redis event bus pubsub close failed", exc_info=True)
            logger.info("Redis event bus subscriber stopped.")


redis_event_bus = RedisEventBus()
