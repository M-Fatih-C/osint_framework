import json
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from redis.asyncio import Redis

from osint_framework.core.config import settings
from osint_framework.core.logger import logger


@dataclass
class RedisQueuedJob:
    raw: str
    payload: Dict[str, Any]

    @property
    def job_id(self) -> Optional[str]:
        value = self.payload.get("job_id")
        return str(value) if value else None


class RedisQueueBackend:
    def __init__(self, client: Redis = None):
        self._client = client
        self._owns_client = client is None
        self.pending_key = settings.queue.redis_pending_key
        self.processing_key = settings.queue.redis_processing_key
        self.reserve_timeout_seconds = max(1, int(settings.queue.reserve_timeout_seconds or 5))
        self.consumer_name = f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}"

    @property
    def enabled(self) -> bool:
        return (settings.queue.mode or "").lower() == "redis"

    @property
    def client(self) -> Redis:
        return self._client

    async def connect(self):
        if self._client is not None:
            return
        self._client = Redis.from_url(settings.queue.redis_url, decode_responses=True)
        await self._client.ping()
        logger.info(
            "Redis queue backend connected (%s, pending=%s, processing=%s)",
            settings.queue.redis_url,
            self.pending_key,
            self.processing_key,
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
                logger.debug("Redis queue close failed", exc_info=True)
        self._client = None

    def _build_payload(self, job_id: str) -> Dict[str, Any]:
        return {
            "job_id": job_id,
            "enqueued_at": int(time.time()),
            "consumer": None,
        }

    async def enqueue(self, job_id: str):
        await self.connect()
        payload = self._build_payload(job_id)
        raw = json.dumps(payload, separators=(",", ":"))
        await self._client.lpush(self.pending_key, raw)
        logger.debug("Enqueued job %s into Redis queue", job_id)

    async def contains_job(self, job_id: str) -> bool:
        await self.connect()
        for key in (self.pending_key, self.processing_key):
            raw_items = await self._client.lrange(key, 0, -1)
            for raw in raw_items or []:
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue
                if str((payload or {}).get("job_id") or "") == str(job_id):
                    return True
        return False

    async def enqueue_if_missing(self, job_id: str) -> bool:
        if await self.contains_job(job_id):
            return False
        await self.enqueue(job_id)
        return True

    async def reserve(self) -> Optional[RedisQueuedJob]:
        await self.connect()
        raw = await self._client.brpoplpush(
            self.pending_key,
            self.processing_key,
            timeout=self.reserve_timeout_seconds,
        )
        if raw is None:
            return None

        try:
            payload = json.loads(raw)
        except Exception:
            logger.error("Invalid Redis queue payload; dropping from processing queue: %r", raw)
            await self._client.lrem(self.processing_key, 1, raw)
            return None

        if isinstance(payload, dict):
            payload["consumer"] = self.consumer_name
        return RedisQueuedJob(raw=raw, payload=payload if isinstance(payload, dict) else {})

    async def ack(self, item: RedisQueuedJob):
        if self._client is None or not item:
            return
        await self._client.lrem(self.processing_key, 1, item.raw)

    async def requeue_all_inflight(self) -> int:
        """Move all items from processing back to pending (best-effort)."""
        await self.connect()
        moved = 0
        while True:
            raw = await self._client.rpoplpush(self.processing_key, self.pending_key)
            if raw is None:
                break
            moved += 1
        if moved:
            logger.warning("Requeued %d inflight Redis jobs back to pending queue.", moved)
        return moved

    async def lengths(self) -> Dict[str, int]:
        await self.connect()
        pipe = self._client.pipeline()
        pipe.llen(self.pending_key)
        pipe.llen(self.processing_key)
        pending, processing = await pipe.execute()
        return {"pending": int(pending or 0), "processing": int(processing or 0)}


redis_queue_backend = RedisQueueBackend()
