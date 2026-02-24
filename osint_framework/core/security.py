import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, Tuple

from fastapi import Request

from osint_framework.core.auth import (
    decode_bearer_token,
    has_required_roles,
    jwt_enabled,
    required_roles_for_request,
)
from osint_framework.core.config import settings
from osint_framework.core.logger import logger

try:
    from redis import asyncio as redis_async
except Exception:  # pragma: no cover
    redis_async = None


def parse_rate_limit(rule: str) -> Optional[Tuple[int, int]]:
    """
    Parse values like '100/minute', '10/min', '1000/hour', '5/second'.
    Returns (limit, window_seconds). Invalid values return None.
    """
    if not rule or "/" not in rule:
        return None
    raw_limit, raw_window = rule.strip().split("/", 1)
    try:
        limit = int(raw_limit)
    except ValueError:
        return None
    if limit <= 0:
        return None

    window_name = raw_window.strip().lower()
    alias = {
        "s": 1,
        "sec": 1,
        "second": 1,
        "seconds": 1,
        "m": 60,
        "min": 60,
        "minute": 60,
        "minutes": 60,
        "h": 3600,
        "hour": 3600,
        "hours": 3600,
    }
    window_seconds = alias.get(window_name)
    if not window_seconds:
        return None
    return limit, window_seconds


class InMemoryRateLimiter:
    def __init__(self):
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        now = time.monotonic()
        async with self._lock:
            q = self._events[key]
            cutoff = now - window_seconds
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                retry_after = max(1, int(window_seconds - (now - q[0])))
                return False, retry_after
            q.append(now)
            return True, 0

    async def reset(self):
        async with self._lock:
            self._events.clear()


class RedisFixedWindowRateLimiter:
    def __init__(self):
        self._client = None
        self._warned = False

    async def _get_client(self):
        if redis_async is None or not settings.cache.url:
            return None
        if self._client is None:
            self._client = redis_async.from_url(settings.cache.url, decode_responses=True)
        return self._client

    async def check(self, key: str, limit: int, window_seconds: int) -> Optional[Tuple[bool, int]]:
        client = await self._get_client()
        if client is None:
            return None

        bucket = int(time.time() // window_seconds)
        redis_key = f"osint:ratelimit:{bucket}:{key}"

        try:
            count = await client.incr(redis_key)
            if count == 1:
                await client.expire(redis_key, window_seconds)
            if count > limit:
                ttl = await client.ttl(redis_key)
                return False, max(1, int(ttl or window_seconds))
            return True, 0
        except Exception as exc:
            if not self._warned:
                logger.warning(
                    "Redis rate limiter unavailable, falling back to in-memory: %s", exc
                )
                self._warned = True
            return None

    async def reset(self):
        return

    async def close(self):
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                pass
            self._client = None


class APISecurityManager:
    def __init__(self):
        self.rate_limiter = InMemoryRateLimiter()
        self.redis_rate_limiter = RedisFixedWindowRateLimiter()

    def is_exempt_path(self, path: str) -> bool:
        for pattern in settings.security.exempt_paths:
            if not pattern:
                continue
            if pattern == "/":
                if path == "/":
                    return True
                continue
            if path == pattern or path.startswith(f"{pattern.rstrip('/')}/"):
                return True
        return False

    def should_protect(self, path: str, method: str) -> bool:
        if not path.startswith("/api/"):
            return False
        if self.is_exempt_path(path):
            return False

        api_key_auth_enabled = bool(settings.security.enabled and settings.security.api_keys)
        jwt_auth_enabled = jwt_enabled()
        if not api_key_auth_enabled and not jwt_auth_enabled:
            return False

        if settings.security.protect_read_endpoints:
            return True
        return method.upper() in {"POST", "PUT", "PATCH", "DELETE"}

    def _extract_api_key(self, request: Request) -> str:
        header_name = settings.security.api_key_header
        return (request.headers.get(header_name) or "").strip()

    @staticmethod
    def _extract_bearer_token(request: Request) -> str:
        auth_header = (request.headers.get("authorization") or "").strip()
        if not auth_header:
            return ""
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() != "bearer":
            return ""
        return value.strip()

    def authenticate_request(
        self, request: Request
    ) -> Tuple[bool, Optional[Dict[str, Any]], bool, Optional[str], int]:
        path = request.url.path
        method = request.method.upper()
        requires_auth = self.should_protect(path, method)

        api_key_used = False
        auth_context: Optional[Dict[str, Any]] = None
        auth_error_detail: Optional[str] = None

        api_key_list = set(settings.security.api_keys or [])
        presented_api_key = self._extract_api_key(request)
        if presented_api_key and api_key_list:
            if presented_api_key in api_key_list:
                auth_context = {"auth_type": "api_key", "subject": "api_key", "roles": ["admin"]}
                api_key_used = True
            else:
                auth_error_detail = "Invalid API key"

        bearer_token = self._extract_bearer_token(request)
        if bearer_token and not api_key_used:
            ok, jwt_context, err = decode_bearer_token(bearer_token)
            if ok:
                auth_context = jwt_context
            else:
                auth_error_detail = f"Invalid bearer token: {err}"

        if requires_auth and not auth_context:
            if not auth_error_detail:
                if jwt_enabled() and not api_key_list:
                    auth_error_detail = "Missing bearer token"
                else:
                    auth_error_detail = "Invalid or missing API key"
            return False, None, api_key_used, auth_error_detail, 401

        required_roles = required_roles_for_request(method, path)
        if required_roles and not has_required_roles(auth_context, required_roles):
            return False, auth_context, api_key_used, "Insufficient role", 403

        return True, auth_context, api_key_used, None, 200

    def get_client_ip(self, request: Request) -> str:
        if settings.security.trust_x_forwarded_for:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
        client = request.client
        return client.host if client else "unknown"

    async def enforce_rate_limit(self, request: Request) -> Tuple[bool, int]:
        path = request.url.path
        if not path.startswith("/api/") or self.is_exempt_path(path):
            return True, 0
        parsed = parse_rate_limit(settings.api.rate_limit)
        if not parsed:
            return True, 0

        limit, window_seconds = parsed
        client_ip = self.get_client_ip(request)
        key = f"{client_ip}:{path}:{request.method.upper()}"

        if (
            settings.cache.enabled
            and str(settings.cache.type).lower() == "redis"
            and settings.cache.url
        ):
            redis_result = await self.redis_rate_limiter.check(key, limit, window_seconds)
            if redis_result is not None:
                return redis_result

        return await self.rate_limiter.check(key, limit, window_seconds)

    async def reset_rate_limiters(self):
        await self.rate_limiter.reset()
        await self.redis_rate_limiter.reset()

    async def shutdown(self):
        await self.redis_rate_limiter.close()


api_security = APISecurityManager()

