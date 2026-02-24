import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import jwt
from jwt import InvalidTokenError

from osint_framework.core.config import settings


ROLE_MAP = {
    ("GET", "/api/v1/audit"): {"admin"},
}


def _jwt_secret() -> Optional[str]:
    return settings.security.jwt.secret


def jwt_enabled() -> bool:
    return bool(settings.security.jwt.enabled and _jwt_secret())


def authenticate_local_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    for user in settings.security.jwt.users:
        if user.disabled:
            continue
        if user.username != username:
            continue
        if not hmac.compare_digest(user.password, password):
            return None
        roles = [r for r in user.roles if r]
        if not roles:
            roles = ["viewer"]
        return {"username": user.username, "roles": roles}
    return None


def issue_access_token(username: str, roles: List[str]) -> Tuple[str, int]:
    now = datetime.now(timezone.utc)
    ttl_minutes = max(1, int(settings.security.jwt.access_token_ttl_minutes))
    expires_at = now + timedelta(minutes=ttl_minutes)
    payload = {
        "sub": username,
        "roles": roles,
        "iss": settings.security.jwt.issuer,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "type": "access",
    }
    token = jwt.encode(
        payload,
        _jwt_secret(),
        algorithm=settings.security.jwt.algorithm,
    )
    return token, ttl_minutes * 60


def decode_bearer_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    if not jwt_enabled():
        return False, None, "JWT auth is not enabled"
    try:
        payload = jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[settings.security.jwt.algorithm],
            issuer=settings.security.jwt.issuer,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
    except InvalidTokenError as exc:
        return False, None, str(exc)

    roles = payload.get("roles")
    if not isinstance(roles, list):
        roles = []
    roles = [str(r) for r in roles if isinstance(r, str) and r]
    if not roles:
        roles = ["viewer"]

    return (
        True,
        {
            "auth_type": "jwt",
            "subject": str(payload.get("sub")),
            "roles": roles,
            "claims": payload,
        },
        None,
    )


def required_roles_for_request(method: str, path: str) -> Optional[set[str]]:
    if not settings.security.jwt.rbac_enabled:
        return None
    return ROLE_MAP.get((method.upper(), path))


def has_required_roles(auth_context: Optional[Dict[str, Any]], required: set[str]) -> bool:
    if not required:
        return True
    if not auth_context:
        return False
    roles = set(auth_context.get("roles") or [])
    return bool(roles.intersection(required))

