import os
from typing import Any, Dict, List
from urllib.parse import quote

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class HIBPBreachModule(BaseModule):
    name = "HIBP_Breach"
    version = "1.0.0"
    description = "Checks HaveIBeenPwned breaches for an email address (requires HIBP API key)."
    target_types = ["email"]
    author = "OSINT_Framework_Team"
    timeout = 12

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Checking HIBP breaches for %s", self.name, target)

        api_key = os.getenv("HIBP_API_KEY")
        if not api_key:
            return {
                "status": "skipped",
                "error": "Module requires HIBP_API_KEY environment variable",
            }

        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{quote(target)}?truncateResponse=false"
        )
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "OSINT-Framework/1.0 (+local)",
        }

        async with self.get_client() as client:
            try:
                resp = await client.get(url, headers=headers, timeout=self.timeout)
                if resp.status_code == 404:
                    return {
                        "status": "ok",
                        "breached": False,
                        "breaches": [],
                        "total_breaches": 0,
                    }
                if resp.status_code == 429:
                    return {
                        "status": "error",
                        "error": "HIBP rate limit exceeded",
                        "retry_after": resp.headers.get("Retry-After"),
                    }
                if resp.status_code in {401, 403}:
                    return {"status": "error", "error": "Invalid HIBP API key or access denied"}
                if resp.status_code != 200:
                    return {"status": "error", "error": f"HTTP {resp.status_code}"}

                breaches: List[Dict[str, Any]] = resp.json()
                normalized = []
                for b in breaches[:50]:
                    normalized.append(
                        {
                            "name": b.get("Name"),
                            "title": b.get("Title"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "added_date": b.get("AddedDate"),
                            "modified_date": b.get("ModifiedDate"),
                            "pwn_count": b.get("PwnCount"),
                            "is_verified": b.get("IsVerified"),
                            "is_sensitive": b.get("IsSensitive"),
                            "data_classes": b.get("DataClasses", []),
                        }
                    )

                return {
                    "status": "ok",
                    "breached": len(normalized) > 0,
                    "total_breaches": len(normalized),
                    "breaches": normalized,
                }
            except Exception as exc:
                logger.warning("[%s] HIBP lookup failed: %s", self.name, exc)
                return {"status": "error", "error": str(exc)}

