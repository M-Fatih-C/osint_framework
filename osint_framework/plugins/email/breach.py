import os
from typing import Any, Dict, List
from urllib.parse import quote

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class HIBPApiProvider:
    name = "hibp"

    async def lookup(self, module: BaseModule, target: str) -> ProviderResult:
        api_key = os.getenv("HIBP_API_KEY")
        if not api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                error="Module requires HIBP_API_KEY environment variable",
                meta={"reason": "missing_api_key"},
            )

        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{quote(target)}?truncateResponse=false"
        )
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "OSINT-Framework/1.0 (+local)",
        }

        async with module.get_client() as client:
            try:
                resp = await client.get(url, headers=headers, timeout=module.timeout)
                if resp.status_code == 404:
                    return ProviderResult(
                        provider=self.name,
                        status="ok",
                        payload={
                            "breached": False,
                            "breaches": [],
                            "total_breaches": 0,
                        },
                        meta={"http_status": 404},
                    )
                if resp.status_code == 429:
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        error="HIBP rate limit exceeded",
                        payload={"retry_after": resp.headers.get("Retry-After")},
                        meta={"http_status": 429},
                    )
                if resp.status_code in {401, 403}:
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        error="Invalid HIBP API key or access denied",
                        meta={"http_status": resp.status_code},
                    )
                if resp.status_code != 200:
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        error=f"HTTP {resp.status_code}",
                        meta={"http_status": resp.status_code},
                    )

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

                return ProviderResult(
                    provider=self.name,
                    status="ok",
                    payload={
                        "breached": len(normalized) > 0,
                        "total_breaches": len(normalized),
                        "breaches": normalized,
                    },
                    meta={"http_status": 200},
                )
            except Exception as exc:
                logger.warning("[HIBP_Breach] HIBP lookup failed: %s", exc)
                return ProviderResult(provider=self.name, status="error", error=str(exc))


class HIBPBreachModule(BaseModule):
    name = "HIBP_Breach"
    version = "1.1.0"
    description = "Checks HaveIBeenPwned breaches for an email address (provider abstraction, HIBP backend)."
    target_types = ["email"]
    author = "OSINT_Framework_Team"
    timeout = 12

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Checking HIBP breaches for %s", self.name, target)
        provider = HIBPApiProvider()
        result = await provider.lookup(self, target)
        return result.to_module_output()
