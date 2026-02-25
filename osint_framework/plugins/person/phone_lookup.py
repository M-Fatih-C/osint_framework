import os
import re
from typing import Dict

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class LocalPhoneAnalysisProvider:
    name = "local-phone-analysis"
    COUNTRY_HINTS = {
        "1": "North America",
        "44": "United Kingdom",
        "49": "Germany",
        "90": "Turkey",
        "33": "France",
        "39": "Italy",
        "34": "Spain",
        "91": "India",
        "81": "Japan",
    }

    @staticmethod
    def _normalize(number: str) -> str:
        cleaned = re.sub(r"[^\d+]", "", number)
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        if cleaned and not cleaned.startswith("+"):
            cleaned = "+" + cleaned
        return cleaned

    def _country_hint(self, normalized: str) -> str:
        digits = normalized.lstrip("+")
        for prefix in sorted(self.COUNTRY_HINTS.keys(), key=len, reverse=True):
            if digits.startswith(prefix):
                return self.COUNTRY_HINTS[prefix]
        return "Unknown"

    def analyze(self, target: str) -> ProviderResult:
        normalized = self._normalize(target)
        digits = re.sub(r"\D", "", normalized)
        result: Dict[str, str] = {
            "input": target,
            "normalized": normalized,
            "digits_only": digits,
            "is_possible_length": str(7 <= len(digits) <= 15),
            "country_hint": self._country_hint(normalized),
            "enrichment": "local_analysis_only",
        }
        return ProviderResult(
            provider=self.name,
            status="ok",
            payload=result,
            meta={"digit_count": len(digits)},
        )


class NumverifyPhoneProvider:
    name = "numverify"

    async def enrich(self, module: BaseModule, base_payload: Dict[str, str]) -> ProviderResult:
        api_key = os.getenv("NUMVERIFY_API_KEY")
        if not api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                payload=base_payload,
                error="NUMVERIFY_API_KEY not configured",
                meta={"reason": "missing_api_key"},
            )

        url = "http://apilayer.net/api/validate"
        async with module.get_client() as client:
            try:
                normalized = base_payload.get("normalized") or ""
                resp = await client.get(
                    url,
                    params={"access_key": api_key, "number": normalized, "format": 1},
                    timeout=module.timeout,
                )
                if resp.status_code != 200:
                    payload = dict(base_payload)
                    payload["enrichment"] = f"numverify_http_{resp.status_code}"
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        payload=payload,
                        error=f"HTTP {resp.status_code}",
                        meta={"http_status": resp.status_code},
                    )
                data = resp.json()
                if "error" in data:
                    payload = dict(base_payload)
                    payload["enrichment"] = "numverify_error"
                    payload["numverify_error"] = str(data.get("error"))
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        payload=payload,
                        error="Numverify API error",
                        meta={"reason": "api_error"},
                    )

                payload = dict(base_payload)
                payload.update(
                    {
                        "enrichment": "numverify",
                        "valid": str(data.get("valid")),
                        "international_format": str(data.get("international_format")),
                        "local_format": str(data.get("local_format")),
                        "country_name": str(data.get("country_name")),
                        "location": str(data.get("location")),
                        "carrier": str(data.get("carrier")),
                        "line_type": str(data.get("line_type")),
                    }
                )
                return ProviderResult(
                    provider=self.name,
                    status="ok",
                    payload=payload,
                    meta={"http_status": resp.status_code},
                )
            except Exception as exc:
                payload = dict(base_payload)
                payload["enrichment"] = "numverify_exception"
                payload["numverify_error"] = str(exc)
                return ProviderResult(
                    provider=self.name,
                    status="error",
                    payload=payload,
                    error=str(exc),
                    meta={"reason": "request_exception"},
                )


class PhoneLookupModule(BaseModule):
    name = "Phone_Lookup"
    version = "1.1.0"
    description = "Performs phone analysis using provider abstraction (local + optional Numverify)."
    target_types = ["phone"]
    author = "OSINT_Framework_Team"
    timeout = 10

    async def run(self, target: str) -> Dict[str, str]:
        local_provider = LocalPhoneAnalysisProvider()
        base_result = local_provider.analyze(target)
        payload: Dict[str, str] = base_result.to_module_output()

        numverify_provider = NumverifyPhoneProvider()
        try:
            enriched = await numverify_provider.enrich(self, dict(base_result.payload))
        except Exception as exc:
            logger.warning("[%s] Numverify provider failed unexpectedly: %s", self.name, exc)
            payload["enrichment"] = "numverify_exception"
            payload["numverify_error"] = str(exc)
            payload.setdefault("provider_chain", ["local-phone-analysis", "numverify"])
            return payload

        if enriched.status != "skipped":
            payload.update(enriched.payload or {})
            payload["provider"] = enriched.provider
            if enriched.error:
                payload["error"] = enriched.error
            if enriched.meta:
                payload["provider_meta"] = enriched.meta
        else:
            payload.setdefault("provider", local_provider.name)
            payload.setdefault("provider_meta", base_result.meta)

        payload.setdefault("provider_chain", [local_provider.name, numverify_provider.name])
        return payload
