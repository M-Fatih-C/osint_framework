import asyncio
from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class PythonWhoisProvider:
    @staticmethod
    def _normalize_value(value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple, set)):
            return [PythonWhoisProvider._normalize_value(v) for v in value]
        return str(value)

    def lookup(self, target: str) -> ProviderResult:
        try:
            import whois  # lazy import to avoid import-time failure if dependency is absent
        except Exception as exc:
            return ProviderResult(
                provider="python-whois",
                status="skipped",
                error=f"python-whois unavailable: {exc}",
                meta={"reason": "dependency_unavailable"},
            )

        try:
            data = whois.whois(target)
        except Exception as exc:
            return ProviderResult(
                provider="python-whois",
                status="error",
                error=str(exc),
                meta={"reason": "lookup_failed"},
            )
        if hasattr(data, "_data"):
            raw = dict(data._data)
        elif isinstance(data, dict):
            raw = data
        else:
            raw = {"raw": str(data)}

        normalized = {k: self._normalize_value(v) for k, v in raw.items()}
        keys = [
            "domain_name",
            "registrar",
            "whois_server",
            "creation_date",
            "expiration_date",
            "updated_date",
            "name_servers",
            "status",
            "emails",
            "dnssec",
        ]
        summary = {k: normalized.get(k) for k in keys if k in normalized}
        summary["raw"] = normalized
        return ProviderResult(
            provider="python-whois",
            status="ok",
            payload=summary,
            meta={"field_count": len(normalized)},
        )


class WhoisLookupModule(BaseModule):
    name = "WHOIS_Lookup"
    version = "1.1.0"
    description = "Performs WHOIS lookup using provider abstraction (python-whois backend)."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 15

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Running WHOIS lookup for %s", self.name, target)
        provider = PythonWhoisProvider()
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(provider.lookup, target),
                timeout=self.timeout,
            )
            if isinstance(result, ProviderResult):
                return result.to_module_output()
            return {"provider": "python-whois", "status": "error", "error": "Invalid provider result"}
        except Exception as exc:
            return {
                "provider": "python-whois",
                "status": "error",
                "error": str(exc),
                "provider_meta": {"reason": "timeout_or_runtime"},
            }
