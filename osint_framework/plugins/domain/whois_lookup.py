import asyncio
from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class WhoisLookupModule(BaseModule):
    name = "WHOIS_Lookup"
    version = "1.0.0"
    description = "Performs WHOIS lookup using python-whois (if installed)."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 15

    @staticmethod
    def _normalize_value(value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple, set)):
            return [WhoisLookupModule._normalize_value(v) for v in value]
        return str(value)

    def _lookup(self, target: str) -> Dict[str, Any]:
        try:
            import whois  # lazy import to avoid import-time failure if dependency is absent
        except Exception as exc:
            return {"error": f"python-whois unavailable: {exc}"}

        data = whois.whois(target)
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
        return summary

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Running WHOIS lookup for %s", self.name, target)
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._lookup, target),
                timeout=self.timeout,
            )
        except Exception as exc:
            return {"error": str(exc)}

