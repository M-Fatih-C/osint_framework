from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class BgpViewAsnProvider:
    name = "bgpview"

    async def lookup(self, module: BaseModule, target: str) -> ProviderResult:
        url = f"https://api.bgpview.io/ip/{target}"
        async with module.get_client() as client:
            try:
                resp = await client.get(url, timeout=module.timeout)
                if resp.status_code != 200:
                    return ProviderResult(
                        provider=self.name,
                        status="error",
                        error=f"HTTP {resp.status_code}",
                        meta={"http_status": resp.status_code},
                    )
                payload = resp.json()
                data = payload.get("data", {}) if isinstance(payload, dict) else {}
                prefixes = data.get("prefixes") or []
                first = prefixes[0] if prefixes else {}
                asn = first.get("asn") if isinstance(first, dict) else None
                return ProviderResult(
                    provider=self.name,
                    status="ok",
                    payload={
                        "ip": data.get("ip", target),
                        "rir_allocation": data.get("rir_allocation"),
                        "prefix_count": len(prefixes),
                        "prefixes": prefixes[:20],  # avoid huge payloads
                        "primary_prefix": {
                            "prefix": first.get("prefix"),
                            "name": (asn or {}).get("name") if isinstance(asn, dict) else None,
                            "asn": (asn or {}).get("asn") if isinstance(asn, dict) else None,
                            "description": (asn or {}).get("description")
                            if isinstance(asn, dict)
                            else None,
                            "country_code": (asn or {}).get("country_code")
                            if isinstance(asn, dict)
                            else None,
                        },
                    },
                    meta={"http_status": resp.status_code, "prefixes_returned": len(prefixes[:20])},
                )
            except Exception as exc:
                return ProviderResult(provider=self.name, status="error", error=str(exc))


class ASNLookupModule(BaseModule):
    name = "ASN_Lookup"
    version = "1.1.0"
    description = "Queries ASN providers for IP prefix/intelligence (bgpview backend)."
    target_types = ["ip"]
    author = "OSINT_Framework_Team"
    timeout = 12

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Fetching ASN data for %s", self.name, target)
        provider = BgpViewAsnProvider()
        result = await provider.lookup(self, target)
        return result.to_module_output()
