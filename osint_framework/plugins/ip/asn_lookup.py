from typing import Any, Dict

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class ASNLookupModule(BaseModule):
    name = "ASN_Lookup"
    version = "1.0.0"
    description = "Queries bgpview.io for ASN/prefix information about an IP."
    target_types = ["ip"]
    author = "OSINT_Framework_Team"
    timeout = 12

    async def run(self, target: str) -> Dict[str, Any]:
        url = f"https://api.bgpview.io/ip/{target}"
        logger.debug("[%s] Fetching ASN data for %s", self.name, target)
        async with self.get_client() as client:
            try:
                resp = await client.get(url, timeout=self.timeout)
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                payload = resp.json()
                data = payload.get("data", {}) if isinstance(payload, dict) else {}
                prefixes = data.get("prefixes") or []
                first = prefixes[0] if prefixes else {}
                asn = first.get("asn") if isinstance(first, dict) else None
                return {
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
                }
            except Exception as exc:
                return {"error": str(exc)}

