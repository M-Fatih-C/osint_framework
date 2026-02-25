import asyncio
from typing import Dict, Any, Set

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule

class ThreatMinerSubdomainProvider:
    name = "threatminer"

    async def lookup(self, module: BaseModule, target: str) -> ProviderResult:
        url = f"https://api.threatminer.org/v2/domain.php?q={target}&rt=5"
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
                data = resp.json()
                if data.get("status_code") == "200" and data.get("results"):
                    found = sorted({str(x).strip().lower() for x in data["results"] if str(x).strip()})
                    return ProviderResult(
                        provider=self.name,
                        status="ok",
                        payload={"subdomains": found},
                        meta={"count": len(found)},
                    )
                return ProviderResult(
                    provider=self.name,
                    status="ok",
                    payload={"subdomains": []},
                    meta={"count": 0},
                )
            except Exception as exc:
                logger.warning("[%s] ThreatMiner err: %s", module.name, exc)
                return ProviderResult(provider=self.name, status="error", error=str(exc))


class CrtShSubdomainProvider:
    name = "crtsh"

    async def lookup(self, module: BaseModule, target: str) -> ProviderResult:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        subdomains: Set[str] = set()
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
                data = resp.json()
                for item in data if isinstance(data, list) else []:
                    name_value = item.get("name_value", "")
                    if not name_value:
                        continue
                    for sub in str(name_value).split('\n'):
                        clean_sub = sub.strip().lower()
                        if clean_sub.endswith(target) and not clean_sub.startswith("*"):
                            subdomains.add(clean_sub)
                found = sorted(subdomains)
                return ProviderResult(
                    provider=self.name,
                    status="ok",
                    payload={"subdomains": found},
                    meta={"count": len(found)},
                )
            except Exception as exc:
                logger.warning("[%s] crt.sh err: %s", module.name, exc)
                return ProviderResult(provider=self.name, status="error", error=str(exc))


class SubdomainModule(BaseModule):
    name = "Subdomain_Scanner"
    version = "1.1.0"
    description = "Discovers subdomains using provider abstraction (ThreatMiner + crt.sh)."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 30

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug(f"[{self.name}] Scanning subdomains for {target}")
        subdomains: Set[str] = set()
        providers = [ThreatMinerSubdomainProvider(), CrtShSubdomainProvider()]
        results = await asyncio.gather(*(p.lookup(self, target) for p in providers))

        sources: Dict[str, Dict[str, Any]] = {}
        provider_errors: Dict[str, str] = {}
        for provider in results:
            pdata = provider.payload or {}
            found = pdata.get("subdomains") or []
            subdomains.update(
                s.strip().lower()
                for s in found
                if isinstance(s, str) and s.strip().lower().endswith(target.lower())
            )
            sources[provider.provider] = {
                "status": provider.status,
                "count": len(found) if isinstance(found, list) else 0,
            }
            if provider.error:
                provider_errors[provider.provider] = provider.error

        return {
            "total_found": len(subdomains),
            "subdomains": sorted(subdomains),
            "provider": "multi",
            "status": "ok",
            "provider_chain": [p.name for p in providers],
            "provider_meta": {
                "source_count": len(providers),
                "sources": sources,
            },
            "provider_errors": provider_errors,
        }
