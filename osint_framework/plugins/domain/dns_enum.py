import asyncio
from typing import Dict, Any, List

import dns.asyncresolver

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule

class DnspythonResolverProvider:
    name = "dnspython-resolver"
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    async def lookup(self, target: str) -> ProviderResult:
        results: Dict[str, List[str]] = {}
        errors: Dict[str, str] = {}

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        async def fetch_record(rtype: str):
            try:
                answers = await resolver.resolve(target, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[rtype] = []
            except dns.resolver.NXDOMAIN:
                results[rtype] = ["domain_not_found"]
                errors[rtype] = "NXDOMAIN"
            except Exception as exc:
                msg = str(exc)
                results[rtype] = [f"error: {msg}"]
                errors[rtype] = msg

        await asyncio.gather(*(fetch_record(rt) for rt in self.record_types))
        return ProviderResult(
            provider=self.name,
            status="ok",
            payload=results,
            meta={
                "record_types": list(self.record_types),
                "error_count": len(errors),
                "record_errors": errors,
            },
        )


class DNSEnumModule(BaseModule):
    name = "DNS_Enum"
    version = "1.1.0"
    description = "Retrieves various DNS records using provider abstraction (dnspython backend)."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 20

    async def run(self, target: str) -> Dict[str, Any]:
        """Fetch multiple DNS records concurrently for a domain."""
        logger.debug(f"[{self.name}] Fetching DNS records for {target}")
        provider = DnspythonResolverProvider()
        try:
            result = await asyncio.wait_for(provider.lookup(target), timeout=self.timeout)
            return result.to_module_output() if isinstance(result, ProviderResult) else {
                "provider": provider.name,
                "status": "error",
                "error": "Invalid provider result",
            }
        except Exception as exc:
            return {
                "provider": provider.name,
                "status": "error",
                "error": str(exc),
                "provider_meta": {"reason": "timeout_or_runtime"},
            }
