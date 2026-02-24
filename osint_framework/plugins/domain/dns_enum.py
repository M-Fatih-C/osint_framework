import asyncio
from typing import Dict, Any, List

import dns.asyncresolver

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule

class DNSEnumModule(BaseModule):
    name = "DNS_Enum"
    version = "1.0.0"
    description = "Retrieves various DNS records (A, AAAA, MX, NS, TXT) for a given domain."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 20

    async def run(self, target: str) -> Dict[str, Any]:
        """Fetch multiple DNS records concurrently for a domain."""
        logger.debug(f"[{self.name}] Fetching DNS records for {target}")
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        results: Dict[str, List[str]] = {}
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
            except Exception as e:
                results[rtype] = [f"error: {str(e)}"]

        tasks = [fetch_record(rt) for rt in record_types]
        await asyncio.gather(*tasks)
        
        return results
