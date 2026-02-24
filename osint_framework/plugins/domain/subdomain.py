import asyncio
from typing import Dict, Any, Set

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule

class SubdomainModule(BaseModule):
    name = "Subdomain_Scanner"
    version = "1.0.0"
    description = "Discovers subdomains using ThreatMiner and crt.sh."
    target_types = ["domain"]
    author = "OSINT_Framework_Team"
    timeout = 30

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug(f"[{self.name}] Scanning subdomains for {target}")
        subdomains: Set[str] = set()
        
        async def fetch_threatminer():
            url = f"https://api.threatminer.org/v2/domain.php?q={target}&rt=5"
            async with self.get_client() as client:
                try:
                    resp = await client.get(url, timeout=self.timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status_code") == "200" and data.get("results"):
                            subdomains.update(data["results"])
                except Exception as e:
                    logger.warning(f"[{self.name}] ThreatMiner err: {e}")

        async def fetch_crtsh():
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            async with self.get_client() as client:
                try:
                    resp = await client.get(url, timeout=self.timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data:
                            name_value = item.get("name_value", "")
                            if name_value:
                                # crt.sh sometimes returns multiple subdomains separated by newlines
                                for sub in name_value.split('\n'):
                                    clean_sub = sub.strip().lower()
                                    if clean_sub.endswith(target) and not clean_sub.startswith("*"):
                                        subdomains.add(clean_sub)
                except Exception as e:
                    logger.warning(f"[{self.name}] crt.sh err: {e}")

        await asyncio.gather(fetch_threatminer(), fetch_crtsh())
        
        return {
            "total_found": len(subdomains),
            "subdomains": list(subdomains)
        }
