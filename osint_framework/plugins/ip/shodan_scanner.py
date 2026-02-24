import os
from typing import Dict, Any

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule

class ShodanModule(BaseModule):
    name = "Shodan_Scanner"
    version = "1.0.0"
    description = "Queries Shodan if an API Key is present in environment for open ports/vulns."
    target_types = ["ip"]
    author = "OSINT_Framework_Team"
    timeout = 15

    async def run(self, target: str) -> Dict[str, Any]:
        """Fetch host details from Shodan REST API."""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            logger.debug(f"[{self.name}] No SHODAN_API_KEY found. Skipping.")
            return {"error": "Module requires SHODAN_API_KEY environment variable"}
            
        url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
        logger.debug(f"[{self.name}] Querying Shodan for {target}")
        
        async with self.get_client() as client:
            try:
                resp = await client.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "os": data.get("os"),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", [])
                    }
                elif resp.status_code == 404:
                    return {"info": "Not found in Shodan database"}
                elif resp.status_code == 401:
                    return {"error": "Invalid Shodan API Key"}
                else:
                    return {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}
