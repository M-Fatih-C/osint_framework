import httpx
from typing import Dict, Any

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule

class GeoIPModule(BaseModule):
    name = "GeoIP"
    version = "1.0.0"
    description = "Fetches geolocation data for an IP address using ip-api.com."
    target_types = ["ip"]
    author = "OSINT_Framework_Team"
    timeout = 10

    async def run(self, target: str) -> Dict[str, Any]:
        """Fetch geolocation for the given IP address."""
        url = f"http://ip-api.com/json/{target}"
        logger.debug(f"[{self.name}] Fetching data for {target}")
        
        async with self.get_client() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                if data.get("status") == "fail":
                    return {"error": data.get("message", "Unknown error")}
                    
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "raw": data
                }
            except httpx.RequestError as e:
                logger.error(f"[{self.name}] Request failed for {target}: {e}")
                raise e
