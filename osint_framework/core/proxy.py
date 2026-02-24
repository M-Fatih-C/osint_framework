import random
from pathlib import Path
from typing import List, Optional

import httpx

from osint_framework.core.config import settings
from osint_framework.core.logger import logger

class ProxyManager:
    """Manages proxy rotation for stealth operations."""
    
    def __init__(self):
        self.enabled = settings.proxy.enabled
        self.proxies: List[str] = []
        self._load_proxies()
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ]

    def _load_proxies(self):
        if not self.enabled or not settings.proxy.list_file:
            return
            
        proxy_file = Path(settings.proxy.list_file)
        if proxy_file.exists():
            with open(proxy_file, 'r', encoding='utf-8') as f:
                self.proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"Loaded {len(self.proxies)} proxies from {proxy_file}")
        else:
            logger.warning(f"Proxy file {settings.proxy.list_file} not found. Running directly.")

    def get_random_proxy(self) -> Optional[str]:
        """Returns a random proxy from the pool, or None if disabled/empty."""
        if not self.enabled or not self.proxies:
            return None
        return random.choice(self.proxies)

    def get_random_user_agent(self) -> str:
        """Returns a random modern User-Agent."""
        return random.choice(self.user_agents)
        
    def get_client(self, timeout: int = 15) -> httpx.AsyncClient:
        """
        Returns a configured httpx.AsyncClient with proxy (if enabled)
        and a randomized User-Agent header.
        """
        proxy_url = self.get_random_proxy()
        headers = {"User-Agent": self.get_random_user_agent()}
        
        if proxy_url:
            return httpx.AsyncClient(proxies={"all://": proxy_url}, headers=headers, timeout=timeout)
        return httpx.AsyncClient(headers=headers, timeout=timeout)

proxy_manager = ProxyManager()
