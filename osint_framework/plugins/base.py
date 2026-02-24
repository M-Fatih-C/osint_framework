from abc import ABC, abstractmethod
from typing import Dict, Any, List
import httpx

from osint_framework.core.proxy import proxy_manager

class BaseModule(ABC):
    name: str = "BaseModule"
    version: str = "1.0.0"
    description: str = "Abstract Base Module"
    target_types: List[str] = []
    author: str = "Developer"
    
    # Execution configs
    timeout: int = 15
    retries: int = 3
    
    def get_client(self) -> httpx.AsyncClient:
        """Helper to get a pre-configured AsyncClient with Proxy and rotation."""
        return proxy_manager.get_client(timeout=self.timeout)
    
    @abstractmethod
    async def run(self, target: str) -> Dict[str, Any]:
        """
        Main execution logic for the module.
        Must handle exceptions gracefully and return dict data.
        """
        pass
