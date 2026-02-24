from typing import Any, Dict, List

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.person.username_providers import (
    BasicHttpUsernameProvider,
    MaigretUsernameProvider,
    UsernameProvider,
)


class UsernameModule(BaseModule):
    name = "Username_Checker"
    version = "2.1.0"
    description = (
        "Checks username presence across social platforms via provider chain "
        "(Maigret primary, HTTP fallback secondary)."
    )
    target_types = ["username"]
    author = "OSINT_Framework_Team"
    timeout = 90

    # Lightweight fallback provider platforms.
    PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Twitter": "https://twitter.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Reddit": "https://www.reddit.com/user/{}/",
    }

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Starting username scan for: %s", self.name, target)

        provider_metas: Dict[str, Dict[str, Any]] = {}
        for provider in self._build_providers():
            outcome = await provider.scan(target)
            if outcome.meta:
                provider_metas[outcome.provider] = outcome.meta

            if outcome.success and outcome.data is not None:
                result = outcome.data
                # Preserve Maigret diagnostics when fallback provider is used.
                if outcome.provider != "maigret" and "maigret" in provider_metas:
                    result.setdefault("maigret", provider_metas["maigret"])
                return result

        # This path should be rare because the fallback provider is expected to succeed.
        return {
            "provider": "username_provider_chain",
            "target_username": target,
            "error": "All username providers failed",
            "providers": provider_metas,
        }

    def _build_providers(self) -> List[UsernameProvider]:
        return [
            MaigretUsernameProvider(self),
            BasicHttpUsernameProvider(self, self.PLATFORMS),
        ]
