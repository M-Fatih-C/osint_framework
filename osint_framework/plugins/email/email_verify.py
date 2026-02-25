import dns.asyncresolver
from typing import Any, Dict, List

from osint_framework.core.logger import logger
from osint_framework.core.provider_models import ProviderResult
from osint_framework.plugins.base import BaseModule


class DnsEmailVerificationProvider:
    name = "dnspython-email"

    @staticmethod
    def _split_email(target: str):
        if "@" not in target or target.count("@") != 1:
            return None, None
        local, domain = target.rsplit("@", 1)
        return local.strip(), domain.strip().lower()

    async def _resolve(self, domain: str, record_type: str) -> List[str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 4
        answers = await resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]

    async def verify(self, target: str) -> ProviderResult:
        local, domain = self._split_email(target)
        if not local or not domain:
            return ProviderResult(
                provider=self.name,
                status="error",
                error="Invalid email format",
                payload={"valid_syntax": False},
                meta={"reason": "invalid_format"},
            )

        result: Dict[str, Any] = {
            "valid_syntax": True,
            "local_part": local,
            "domain": domain,
            "mx_records": [],
            "a_records": [],
            "deliverability_estimate": "unknown",
        }

        try:
            mx_records = await self._resolve(domain, "MX")
            result["mx_records"] = mx_records
            result["deliverability_estimate"] = "likely_deliverable" if mx_records else "unknown"
        except Exception as exc:
            result["mx_lookup_error"] = str(exc)

        try:
            result["a_records"] = await self._resolve(domain, "A")
        except Exception as exc:
            result["a_lookup_error"] = str(exc)

        if not result["mx_records"] and result["a_records"]:
            result["deliverability_estimate"] = "fallback_to_a_record"
        elif not result["mx_records"] and not result["a_records"]:
            result["deliverability_estimate"] = "undeliverable_or_unresolvable"

        return ProviderResult(
            provider=self.name,
            status="ok",
            payload=result,
            meta={
                "mx_count": len(result.get("mx_records") or []),
                "a_count": len(result.get("a_records") or []),
            },
        )


class EmailVerifyModule(BaseModule):
    name = "Email_Verify"
    version = "1.1.0"
    description = "Performs lightweight email verification using provider abstraction (dnspython backend)."
    target_types = ["email"]
    author = "OSINT_Framework_Team"
    timeout = 10

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Verifying email %s", self.name, target)
        provider = DnsEmailVerificationProvider()
        try:
            result = await provider.verify(target)
            return result.to_module_output()
        except Exception as exc:
            return {
                "provider": provider.name,
                "status": "error",
                "valid_syntax": False,
                "error": str(exc),
                "provider_meta": {"reason": "provider_runtime"},
            }
