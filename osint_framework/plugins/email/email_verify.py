import dns.asyncresolver
from typing import Any, Dict, List

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class EmailVerifyModule(BaseModule):
    name = "Email_Verify"
    version = "1.0.0"
    description = "Performs lightweight email verification (syntax + MX lookup)."
    target_types = ["email"]
    author = "OSINT_Framework_Team"
    timeout = 10

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

    async def run(self, target: str) -> Dict[str, Any]:
        logger.debug("[%s] Verifying email %s", self.name, target)
        local, domain = self._split_email(target)
        if not local or not domain:
            return {"valid_syntax": False, "error": "Invalid email format"}

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

        return result

