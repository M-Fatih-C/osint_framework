import os
import re
from typing import Dict

from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


class PhoneLookupModule(BaseModule):
    name = "Phone_Lookup"
    version = "1.0.0"
    description = "Performs basic phone format analysis and optional Numverify enrichment."
    target_types = ["phone"]
    author = "OSINT_Framework_Team"
    timeout = 10

    COUNTRY_HINTS = {
        "1": "North America",
        "44": "United Kingdom",
        "49": "Germany",
        "90": "Turkey",
        "33": "France",
        "39": "Italy",
        "34": "Spain",
        "91": "India",
        "81": "Japan",
    }

    @staticmethod
    def _normalize(number: str) -> str:
        cleaned = re.sub(r"[^\d+]", "", number)
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        if cleaned and not cleaned.startswith("+"):
            cleaned = "+" + cleaned
        return cleaned

    def _country_hint(self, normalized: str) -> str:
        digits = normalized.lstrip("+")
        for prefix in sorted(self.COUNTRY_HINTS.keys(), key=len, reverse=True):
            if digits.startswith(prefix):
                return self.COUNTRY_HINTS[prefix]
        return "Unknown"

    async def run(self, target: str) -> Dict[str, str]:
        normalized = self._normalize(target)
        digits = re.sub(r"\D", "", normalized)
        result: Dict[str, str] = {
            "input": target,
            "normalized": normalized,
            "digits_only": digits,
            "is_possible_length": str(7 <= len(digits) <= 15),
            "country_hint": self._country_hint(normalized),
            "enrichment": "local_analysis_only",
        }

        api_key = os.getenv("NUMVERIFY_API_KEY")
        if not api_key:
            return result

        url = "http://apilayer.net/api/validate"
        async with self.get_client() as client:
            try:
                resp = await client.get(
                    url,
                    params={"access_key": api_key, "number": normalized, "format": 1},
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    result["enrichment"] = f"numverify_http_{resp.status_code}"
                    return result
                data = resp.json()
                if "error" in data:
                    result["enrichment"] = "numverify_error"
                    result["numverify_error"] = str(data.get("error"))
                    return result

                result.update(
                    {
                        "enrichment": "numverify",
                        "valid": str(data.get("valid")),
                        "international_format": str(data.get("international_format")),
                        "local_format": str(data.get("local_format")),
                        "country_name": str(data.get("country_name")),
                        "location": str(data.get("location")),
                        "carrier": str(data.get("carrier")),
                        "line_type": str(data.get("line_type")),
                    }
                )
                return result
            except Exception as exc:
                logger.warning("[%s] Numverify lookup failed: %s", self.name, exc)
                result["enrichment"] = "numverify_exception"
                result["numverify_error"] = str(exc)
                return result

