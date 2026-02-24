from typing import Any, Dict

from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.person.person_name_utils import build_name_analysis


class PersonNameAnalyzerModule(BaseModule):
    name = "Person_Name_Analyzer"
    version = "1.0.0"
    description = "Normalizes a full name, extracts parts/initials, and generates canonical variants."
    target_types = ["person_name"]
    author = "OSINT_Framework_Team"

    async def run(self, target: str) -> Dict[str, Any]:
        info = build_name_analysis(target)
        return {
            "target_person_name": target,
            "normalized_name": info["normalized"],
            "name_parts": info["parts"],
            "part_count": info["part_count"],
            "first_name": info["first_name"],
            "middle_names": info["middle_names"],
            "last_name": info["last_name"],
            "initials": info["initials"],
            "ascii_transliteration": info["ascii_transliteration"],
            "name_variants": info["variants"],
            "notes": [
                "Use transliterated variants for username and email pivoting.",
                "Use exact-quote variants in search engines for precision.",
            ],
        }
