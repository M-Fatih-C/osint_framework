from typing import Any, Dict

from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.person.person_name_utils import (
    build_name_analysis,
    generate_email_local_parts,
    generate_username_candidates,
)


class PersonNameHandleGeneratorModule(BaseModule):
    name = "Person_Name_Handle_Generator"
    version = "1.0.0"
    description = "Generates username and email local-part candidates from a full name."
    target_types = ["person_name"]
    author = "OSINT_Framework_Team"

    async def run(self, target: str) -> Dict[str, Any]:
        analysis = build_name_analysis(target)
        usernames = generate_username_candidates(target, limit=80)
        email_locals = generate_email_local_parts(target, limit=50)

        conservative = usernames[:15]
        extended = usernames[15:50]

        return {
            "target_person_name": target,
            "normalized_name": analysis["normalized"],
            "ascii_transliteration": analysis["ascii_transliteration"],
            "username_candidates_total": len(usernames),
            "username_candidates": {
                "conservative": conservative,
                "extended": extended,
                "all": usernames,
            },
            "recommended_username_scan_targets": conservative[:8],
            "email_local_part_candidates": email_locals,
            "next_steps": [
                "Run Username target type scans with conservative candidates first.",
                "Use Maigret-backed Username_Checker for the highest-confidence handles.",
                "Combine with person-name search dorks for profile correlation.",
            ],
        }
