import re
from typing import Any, Dict, List, Optional

from osint_framework.core.logger import logger
from osint_framework.core.normalization import IntelNormalizer


class Correlator:
    """
    Intelligence Correlation Engine
    Finds relationships between different intelligence data points.
    """

    @staticmethod
    def analyze(
        results: List[Dict[str, Any]],
        *,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Merge results and find correlations like Email -> Domain -> IP.
        """
        merged_data = {}
        extracted_emails = set()
        extracted_domains = set()
        extracted_ips = set()
        extracted_similarity_matches = 0

        for result in results:
            mod_name = result.get("module")
            data = result.get("data", {})

            # Simple merge
            merged_data[mod_name] = data

            # Extract common indicators (naive regex extract for demonstration)
            text_repr = str(data)

            # Extract IPs
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_repr)
            extracted_ips.update(ips)

            # Extract Emails
            emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text_repr)
            extracted_emails.update(emails)

            if mod_name == "Vision_Image_OSINT" and isinstance(data, dict):
                extracted_similarity_matches += len(data.get("similarity_matches") or [])

        normalized = IntelNormalizer.build(
            results,
            target=target,
            target_type=target_type,
        )

        # Enrich counters from normalized graph.
        normalized_entities = normalized.get("entities") or []
        normalized_relations = normalized.get("relations") or []

        normalized_domains = {
            ent.get("value")
            for ent in normalized_entities
            if ent.get("type") == "domain" and ent.get("value")
        }
        normalized_emails = {
            ent.get("value")
            for ent in normalized_entities
            if ent.get("type") == "email" and ent.get("value")
        }
        normalized_ips = {
            ent.get("value")
            for ent in normalized_entities
            if ent.get("type") == "ip" and ent.get("value")
        }
        normalized_faces = {
            ent.get("value")
            for ent in normalized_entities
            if ent.get("type") == "face" and ent.get("value")
        }
        normalized_images = {
            ent.get("value")
            for ent in normalized_entities
            if ent.get("type") == "image" and ent.get("value")
        }
        normalized_similarity_edges = [
            rel
            for rel in normalized_relations
            if rel.get("type") in {"similar_to_image", "similar_to_face_reference"}
        ]

        extracted_domains.update(normalized_domains)
        extracted_emails.update(normalized_emails)
        extracted_ips.update(normalized_ips)
        extracted_similarity_matches = max(
            extracted_similarity_matches,
            len(normalized_similarity_edges),
        )

        logger.debug(
            "Correlator found %d emails, %d IPs, %d domains, %d faces and built %d normalized entities.",
            len(extracted_emails),
            len(extracted_ips),
            len(extracted_domains),
            len(normalized_faces),
            len(normalized_entities),
        )

        return {
            "raw_results": merged_data,
            "correlations": {
                "emails_found": list(extracted_emails),
                "ips_found": list(extracted_ips),
                "domains_found": list(extracted_domains),
                "faces_found": list(normalized_faces),
                "images_found": list(normalized_images),
                "similarity_matches_found": extracted_similarity_matches,
            },
            "normalized": normalized,
        }
