from typing import Any, Dict, List


class VisionReportBuilder:
    """Builds a compact report block for vision pipeline results."""

    @staticmethod
    def from_job_data(job_data: Dict[str, Any]) -> Dict[str, Any]:
        results = job_data.get("results") or []
        vision_item = next((r for r in results if r.get("module") == "Vision_Image_OSINT"), None)
        if not vision_item:
            return {
                "target": job_data.get("target"),
                "vision": None,
                "note": "No vision pipeline output in this job.",
            }

        data = vision_item.get("data") or {}
        links: List[str] = []
        seen = set()
        for item in data.get("reverse_image_results") or []:
            url = item.get("url")
            if not isinstance(url, str):
                continue
            key = url.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            links.append(url)

        similarity_matches = data.get("similarity_matches") or []
        compact_similarity = []
        for item in similarity_matches[:10]:
            if not isinstance(item, dict):
                continue
            compact_similarity.append(
                {
                    "score": item.get("score"),
                    "matched_image_path": item.get("matched_image_path"),
                    "matched_face_ref": item.get("matched_face_ref"),
                }
            )

        return {
            "target": job_data.get("target"),
            "target_type": job_data.get("target_type"),
            "faces_detected": int(data.get("faces_detected") or 0),
            "similarity_matches_total": int(data.get("similarity_matches_total") or 0),
            "similarity_matches": compact_similarity,
            "reverse_image_results": links,
            "entities": data.get("entities") or [],
            "status": data.get("status") or "unknown",
        }
