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

        return {
            "target": job_data.get("target"),
            "target_type": job_data.get("target_type"),
            "faces_detected": int(data.get("faces_detected") or 0),
            "reverse_image_results": links,
            "entities": data.get("entities") or [],
            "status": data.get("status") or "unknown",
        }
