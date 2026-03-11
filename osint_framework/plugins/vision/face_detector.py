from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from osint_framework.core.logger import logger


class VisionFaceDetector:
    """Face detection with provider chain (RetinaFace -> OpenCV -> full-image fallback)."""

    def detect_faces(self, image_path: str) -> Dict[str, Any]:
        provider_errors: Dict[str, str] = {}

        for provider in (self._detect_with_retinaface, self._detect_with_opencv):
            provider_name = provider.__name__.replace("_detect_with_", "")
            try:
                result = provider(image_path)
            except Exception as exc:  # defensive
                provider_errors[provider_name] = str(exc)
                continue

            faces = result.get("faces") if isinstance(result, dict) else None
            if faces:
                result.setdefault("status", "ok")
                result["provider_errors"] = provider_errors
                return result

            provider_errors[provider_name] = result.get("reason", "no_faces") if isinstance(result, dict) else "no_faces"

        # Fallback keeps pipeline operable even if no detector dependency is installed.
        fallback_dims = self._probe_dimensions(image_path)
        if fallback_dims:
            width, height = fallback_dims
            return {
                "status": "ok",
                "provider": "full_image_fallback",
                "faces": [
                    {
                        "face_id": "face_1",
                        "bbox": [0, 0, width, height],
                        "confidence": 0.05,
                    }
                ],
                "provider_errors": provider_errors,
                "fallback": True,
            }

        return {
            "status": "error",
            "provider": "none",
            "faces": [],
            "provider_errors": provider_errors,
            "reason": "Could not load image for face detection",
        }

    def _detect_with_retinaface(self, image_path: str) -> Dict[str, Any]:
        try:
            from retinaface import RetinaFace
        except Exception as exc:
            return {"status": "skipped", "faces": [], "reason": f"retinaface unavailable: {exc}"}

        try:
            raw = RetinaFace.detect_faces(image_path)
        except Exception as exc:
            return {"status": "error", "faces": [], "reason": str(exc)}

        faces: List[Dict[str, Any]] = []
        if isinstance(raw, dict):
            for key, item in raw.items():
                if not isinstance(item, dict):
                    continue
                area = item.get("facial_area")
                if not isinstance(area, (list, tuple)) or len(area) != 4:
                    continue
                bbox = [int(max(0, int(v))) for v in area]
                score = float(item.get("score") or item.get("confidence") or 0.8)
                faces.append(
                    {
                        "face_id": str(key),
                        "bbox": bbox,
                        "confidence": max(0.0, min(1.0, score)),
                    }
                )

        return {
            "status": "ok",
            "provider": "retinaface",
            "faces": faces,
            "meta": {"count": len(faces)},
        }

    def _detect_with_opencv(self, image_path: str) -> Dict[str, Any]:
        try:
            import cv2  # type: ignore
        except Exception as exc:
            return {"status": "skipped", "faces": [], "reason": f"opencv unavailable: {exc}"}

        img = cv2.imread(image_path)
        if img is None:
            return {"status": "error", "faces": [], "reason": "cv2 failed to read image"}

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        cascade_path = str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml")
        cascade = cv2.CascadeClassifier(cascade_path)
        detections = cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(40, 40),
        )

        faces: List[Dict[str, Any]] = []
        for idx, (x, y, w, h) in enumerate(detections):
            faces.append(
                {
                    "face_id": f"face_{idx + 1}",
                    "bbox": [int(x), int(y), int(x + w), int(y + h)],
                    "confidence": 0.6,
                }
            )

        return {
            "status": "ok",
            "provider": "opencv_haar",
            "faces": faces,
            "meta": {"count": len(faces)},
        }

    def _probe_dimensions(self, image_path: str) -> Optional[Tuple[int, int]]:
        try:
            from PIL import Image  # type: ignore

            with Image.open(image_path) as img:
                return int(img.width), int(img.height)
        except Exception:
            pass

        try:
            import cv2  # type: ignore

            img = cv2.imread(image_path)
            if img is None:
                return None
            h, w = img.shape[:2]
            return int(w), int(h)
        except Exception as exc:
            logger.debug("Dimension probe failed for %s: %s", image_path, exc)
            return None
