from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from osint_framework.core.config import settings
from osint_framework.core.logger import logger


class VisionFaceDetector:
    """Face detection with provider chain (RetinaFace -> OpenCV -> full-image fallback)."""

    def __init__(self):
        cfg = settings.integrations.vision
        self.min_confidence = max(0.0, min(1.0, float(cfg.face_detection_min_confidence)))
        self.min_size_px = max(8, int(cfg.face_detection_min_size_px))
        self.iou_threshold = max(0.0, min(1.0, float(cfg.face_detection_iou_threshold)))
        self.max_faces = max(1, int(cfg.face_detection_max_faces))
        self.allow_full_image_fallback = bool(cfg.face_detection_allow_full_image_fallback)

    def detect_faces(self, image_path: str) -> Dict[str, Any]:
        provider_errors: Dict[str, str] = {}
        dimensions = self._probe_dimensions(image_path)

        for provider in (self._detect_with_retinaface, self._detect_with_opencv):
            provider_name = provider.__name__.replace("_detect_with_", "")
            try:
                result = provider(image_path)
            except Exception as exc:  # defensive
                provider_errors[provider_name] = str(exc)
                continue

            raw_faces = result.get("faces") if isinstance(result, dict) else []
            filtered_faces, quality = self._sanitize_faces(raw_faces, dimensions)
            if filtered_faces:
                return {
                    "status": "ok",
                    "provider": (
                        str(result.get("provider") or provider_name)
                        if isinstance(result, dict)
                        else provider_name
                    ),
                    "faces": filtered_faces,
                    "meta": (
                        dict(result.get("meta") or {})
                        if isinstance(result, dict) and isinstance(result.get("meta"), dict)
                        else {}
                    ),
                    "provider_errors": provider_errors,
                    "quality": quality,
                }

            provider_errors[provider_name] = (
                result.get("reason", "no_valid_faces")
                if isinstance(result, dict)
                else "no_valid_faces"
            )

        # Fallback keeps pipeline operable even if no detector dependency is installed.
        if self.allow_full_image_fallback and dimensions:
            width, height = dimensions
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
                "quality": {
                    "raw_count": 0,
                    "kept_count": 1,
                    "rejected_count": 0,
                    "rejected": {},
                    "nms_suppressed": 0,
                    "trimmed_by_max_faces": 0,
                    "min_confidence": self.min_confidence,
                    "min_size_px": self.min_size_px,
                    "iou_threshold": self.iou_threshold,
                    "max_faces": self.max_faces,
                    "used_full_image_fallback": True,
                },
            }

        return {
            "status": "error",
            "provider": "none",
            "faces": [],
            "provider_errors": provider_errors,
            "reason": (
                "No valid faces detected and full-image fallback disabled"
                if dimensions
                else "Could not load image for face detection"
            ),
            "fallback": False,
            "quality": {
                "raw_count": 0,
                "kept_count": 0,
                "rejected_count": 0,
                "rejected": {},
                "nms_suppressed": 0,
                "trimmed_by_max_faces": 0,
                "min_confidence": self.min_confidence,
                "min_size_px": self.min_size_px,
                "iou_threshold": self.iou_threshold,
                "max_faces": self.max_faces,
                "used_full_image_fallback": False,
            },
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

    def _sanitize_faces(
        self,
        faces: Any,
        dimensions: Optional[Tuple[int, int]],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        raw_faces = list(faces or []) if isinstance(faces, list) else []
        rejected = {
            "invalid_bbox": 0,
            "below_confidence": 0,
            "too_small": 0,
        }
        quality = {
            "raw_count": len(raw_faces),
            "kept_count": 0,
            "rejected_count": 0,
            "rejected": rejected,
            "nms_suppressed": 0,
            "trimmed_by_max_faces": 0,
            "min_confidence": self.min_confidence,
            "min_size_px": self.min_size_px,
            "iou_threshold": self.iou_threshold,
            "max_faces": self.max_faces,
            "used_full_image_fallback": False,
        }

        if not dimensions:
            quality["rejected_count"] = len(raw_faces)
            return [], quality

        width, height = dimensions
        candidates: List[Dict[str, Any]] = []
        for idx, item in enumerate(raw_faces):
            if not isinstance(item, dict):
                rejected["invalid_bbox"] += 1
                continue

            bbox = self._normalize_bbox(item.get("bbox"), width=width, height=height)
            if bbox is None:
                rejected["invalid_bbox"] += 1
                continue

            try:
                confidence = float(item.get("confidence") or item.get("score") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            confidence = max(0.0, min(1.0, confidence))
            if confidence < self.min_confidence:
                rejected["below_confidence"] += 1
                continue

            box_w = int(bbox[2] - bbox[0])
            box_h = int(bbox[3] - bbox[1])
            if box_w < self.min_size_px or box_h < self.min_size_px:
                rejected["too_small"] += 1
                continue

            candidates.append(
                {
                    "face_id": str(item.get("face_id") or f"face_{idx + 1}"),
                    "bbox": bbox,
                    "confidence": round(confidence, 6),
                }
            )

        deduped, suppressed_count = self._apply_nms(candidates)
        deduped.sort(key=lambda x: float(x.get("confidence") or 0.0), reverse=True)
        trimmed_count = max(0, len(deduped) - self.max_faces)
        deduped = deduped[: self.max_faces]

        quality["kept_count"] = len(deduped)
        quality["nms_suppressed"] = suppressed_count
        quality["trimmed_by_max_faces"] = trimmed_count
        quality["rejected_count"] = (
            int(rejected["invalid_bbox"])
            + int(rejected["below_confidence"])
            + int(rejected["too_small"])
            + int(suppressed_count)
            + int(trimmed_count)
        )

        return deduped, quality

    def _normalize_bbox(
        self,
        raw_bbox: Any,
        *,
        width: int,
        height: int,
    ) -> Optional[List[int]]:
        if not isinstance(raw_bbox, (list, tuple)) or len(raw_bbox) != 4:
            return None
        try:
            x1, y1, x2, y2 = [int(float(v)) for v in raw_bbox]
        except (TypeError, ValueError):
            return None

        left = max(0, min(width - 1, min(x1, x2)))
        top = max(0, min(height - 1, min(y1, y2)))
        right = max(left + 1, min(width, max(x1, x2)))
        bottom = max(top + 1, min(height, max(y1, y2)))
        if right - left < 2 or bottom - top < 2:
            return None
        return [left, top, right, bottom]

    def _apply_nms(self, faces: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        if not faces:
            return [], 0

        ordered = sorted(faces, key=lambda x: float(x.get("confidence") or 0.0), reverse=True)
        kept: List[Dict[str, Any]] = []
        suppressed = 0
        for candidate in ordered:
            cand_bbox = candidate.get("bbox")
            if not isinstance(cand_bbox, list):
                continue
            if any(self._iou(cand_bbox, existing["bbox"]) > self.iou_threshold for existing in kept):
                suppressed += 1
                continue
            kept.append(candidate)
        return kept, suppressed

    @staticmethod
    def _iou(a: List[int], b: List[int]) -> float:
        ax1, ay1, ax2, ay2 = a
        bx1, by1, bx2, by2 = b

        inter_left = max(ax1, bx1)
        inter_top = max(ay1, by1)
        inter_right = min(ax2, bx2)
        inter_bottom = min(ay2, by2)
        if inter_right <= inter_left or inter_bottom <= inter_top:
            return 0.0

        inter_area = float((inter_right - inter_left) * (inter_bottom - inter_top))
        area_a = float(max(1, (ax2 - ax1) * (ay2 - ay1)))
        area_b = float(max(1, (bx2 - bx1) * (by2 - by1)))
        union = area_a + area_b - inter_area
        if union <= 0.0:
            return 0.0
        return inter_area / union
