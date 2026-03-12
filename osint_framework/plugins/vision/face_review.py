from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from osint_framework.plugins.vision.face_detector import VisionFaceDetector


class VisionFaceReviewSession:
    """
    Prepare and materialize manually approved faces for calibration datasets.

    Workflow:
    1) create_review(image_path, review_dir) -> writes crops + review.json
    2) user edits review.json (`approved`, `identity`)
    3) export_approved_dataset(review_json_path, dataset_dir)
    """

    def __init__(
        self,
        *,
        min_size_px: int = 120,
        max_faces: int = 20,
        padding_ratio: float = 0.18,
        square_crop: bool = True,
    ):
        self.detector = VisionFaceDetector()
        self.min_size_px = max(24, int(min_size_px))
        self.max_faces = max(1, int(max_faces))
        self.padding_ratio = max(0.0, min(0.75, float(padding_ratio)))
        self.square_crop = bool(square_crop)

    def create_review(self, image_path: str, review_dir: str) -> Dict[str, Any]:
        try:
            from PIL import Image  # type: ignore
        except Exception as exc:
            return {"status": "error", "reason": f"pillow_unavailable: {exc}"}

        source = self._resolve_file(image_path)
        output_dir = self._resolve_output_dir(review_dir)

        # Use stricter size/max-face constraints for review quality.
        self.detector.min_size_px = self.min_size_px
        self.detector.max_faces = self.max_faces
        detection = self.detector.detect_faces(str(source))
        faces_raw = (detection.get("faces") if isinstance(detection, dict) else []) or []
        if not isinstance(faces_raw, list):
            faces_raw = []
        if not faces_raw:
            return {
                "status": "error",
                "reason": "no_faces_detected",
                "provider": detection.get("provider"),
                "detection": detection,
            }

        crops_dir = output_dir / "crops"
        crops_dir.mkdir(parents=True, exist_ok=True)

        faces_payload: List[Dict[str, Any]] = []
        with Image.open(source) as img:
            width, height = img.size
            for idx, item in enumerate(faces_raw, start=1):
                if not isinstance(item, dict):
                    continue
                bbox = self._normalize_bbox(item.get("bbox"), width=width, height=height)
                if not bbox:
                    continue
                crop_bbox = self._build_crop_bbox(bbox, width=width, height=height)
                if not crop_bbox:
                    continue
                cx1, cy1, cx2, cy2 = crop_bbox
                crop = img.crop((cx1, cy1, cx2, cy2)).convert("RGB")

                face_id = str(item.get("face_id") or f"face_{idx}")
                crop_path = crops_dir / f"{face_id}.jpg"
                crop.save(crop_path, format="JPEG", quality=95)

                area = int((bbox[2] - bbox[0]) * (bbox[3] - bbox[1]))
                faces_payload.append(
                    {
                        "face_id": face_id,
                        "bbox": bbox,
                        "crop_bbox": crop_bbox,
                        "crop_path": str(crop_path.resolve()),
                        "area": area,
                        "confidence": float(item.get("confidence") or 0.0),
                        "approved": False,
                        "identity": "",
                        "notes": "",
                    }
                )

        if not faces_payload:
            return {
                "status": "error",
                "reason": "no_valid_faces_after_crop",
                "provider": detection.get("provider"),
                "detection": detection,
            }

        faces_payload.sort(key=lambda x: int(x.get("area") or 0), reverse=True)
        review_doc = {
            "schema_version": "1.0",
            "created_at": datetime.now(UTC).isoformat(),
            "source_image": str(source),
            "provider": detection.get("provider"),
            "quality": detection.get("quality") if isinstance(detection, dict) else {},
            "faces_total": len(faces_payload),
            "faces": faces_payload,
        }

        review_path = output_dir / "review.json"
        review_path.write_text(json.dumps(review_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "status": "ok",
            "review_path": str(review_path.resolve()),
            "faces_total": len(faces_payload),
            "provider": detection.get("provider"),
        }

    def export_approved_dataset(
        self,
        review_json_path: str,
        dataset_dir: str,
        *,
        min_samples_per_identity: int = 2,
    ) -> Dict[str, Any]:
        review_path = self._resolve_file(review_json_path)
        target_dir = self._resolve_output_dir(dataset_dir)

        payload = json.loads(review_path.read_text(encoding="utf-8"))
        faces = (payload.get("faces") if isinstance(payload, dict) else []) or []
        if not isinstance(faces, list):
            faces = []

        identities_written: Dict[str, int] = {}
        skipped = {"not_approved": 0, "missing_identity": 0, "missing_crop": 0}
        written = 0

        for item in faces:
            if not isinstance(item, dict):
                continue
            approved = bool(item.get("approved"))
            if not approved:
                skipped["not_approved"] += 1
                continue

            identity = self._clean_identity(str(item.get("identity") or ""))
            if not identity:
                skipped["missing_identity"] += 1
                continue

            crop_path_value = str(item.get("crop_path") or "").strip()
            if not crop_path_value:
                skipped["missing_crop"] += 1
                continue
            crop_path = Path(crop_path_value)
            if not crop_path.exists() or not crop_path.is_file():
                skipped["missing_crop"] += 1
                continue

            person_dir = target_dir / identity
            person_dir.mkdir(parents=True, exist_ok=True)
            next_index = identities_written.get(identity, 0) + 1
            identities_written[identity] = next_index
            out_file = person_dir / f"sample_{next_index:03d}.jpg"
            shutil.copy2(crop_path, out_file)
            written += 1

        identities = sorted(identities_written.keys())
        below_min = {
            identity: count
            for identity, count in identities_written.items()
            if count < max(1, int(min_samples_per_identity))
        }
        status = "ok" if written > 0 else "error"
        return {
            "status": status,
            "review_path": str(review_path),
            "dataset_dir": str(target_dir),
            "written_total": written,
            "identities_total": len(identities),
            "identities": identities,
            "samples_per_identity": identities_written,
            "below_min_samples": below_min,
            "skipped": skipped,
        }

    def _resolve_file(self, value: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"file not found: {path}")
        return path

    def _resolve_output_dir(self, value: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

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

    def _build_crop_bbox(self, bbox: List[int], *, width: int, height: int) -> Optional[List[int]]:
        x1, y1, x2, y2 = bbox
        w = max(1, x2 - x1)
        h = max(1, y2 - y1)
        px = int(round(w * self.padding_ratio))
        py = int(round(h * self.padding_ratio))
        left = max(0, x1 - px)
        top = max(0, y1 - py)
        right = min(width, x2 + px)
        bottom = min(height, y2 + py)

        if self.square_crop:
            left, top, right, bottom = self._square_bbox(
                left=left,
                top=top,
                right=right,
                bottom=bottom,
                width=width,
                height=height,
            )
        if right - left < 2 or bottom - top < 2:
            return None
        return [left, top, right, bottom]

    def _square_bbox(
        self,
        *,
        left: int,
        top: int,
        right: int,
        bottom: int,
        width: int,
        height: int,
    ) -> Tuple[int, int, int, int]:
        cw = max(1, right - left)
        ch = max(1, bottom - top)
        side = max(cw, ch)
        cx = (left + right) / 2.0
        cy = (top + bottom) / 2.0
        s_left = int(round(cx - side / 2.0))
        s_top = int(round(cy - side / 2.0))
        s_right = s_left + side
        s_bottom = s_top + side

        if s_left < 0:
            s_right += -s_left
            s_left = 0
        if s_top < 0:
            s_bottom += -s_top
            s_top = 0
        if s_right > width:
            overflow = s_right - width
            s_left = max(0, s_left - overflow)
            s_right = width
        if s_bottom > height:
            overflow = s_bottom - height
            s_top = max(0, s_top - overflow)
            s_bottom = height

        clipped_w = max(1, s_right - s_left)
        clipped_h = max(1, s_bottom - s_top)
        side = min(clipped_w, clipped_h)
        s_right = s_left + side
        s_bottom = s_top + side
        return s_left, s_top, s_right, s_bottom

    @staticmethod
    def _clean_identity(value: str) -> str:
        cleaned = value.strip().lower().replace(" ", "_")
        return cleaned
