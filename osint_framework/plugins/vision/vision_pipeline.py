from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from osint_framework.core.config import settings
from osint_framework.core.logger import logger
from osint_framework.core.pipeline import PipelineContext, PipelineRunner
from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.vision.face_detector import VisionFaceDetector
from osint_framework.plugins.vision.face_embedding import FaceEmbeddingExtractor
from osint_framework.plugins.vision.identity_matcher import VisionIdentityMatcher
from osint_framework.plugins.vision.osint_scraper import VisionOsintScraper
from osint_framework.plugins.vision.reverse_search import ReverseImageSearcher
from osint_framework.plugins.vision.similarity_search import FaceSimilaritySearcher


class ResolveImageStage:
    name = "resolve_image"

    def __init__(self, module: BaseModule):
        self.module = module

    async def run(self, context: PipelineContext) -> None:
        target = context.target.strip()
        if target.startswith(("http://", "https://")):
            image_path = await self._download_image(target)
            context.data["image_source"] = "url"
            context.data["image_url"] = target
            context.data["cleanup_download"] = str(image_path)
            context.data["image_path"] = str(image_path)
            return

        local = Path(target)
        if local.exists() and local.is_file():
            context.data["image_source"] = "path"
            context.data["image_path"] = str(local.resolve())
            return

        raise ValueError("Image target path/url could not be resolved")

    async def _download_image(self, url: str) -> Path:
        upload_dir = _resolve_vision_dir()
        upload_dir.mkdir(parents=True, exist_ok=True)

        parsed = urlparse(url)
        ext = Path(parsed.path).suffix.lower()
        if ext not in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff"}:
            ext = ".jpg"

        file_path = upload_dir / f"remote_{uuid.uuid4().hex[:12]}{ext}"

        async with self.module.get_client() as client:
            resp = await client.get(url, timeout=self.module.timeout)
            resp.raise_for_status()
            content_type = (resp.headers.get("content-type") or "").lower()
            if content_type and not content_type.startswith("image/"):
                raise ValueError(f"URL does not appear to be an image (content-type={content_type})")
            file_path.write_bytes(resp.content)

        return file_path.resolve()


class DetectAndCropStage:
    name = "face_detect_crop"

    def __init__(self):
        self.detector = VisionFaceDetector()
        cfg = settings.integrations.vision
        self.crop_padding_ratio = max(0.0, min(0.75, float(cfg.face_crop_padding_ratio)))
        self.crop_square = bool(cfg.face_crop_square)

    async def run(self, context: PipelineContext) -> None:
        image_path = str(context.data.get("image_path") or "")
        if not image_path:
            raise ValueError("Missing image path for face detection")

        detection = self.detector.detect_faces(image_path)
        context.data["face_detection"] = detection

        faces = detection.get("faces") if isinstance(detection, dict) else []
        if not isinstance(faces, list):
            faces = []

        cropped = self._crop_faces(image_path, faces)
        context.data["faces"] = cropped

    def _crop_faces(self, image_path: str, faces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not faces:
            return [{"face_id": "face_1", "bbox": None, "crop_path": image_path, "crop_status": "fallback_original"}]

        try:
            from PIL import Image  # type: ignore
        except Exception:
            return [
                {
                    "face_id": str(face.get("face_id") or f"face_{idx + 1}"),
                    "bbox": face.get("bbox"),
                    "crop_bbox": face.get("bbox"),
                    "crop_path": image_path,
                    "crop_status": "pillow_unavailable",
                    "confidence": face.get("confidence"),
                }
                for idx, face in enumerate(faces)
            ]

        src = Path(image_path)
        run_dir = src.parent / "derived" / uuid.uuid4().hex[:12]
        run_dir.mkdir(parents=True, exist_ok=True)

        items: List[Dict[str, Any]] = []
        with Image.open(src) as img:
            width, height = img.size
            for idx, face in enumerate(faces):
                face_id = str(face.get("face_id") or f"face_{idx + 1}")
                bbox = self._normalize_bbox(face.get("bbox"), width=width, height=height)
                if not bbox:
                    items.append(
                        {
                            "face_id": face_id,
                            "bbox": None,
                            "crop_bbox": None,
                            "crop_path": str(src.resolve()),
                            "crop_status": "invalid_bbox",
                            "confidence": face.get("confidence"),
                        }
                    )
                    continue

                crop_bbox = self._build_crop_bbox(bbox, width=width, height=height)
                if not crop_bbox:
                    items.append(
                        {
                            "face_id": face_id,
                            "bbox": bbox,
                            "crop_bbox": None,
                            "crop_path": str(src.resolve()),
                            "crop_status": "crop_bbox_invalid",
                            "confidence": face.get("confidence"),
                        }
                    )
                    continue

                cx1, cy1, cx2, cy2 = crop_bbox
                crop = img.crop((cx1, cy1, cx2, cy2))
                crop_path = run_dir / f"{face_id}.jpg"
                crop.save(crop_path, format="JPEG", quality=95)
                items.append(
                    {
                        "face_id": face_id,
                        "bbox": bbox,
                        "crop_bbox": crop_bbox,
                        "crop_path": str(crop_path.resolve()),
                        "crop_status": "ok",
                        "confidence": face.get("confidence"),
                        "crop_size": [int(cx2 - cx1), int(cy2 - cy1)],
                    }
                )

        return items

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
        box_w = max(1, x2 - x1)
        box_h = max(1, y2 - y1)
        pad_x = int(round(box_w * self.crop_padding_ratio))
        pad_y = int(round(box_h * self.crop_padding_ratio))

        left = max(0, x1 - pad_x)
        top = max(0, y1 - pad_y)
        right = min(width, x2 + pad_x)
        bottom = min(height, y2 + pad_y)

        if self.crop_square:
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
        current_w = max(1, right - left)
        current_h = max(1, bottom - top)
        side = max(current_w, current_h)

        center_x = (left + right) / 2.0
        center_y = (top + bottom) / 2.0
        square_left = int(round(center_x - side / 2.0))
        square_top = int(round(center_y - side / 2.0))
        square_right = square_left + side
        square_bottom = square_top + side

        if square_left < 0:
            square_right += -square_left
            square_left = 0
        if square_top < 0:
            square_bottom += -square_top
            square_top = 0
        if square_right > width:
            overflow = square_right - width
            square_left = max(0, square_left - overflow)
            square_right = width
        if square_bottom > height:
            overflow = square_bottom - height
            square_top = max(0, square_top - overflow)
            square_bottom = height

        # If clipping reduced one side, trim the other side to keep a square.
        clipped_w = max(1, square_right - square_left)
        clipped_h = max(1, square_bottom - square_top)
        side = min(clipped_w, clipped_h)
        square_right = square_left + side
        square_bottom = square_top + side
        return square_left, square_top, square_right, square_bottom


class FaceEmbeddingStage:
    name = "face_embedding"

    def __init__(self):
        self.embedder = FaceEmbeddingExtractor()
        cfg = settings.integrations.vision
        self.min_face_confidence = max(
            0.0,
            min(1.0, float(cfg.face_detection_min_confidence)),
        )
        self.max_faces = max(1, int(cfg.embedding_max_faces))
        self.force_top_face = bool(cfg.embedding_force_top_face)

    async def run(self, context: PipelineContext) -> None:
        faces = context.data.get("faces") or []
        skipped_invalid = 0
        candidates: List[Dict[str, Any]] = []
        for idx, face in enumerate(faces):
            if not isinstance(face, dict):
                skipped_invalid += 1
                continue
            bbox = face.get("bbox")
            if not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
                skipped_invalid += 1
                continue
            crop_path = face.get("crop_path")
            if not crop_path:
                skipped_invalid += 1
                continue
            try:
                confidence = float(face.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0

            candidates.append(
                {
                    "face_ref": str(face.get("face_id") or f"face_{idx + 1}"),
                    "path": str(crop_path),
                    "confidence": confidence,
                }
            )

        selected = [
            item for item in candidates if float(item.get("confidence") or 0.0) >= self.min_face_confidence
        ]
        skipped_low_confidence = max(0, len(candidates) - len(selected))
        forced_low_confidence = 0
        if not selected and self.force_top_face and candidates:
            top_face = max(candidates, key=lambda x: float(x.get("confidence") or 0.0))
            selected = [top_face]
            skipped_low_confidence = max(0, skipped_low_confidence - 1)
            forced_low_confidence = 1

        selected.sort(key=lambda x: float(x.get("confidence") or 0.0), reverse=True)
        trimmed_by_max_faces = max(0, len(selected) - self.max_faces)
        selected = selected[: self.max_faces]

        face_inputs: List[Dict[str, Any]] = [
            {"face_ref": str(item.get("face_ref")), "path": str(item.get("path"))}
            for item in selected
        ]

        context.data["embedding_inputs"] = {
            "candidates_total": len(faces),
            "used_total": len(face_inputs),
            "skipped_low_confidence": skipped_low_confidence,
            "skipped_invalid": skipped_invalid,
            "min_face_confidence": self.min_face_confidence,
            "max_faces": self.max_faces,
            "trimmed_by_max_faces": trimmed_by_max_faces,
            "force_top_face": self.force_top_face,
            "forced_low_confidence": forced_low_confidence,
        }

        raw_payload = self.embedder.extract(face_inputs, include_vectors=True)
        context.data["embedding_raw"] = raw_payload
        context.data["embedding"] = self._sanitize_embedding_output(raw_payload)

    def _sanitize_embedding_output(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(payload or {})
        cleaned_embeddings: List[Dict[str, Any]] = []
        for item in (payload.get("embeddings") if isinstance(payload, dict) else []) or []:
            if not isinstance(item, dict):
                continue
            cleaned_embeddings.append({k: v for k, v in item.items() if k != "vector"})
        sanitized["embeddings"] = cleaned_embeddings
        return sanitized


class FaceSimilarityStage:
    name = "face_similarity_search"

    def __init__(self):
        cfg = settings.integrations.vision
        self.enabled = bool(cfg.enable_similarity_search)
        self.searcher = FaceSimilaritySearcher(
            index_path=str(_resolve_similarity_index_path()),
            min_score=cfg.similarity_min_score,
            top_k=cfg.similarity_top_k,
            max_items=cfg.similarity_max_items,
        )

    async def run(self, context: PipelineContext) -> None:
        if not self.enabled:
            context.data["similarity"] = {
                "status": "skipped",
                "provider": self.searcher.provider_name,
                "reason": "similarity disabled",
                "matches": [],
                "matches_by_face": [],
            }
            return

        embedding_raw = context.data.get("embedding_raw") or {}
        embeddings = (embedding_raw.get("embeddings") if isinstance(embedding_raw, dict) else []) or []

        if not embeddings:
            context.data["similarity"] = {
                "status": "skipped",
                "provider": self.searcher.provider_name,
                "reason": "no embeddings",
                "matches": [],
                "matches_by_face": [],
            }
            return

        similarity = self.searcher.search_and_update(
            embeddings,
            current_image_path=str(context.data.get("image_path") or context.target),
            image_source=context.data.get("image_source"),
        )
        context.data["similarity"] = similarity


class ReverseSearchStage:
    name = "reverse_image_search"

    def __init__(self, module: BaseModule):
        self.module = module
        self.searcher = ReverseImageSearcher(max_results=settings.integrations.vision.reverse_max_results)

    async def run(self, context: PipelineContext) -> None:
        faces = context.data.get("faces") or []
        reverse = await self.searcher.search_faces(self.module, faces)
        context.data["reverse_search"] = reverse

        urls = []
        seen = set()
        for item in reverse.get("results") or []:
            url = item.get("url")
            if not isinstance(url, str):
                continue
            key = url.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            urls.append(url)
        context.data["result_urls"] = urls


class ScrapeStage:
    name = "osint_scraper"

    def __init__(self, module: BaseModule):
        self.module = module
        self.scraper = VisionOsintScraper()

    async def run(self, context: PipelineContext) -> None:
        urls = list(context.data.get("result_urls") or [])
        scraped = await self.scraper.scrape(
            self.module,
            urls,
            max_pages=settings.integrations.vision.scraper_max_pages,
        )
        context.data["scraped"] = scraped


class VisionImageOsintModule(BaseModule):
    name = "Vision_Image_OSINT"
    version = "2.0.0"
    description = (
        "Image-first OSINT pipeline: face detection/crop, embeddings, similarity search, reverse image search, and entity extraction."
    )
    target_types = ["image"]
    author = "OSINT_Framework_Team"
    timeout = 120

    def __init__(self):
        self.identity_matcher = VisionIdentityMatcher()

    async def run(self, target: str) -> Dict[str, Any]:
        context = PipelineContext(target=target, target_type="image")
        runner = PipelineRunner(
            [
                ResolveImageStage(self),
                DetectAndCropStage(),
                FaceEmbeddingStage(),
                FaceSimilarityStage(),
                ReverseSearchStage(self),
                ScrapeStage(self),
            ]
        )

        try:
            await runner.execute(context)
            return self._build_output(context)
        except Exception as exc:
            logger.exception("[%s] Vision pipeline failed: %s", self.name, exc)
            return {
                "pipeline": "vision_osint_v2",
                "status": "error",
                "image_target": target,
                "error": str(exc),
                "faces_detected": 0,
                "faces": [],
                "reverse_image_results": [],
                "entities": [],
                "identity_matches": {
                    "status": "no_matches",
                    "candidates_total": 0,
                    "candidates": [],
                    "best_candidate": None,
                },
                "pipeline_metrics": self._build_pipeline_metrics(context),
                "pipeline_events": context.events,
            }
        finally:
            self._cleanup_download(context)

    def _build_output(self, context: PipelineContext) -> Dict[str, Any]:
        faces = list(context.data.get("faces") or [])
        reverse = context.data.get("reverse_search") or {}
        scraped = context.data.get("scraped") or {}
        detection = context.data.get("face_detection") or {}
        embedding = context.data.get("embedding") or {}
        embedding_inputs = context.data.get("embedding_inputs") or {}
        similarity = context.data.get("similarity") or {}
        identity_matches = self._build_identity_matches(
            context=context,
            reverse=reverse,
            scraped=scraped,
            similarity=similarity,
        )
        pipeline_metrics = self._build_pipeline_metrics(context)

        return {
            "pipeline": "vision_osint_v2",
            "status": "ok",
            "image_target": context.target,
            "image_source": context.data.get("image_source"),
            "image_path": context.data.get("image_path"),
            "faces_detected": len(faces),
            "faces": faces,
            "face_detection": {
                "provider": detection.get("provider"),
                "fallback": bool(detection.get("fallback")),
                "provider_errors": detection.get("provider_errors") or {},
                "quality": detection.get("quality") or {},
            },
            "embedding": embedding,
            "embedding_inputs": embedding_inputs,
            "similarity": similarity,
            "similarity_matches_total": similarity.get("matches_total", 0),
            "similarity_matches": similarity.get("matches") or [],
            "reverse_image_results_total": reverse.get("total_results", 0),
            "reverse_image_results": reverse.get("results") or [],
            "reverse_image_results_by_face": reverse.get("per_face") or [],
            "result_urls": context.data.get("result_urls") or [],
            "osint_pages": scraped.get("pages") or [],
            "entities": scraped.get("entities") or [],
            "identity_matches": identity_matches,
            "pipeline_metrics": pipeline_metrics,
            "pipeline_events": context.events,
        }

    def _build_identity_matches(
        self,
        *,
        context: PipelineContext,
        reverse: Dict[str, Any],
        scraped: Dict[str, Any],
        similarity: Dict[str, Any],
    ) -> Dict[str, Any]:
        image_target = str(context.data.get("image_path") or context.target)
        try:
            return self.identity_matcher.match(
                image_target=image_target,
                reverse_search=reverse if isinstance(reverse, dict) else {},
                scraped=scraped if isinstance(scraped, dict) else {},
                similarity=similarity if isinstance(similarity, dict) else {},
            )
        except Exception as exc:
            logger.warning("[%s] Identity matcher failed: %s", self.name, exc)
            return {
                "status": "error",
                "error": str(exc),
                "candidates_total": 0,
                "candidates": [],
                "best_candidate": None,
            }

    def _build_pipeline_metrics(self, context: PipelineContext) -> Dict[str, Any]:
        events = list(context.events or [])
        stage_durations: Dict[str, int] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            status = str(event.get("status") or "")
            stage = str(event.get("stage") or "")
            duration = event.get("duration_ms")
            if status not in {"completed", "error"} or not stage:
                continue
            if isinstance(duration, int):
                stage_durations[stage] = max(0, duration)
        return {
            "events_total": len(events),
            "stage_durations_ms": stage_durations,
            "stages_total": len(stage_durations),
        }

    def _cleanup_download(self, context: PipelineContext) -> None:
        download_path = context.data.get("cleanup_download")
        if not download_path:
            return
        try:
            Path(str(download_path)).unlink(missing_ok=True)
        except Exception:
            logger.debug("[%s] Failed to cleanup temporary download: %s", self.name, download_path)


def _resolve_vision_dir() -> Path:
    configured = settings.integrations.vision.upload_dir
    path = Path(configured)
    if path.is_absolute():
        return path
    return Path(__file__).resolve().parents[3] / configured


def _resolve_similarity_index_path() -> Path:
    configured = settings.integrations.vision.similarity_index_path
    path = Path(configured)
    if path.is_absolute():
        return path
    return Path(__file__).resolve().parents[3] / configured
