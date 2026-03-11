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
from osint_framework.plugins.vision.osint_scraper import VisionOsintScraper
from osint_framework.plugins.vision.reverse_search import ReverseImageSearcher


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
                bbox = face.get("bbox")
                if not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
                    items.append(
                        {
                            "face_id": face_id,
                            "bbox": None,
                            "crop_path": str(src.resolve()),
                            "crop_status": "invalid_bbox",
                            "confidence": face.get("confidence"),
                        }
                    )
                    continue

                x1, y1, x2, y2 = [int(v) for v in bbox]
                x1 = max(0, min(width - 1, x1))
                y1 = max(0, min(height - 1, y1))
                x2 = max(x1 + 1, min(width, x2))
                y2 = max(y1 + 1, min(height, y2))
                crop = img.crop((x1, y1, x2, y2))
                crop_path = run_dir / f"{face_id}.jpg"
                crop.save(crop_path, format="JPEG", quality=95)
                items.append(
                    {
                        "face_id": face_id,
                        "bbox": [x1, y1, x2, y2],
                        "crop_path": str(crop_path.resolve()),
                        "crop_status": "ok",
                        "confidence": face.get("confidence"),
                    }
                )

        return items


class FaceEmbeddingStage:
    name = "face_embedding"

    def __init__(self):
        self.embedder = FaceEmbeddingExtractor()

    async def run(self, context: PipelineContext) -> None:
        faces = context.data.get("faces") or []
        image_paths = [str(face.get("crop_path")) for face in faces if isinstance(face, dict) and face.get("crop_path")]
        context.data["embedding"] = self.embedder.extract(image_paths)


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
    version = "1.0.0"
    description = (
        "Image-first OSINT pipeline: face detection/crop, optional embeddings, reverse image search, and URL/entity extraction."
    )
    target_types = ["image"]
    author = "OSINT_Framework_Team"
    timeout = 120

    async def run(self, target: str) -> Dict[str, Any]:
        context = PipelineContext(target=target, target_type="image")
        runner = PipelineRunner(
            [
                ResolveImageStage(self),
                DetectAndCropStage(),
                FaceEmbeddingStage(),
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
                "pipeline": "vision_osint_v1",
                "status": "error",
                "image_target": target,
                "error": str(exc),
                "faces_detected": 0,
                "faces": [],
                "reverse_image_results": [],
                "entities": [],
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

        return {
            "pipeline": "vision_osint_v1",
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
            },
            "embedding": embedding,
            "reverse_image_results_total": reverse.get("total_results", 0),
            "reverse_image_results": reverse.get("results") or [],
            "reverse_image_results_by_face": reverse.get("per_face") or [],
            "result_urls": context.data.get("result_urls") or [],
            "osint_pages": scraped.get("pages") or [],
            "entities": scraped.get("entities") or [],
            "pipeline_events": context.events,
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
