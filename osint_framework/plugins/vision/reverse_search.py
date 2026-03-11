from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Protocol, Tuple
from urllib.parse import quote_plus

from osint_framework.core.provider_models import ProviderResult


class _ReverseProvider(Protocol):
    name: str

    async def search(self, module, image_path: str) -> ProviderResult:
        ...


class GoogleVisionWebDetectionProvider:
    name = "google_vision_web"

    async def search(self, module, image_path: str) -> ProviderResult:
        api_key = os.getenv("GOOGLE_VISION_API_KEY", "").strip()
        if not api_key:
            return ProviderResult(
                provider=self.name,
                status="skipped",
                payload={"results": []},
                error="GOOGLE_VISION_API_KEY not configured",
            )

        path = Path(image_path)
        if not path.exists() or not path.is_file():
            return ProviderResult(
                provider=self.name,
                status="error",
                payload={"results": []},
                error="image file not found",
            )

        raw = path.read_bytes()
        content = base64.b64encode(raw).decode("utf-8")
        payload = {
            "requests": [
                {
                    "image": {"content": content},
                    "features": [{"type": "WEB_DETECTION", "maxResults": 30}],
                }
            ]
        }

        url = f"https://vision.googleapis.com/v1/images:annotate?key={api_key}"
        async with module.get_client() as client:
            try:
                resp = await client.post(url, json=payload, timeout=module.timeout)
            except Exception as exc:
                return ProviderResult(
                    provider=self.name,
                    status="error",
                    payload={"results": []},
                    error=str(exc),
                )

        if resp.status_code != 200:
            return ProviderResult(
                provider=self.name,
                status="error",
                payload={"results": []},
                error=f"HTTP {resp.status_code}",
                meta={"response": resp.text[:600]},
            )

        data = resp.json()
        detection = (((data.get("responses") or [{}])[0]).get("webDetection") or {})
        results: List[Dict[str, Any]] = []

        def add_result(item: Dict[str, Any], match_type: str):
            url_value = item.get("url")
            if not isinstance(url_value, str) or not url_value.startswith(("http://", "https://")):
                return
            results.append(
                {
                    "url": url_value,
                    "title": item.get("title") or item.get("pageTitle") or match_type,
                    "match_type": match_type,
                }
            )

        for page in detection.get("pagesWithMatchingImages") or []:
            if isinstance(page, dict):
                add_result(page, "page_match")

        for item in detection.get("fullMatchingImages") or []:
            if isinstance(item, dict):
                add_result(item, "full_match")

        for item in detection.get("partialMatchingImages") or []:
            if isinstance(item, dict):
                add_result(item, "partial_match")

        for item in detection.get("visuallySimilarImages") or []:
            if isinstance(item, dict):
                add_result(item, "visual_similar")

        deduped: Dict[str, Dict[str, Any]] = {}
        for item in results:
            key = item["url"].strip().lower()
            if key not in deduped:
                deduped[key] = item

        final = list(deduped.values())
        return ProviderResult(
            provider=self.name,
            status="ok",
            payload={"results": final},
            meta={
                "count": len(final),
                "web_entities": len(detection.get("webEntities") or []),
                "best_guess_labels": detection.get("bestGuessLabels") or [],
            },
        )


class PivotSearchUrlProvider:
    """Fallback URL pivots when reverse-search APIs are not configured."""

    name = "pivot_search_urls"

    async def search(self, module, image_path: str) -> ProviderResult:
        path = Path(image_path)
        stem = path.stem or "image"
        digest = hashlib.sha1(path.read_bytes()).hexdigest()[:12]
        query = quote_plus(f'"{stem}" {digest}')

        results = [
            {
                "url": f"https://www.google.com/search?q={query}",
                "title": "Google pivot search",
                "match_type": "pivot_search",
            },
            {
                "url": f"https://duckduckgo.com/?q={query}",
                "title": "DuckDuckGo pivot search",
                "match_type": "pivot_search",
            },
            {
                "url": f"https://yandex.com/images/search?text={quote_plus(stem)}",
                "title": "Yandex image search pivot",
                "match_type": "pivot_search",
            },
            {
                "url": "https://tineye.com/",
                "title": "TinEye upload portal",
                "match_type": "manual_reverse",
            },
        ]

        return ProviderResult(
            provider=self.name,
            status="ok",
            payload={"results": results},
            meta={"count": len(results), "note": "fallback pivots"},
        )


class ReverseImageSearcher:
    def __init__(self, max_results: int = 30):
        self.max_results = max(1, int(max_results))
        self.providers: Tuple[_ReverseProvider, ...] = (
            GoogleVisionWebDetectionProvider(),
            PivotSearchUrlProvider(),
        )

    async def search_faces(self, module, face_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        all_results: List[Dict[str, Any]] = []
        per_face: List[Dict[str, Any]] = []
        provider_errors: Dict[str, str] = {}
        provider_meta: Dict[str, Dict[str, Any]] = {}

        for face in face_items:
            face_id = str(face.get("face_id") or "face_unknown")
            image_path = str(face.get("crop_path") or "")
            if not image_path:
                continue

            face_results: List[Dict[str, Any]] = []
            for provider in self.providers:
                outcome = await provider.search(module, image_path)
                if outcome.error and outcome.status != "ok":
                    provider_errors.setdefault(provider.name, outcome.error)
                if outcome.meta:
                    provider_meta[provider.name] = dict(outcome.meta)

                for item in (outcome.payload or {}).get("results") or []:
                    if not isinstance(item, dict):
                        continue
                    url = item.get("url")
                    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                        continue
                    face_results.append(
                        {
                            "face_id": face_id,
                            "url": url,
                            "title": item.get("title") or "result",
                            "match_type": item.get("match_type") or "unknown",
                            "provider": provider.name,
                        }
                    )

            dedup_face: Dict[str, Dict[str, Any]] = {}
            for item in face_results:
                key = item["url"].strip().lower()
                if key not in dedup_face:
                    dedup_face[key] = item
            compact = list(dedup_face.values())[: self.max_results]
            per_face.append({"face_id": face_id, "results": compact, "result_count": len(compact)})
            all_results.extend(compact)

        dedup_all: Dict[str, Dict[str, Any]] = {}
        for item in all_results:
            key = f"{item['face_id']}::{item['url'].strip().lower()}"
            if key not in dedup_all:
                dedup_all[key] = item

        flat = list(dedup_all.values())[: self.max_results]
        return {
            "results": flat,
            "per_face": per_face,
            "provider_errors": provider_errors,
            "provider_meta": provider_meta,
            "total_results": len(flat),
        }
