from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List

from osint_framework.core.config import settings


class FaceEmbeddingExtractor:
    """Optional embedding stage (kept off by default for v1)."""

    def __init__(self):
        self.enabled = bool(settings.integrations.vision.enable_embedding) or (
            os.getenv("OSINT_VISION_ENABLE_EMBEDDING", "").strip().lower()
            in {"1", "true", "yes", "on"}
        )

    def extract(self, image_paths: List[str]) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "status": "skipped",
                "provider": "deepface",
                "embeddings": [],
                "reason": "embedding disabled",
            }

        try:
            from deepface import DeepFace  # type: ignore
        except Exception as exc:
            return {
                "status": "skipped",
                "provider": "deepface",
                "embeddings": [],
                "reason": f"deepface unavailable: {exc}",
            }

        embeddings: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        for idx, image_path in enumerate(image_paths):
            try:
                reps = DeepFace.represent(
                    img_path=image_path,
                    enforce_detection=False,
                    detector_backend="skip",
                )
                vector = []
                if isinstance(reps, list) and reps:
                    first = reps[0]
                    if isinstance(first, dict):
                        vector = list(first.get("embedding") or [])
                dim = len(vector)
                digest = hashlib.sha256(json.dumps(vector[:32]).encode("utf-8")).hexdigest() if vector else None
                embeddings.append(
                    {
                        "face_ref": f"face_{idx + 1}",
                        "path": image_path,
                        "dimension": dim,
                        "vector_sha256_head": digest,
                    }
                )
            except Exception as exc:
                errors.append({"path": image_path, "error": str(exc)})

        return {
            "status": "ok" if embeddings else "error",
            "provider": "deepface",
            "embeddings": embeddings,
            "errors": errors,
        }
