from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from osint_framework.core.config import settings


class FaceEmbeddingExtractor:
    """Face embedding extractor with DeepFace primary and descriptor fallback."""

    def __init__(self):
        self.enabled = bool(settings.integrations.vision.enable_embedding) or (
            os.getenv("OSINT_VISION_ENABLE_EMBEDDING", "").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        self.fallback_dimension = 128

    def extract(
        self,
        face_inputs: List[Dict[str, Any]],
        *,
        include_vectors: bool = False,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "status": "skipped",
                "provider": "disabled",
                "providers_used": [],
                "embeddings": [],
                "reason": "embedding disabled",
            }

        embeddings: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        providers_used: List[str] = []

        deepface = self._load_deepface()
        if deepface is not None:
            providers_used.append("deepface")

        for idx, face_item in enumerate(face_inputs):
            image_path = str(face_item.get("path") or "")
            if not image_path:
                continue
            face_ref = str(face_item.get("face_ref") or f"face_{idx + 1}")
            vector: Optional[List[float]] = None
            provider = "byte_descriptor"

            if deepface is not None:
                try:
                    vector = self._extract_deepface_vector(deepface, image_path)
                    if vector:
                        provider = "deepface"
                except Exception as exc:
                    errors.append({"path": image_path, "error": f"deepface: {exc}"})

            if not vector:
                try:
                    vector = self._extract_fallback_vector(image_path)
                    provider = "byte_descriptor"
                except Exception as exc:
                    errors.append({"path": image_path, "error": f"fallback: {exc}"})
                    continue

            if provider not in providers_used:
                providers_used.append(provider)

            shaped = self._shape_embedding(
                face_ref=face_ref,
                image_path=image_path,
                vector=vector,
                provider=provider,
                include_vectors=include_vectors,
            )
            embeddings.append(shaped)

        return {
            "status": "ok" if embeddings else "error",
            "provider": providers_used[0] if len(providers_used) == 1 else "hybrid",
            "providers_used": providers_used,
            "embeddings": embeddings,
            "errors": errors,
        }

    def _load_deepface(self):
        try:
            from deepface import DeepFace  # type: ignore

            return DeepFace
        except Exception:
            return None

    def _extract_deepface_vector(self, deepface, image_path: str) -> List[float]:
        reps = deepface.represent(
            img_path=image_path,
            enforce_detection=False,
            detector_backend="skip",
        )

        if not isinstance(reps, list) or not reps:
            return []

        first = reps[0]
        if not isinstance(first, dict):
            return []

        vector = first.get("embedding")
        if not isinstance(vector, list):
            return []

        return [float(x) for x in vector]

    def _extract_fallback_vector(self, image_path: str) -> List[float]:
        """Deterministic descriptor fallback that requires no external ML dependency."""
        raw = Path(image_path).read_bytes()
        if not raw:
            raise ValueError("empty file bytes")

        buckets = [0.0] * self.fallback_dimension
        counts = [0] * self.fallback_dimension

        # Use up to 128KB for speed while keeping descriptor stable.
        for idx, value in enumerate(raw[:131072]):
            slot = idx % self.fallback_dimension
            buckets[slot] += float(value) / 255.0
            counts[slot] += 1

        vector = [
            (buckets[i] / counts[i]) if counts[i] else 0.0
            for i in range(self.fallback_dimension)
        ]

        # Mean-center + L2 normalize to make cosine distance meaningful.
        mean = sum(vector) / len(vector)
        centered = [v - mean for v in vector]
        norm = math.sqrt(sum(v * v for v in centered))
        if norm > 0:
            centered = [v / norm for v in centered]

        return centered

    def _shape_embedding(
        self,
        *,
        face_ref: str,
        image_path: str,
        vector: List[float],
        provider: str,
        include_vectors: bool,
    ) -> Dict[str, Any]:
        qvec = [round(float(x), 8) for x in vector]
        digest = hashlib.sha256(json.dumps(qvec).encode("utf-8")).hexdigest()
        norm = math.sqrt(sum(v * v for v in qvec))

        payload: Dict[str, Any] = {
            "face_ref": face_ref,
            "path": image_path,
            "provider": provider,
            "dimension": len(qvec),
            "vector_sha256_head": digest[:32],
            "vector_norm": round(norm, 8),
        }
        if include_vectors:
            payload["vector"] = qvec
        return payload
