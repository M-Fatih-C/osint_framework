from __future__ import annotations

import json
import math
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class FaceSimilaritySearcher:
    provider_name = "cosine_index_v1"

    def __init__(
        self,
        *,
        index_path: str,
        min_score: float = 0.82,
        top_k: int = 5,
        max_items: int = 5000,
    ):
        self.index_path = Path(index_path)
        self.min_score = float(min_score)
        self.top_k = max(1, int(top_k))
        self.max_items = max(100, int(max_items))

    def search_and_update(
        self,
        embeddings: List[Dict[str, Any]],
        *,
        current_image_path: str,
        image_source: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_embeddings = [
            emb
            for emb in embeddings
            if isinstance(emb, dict)
            and isinstance(emb.get("vector"), list)
            and emb.get("dimension")
        ]

        if not clean_embeddings:
            return {
                "status": "skipped",
                "provider": self.provider_name,
                "reason": "no embeddings available",
                "matches": [],
                "matches_by_face": [],
            }

        index_doc = self._load_index()
        index_items = list(index_doc.get("items") or [])

        matches_by_face: List[Dict[str, Any]] = []
        flat_matches: List[Dict[str, Any]] = []

        for emb in clean_embeddings:
            face_ref = str(emb.get("face_ref") or "unknown_face")
            vector = self._to_float_vector(emb.get("vector") or [])
            if not vector:
                continue

            candidates: List[Dict[str, Any]] = []
            for indexed in index_items:
                indexed_vector = self._to_float_vector(indexed.get("vector") or [])
                if not indexed_vector or len(indexed_vector) != len(vector):
                    continue

                # Avoid matching a face with itself (same image + same vector hash).
                if (
                    str(indexed.get("image_path") or "") == str(current_image_path)
                    and indexed.get("vector_sha256_head") == emb.get("vector_sha256_head")
                ):
                    continue

                score = self._cosine_similarity(vector, indexed_vector)
                if score < self.min_score:
                    continue

                item = {
                    "face_ref": face_ref,
                    "score": round(score, 6),
                    "match_id": indexed.get("entry_id"),
                    "matched_face_ref": indexed.get("face_ref"),
                    "matched_image_path": indexed.get("image_path"),
                    "matched_created_at": indexed.get("created_at"),
                    "matched_provider": indexed.get("embedding_provider"),
                    "matched_source": indexed.get("image_source"),
                    "matched_vector_sha256_head": indexed.get("vector_sha256_head"),
                }
                candidates.append(item)

            candidates.sort(key=lambda x: x.get("score", 0.0), reverse=True)
            selected = candidates[: self.top_k]
            matches_by_face.append(
                {
                    "face_ref": face_ref,
                    "matches_count": len(selected),
                    "matches": selected,
                }
            )
            flat_matches.extend(selected)

        new_entries = self._build_index_entries(
            clean_embeddings,
            current_image_path=current_image_path,
            image_source=image_source,
        )
        if new_entries:
            index_items.extend(new_entries)
            if len(index_items) > self.max_items:
                # Keep the most recent items only.
                index_items = index_items[-self.max_items :]

            index_doc["items"] = index_items
            index_doc["updated_at"] = datetime.now(UTC).isoformat()
            self._save_index(index_doc)

        flat_matches.sort(key=lambda x: x.get("score", 0.0), reverse=True)

        return {
            "status": "ok",
            "provider": self.provider_name,
            "min_score": self.min_score,
            "top_k": self.top_k,
            "faces_processed": len(clean_embeddings),
            "matches_total": len(flat_matches),
            "matches": flat_matches,
            "matches_by_face": matches_by_face,
            "indexed_count": len(new_entries),
            "index_size": len(index_items),
            "index_path": str(self.index_path),
        }

    def _build_index_entries(
        self,
        embeddings: List[Dict[str, Any]],
        *,
        current_image_path: str,
        image_source: Optional[str],
    ) -> List[Dict[str, Any]]:
        now = datetime.now(UTC).isoformat()
        entries: List[Dict[str, Any]] = []
        for emb in embeddings:
            vector = self._to_float_vector(emb.get("vector") or [])
            if not vector:
                continue
            entries.append(
                {
                    "entry_id": f"fidx_{uuid.uuid4().hex[:12]}",
                    "created_at": now,
                    "image_path": str(current_image_path),
                    "image_source": image_source,
                    "face_ref": emb.get("face_ref"),
                    "embedding_provider": emb.get("provider"),
                    "dimension": len(vector),
                    "vector_sha256_head": emb.get("vector_sha256_head"),
                    "vector": vector,
                }
            )
        return entries

    def _load_index(self) -> Dict[str, Any]:
        if not self.index_path.exists():
            return {"schema_version": "1.0", "updated_at": None, "items": []}

        try:
            with self.index_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return {"schema_version": "1.0", "updated_at": None, "items": []}
            if not isinstance(data.get("items"), list):
                data["items"] = []
            return data
        except Exception:
            return {"schema_version": "1.0", "updated_at": None, "items": []}

    def _save_index(self, payload: Dict[str, Any]) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.index_path.with_suffix(self.index_path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        tmp.replace(self.index_path)

    def _to_float_vector(self, value: List[Any]) -> List[float]:
        out: List[float] = []
        for item in value:
            try:
                out.append(float(item))
            except (TypeError, ValueError):
                return []
        return out

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(y * y for y in b))
        if norm_a <= 0.0 or norm_b <= 0.0:
            return 0.0
        return dot / (norm_a * norm_b)
