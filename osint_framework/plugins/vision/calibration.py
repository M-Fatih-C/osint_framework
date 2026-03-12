from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from osint_framework.plugins.vision.face_embedding import FaceEmbeddingExtractor


@dataclass
class CalibrationSample:
    sample_id: str
    identity: str
    path: str


@dataclass
class EmbeddingRecord:
    sample_id: str
    identity: str
    path: str
    provider: str
    vector: List[float]


class VisionThresholdCalibrator:
    """
    Offline threshold calibration helper for face similarity.

    Manifest format (json/jsonl/csv):
    - required columns: path, identity
    - optional columns: sample_id
    """

    def __init__(
        self,
        *,
        min_threshold: float = 0.6,
        max_threshold: float = 0.98,
        step: float = 0.01,
        default_threshold: float = 0.82,
        max_pairs_per_class: int = 25000,
    ):
        self.min_threshold = max(0.0, min(1.0, float(min_threshold)))
        self.max_threshold = max(0.0, min(1.0, float(max_threshold)))
        if self.max_threshold < self.min_threshold:
            self.min_threshold, self.max_threshold = self.max_threshold, self.min_threshold
        self.step = max(0.001, float(step))
        self.default_threshold = max(0.0, min(1.0, float(default_threshold)))
        self.max_pairs_per_class = max(100, int(max_pairs_per_class))
        self.embedder = FaceEmbeddingExtractor()

    def calibrate_from_manifest(self, manifest_path: str) -> Dict[str, Any]:
        try:
            samples = self.load_manifest(manifest_path)
        except Exception as exc:
            return {"status": "error", "reason": f"manifest_load_failed: {exc}"}

        records, skipped = self.extract_embeddings(samples)
        identities = sorted({item.identity for item in records})
        positives, negatives = self.build_pair_scores(records)
        calibrated = self.calibrate_from_scores(positives, negatives)

        payload: Dict[str, Any] = {
            "status": calibrated.get("status"),
            "manifest_path": str(Path(manifest_path).resolve()),
            "samples_total": len(samples),
            "embeddings_total": len(records),
            "skipped_samples_total": len(skipped),
            "skipped_samples": skipped[:200],
            "identities_total": len(identities),
            "identities": identities[:200],
            "positive_pairs_total": len(positives),
            "negative_pairs_total": len(negatives),
            "distribution": {
                "positive_mean": self._round(self._mean(positives)),
                "positive_p50": self._round(self._percentile(positives, 50)),
                "positive_p90": self._round(self._percentile(positives, 90)),
                "negative_mean": self._round(self._mean(negatives)),
                "negative_p50": self._round(self._percentile(negatives, 50)),
                "negative_p90": self._round(self._percentile(negatives, 90)),
            },
        }
        payload.update(calibrated)
        return payload

    def calibrate_from_scores(
        self,
        positive_scores: List[float],
        negative_scores: List[float],
    ) -> Dict[str, Any]:
        positives = [self._clip_score(v) for v in positive_scores if isinstance(v, (int, float))]
        negatives = [self._clip_score(v) for v in negative_scores if isinstance(v, (int, float))]
        if not positives or not negatives:
            return {
                "status": "error",
                "reason": "insufficient_pairs (need both positive and negative similarity pairs)",
                "recommended_similarity_min_score": None,
                "best_threshold_metrics": None,
                "threshold_sweep": [],
            }

        thresholds = self._build_thresholds()
        sweep: List[Dict[str, Any]] = []
        best: Optional[Dict[str, Any]] = None
        best_key: Optional[Tuple[float, float, float, float, float]] = None
        for threshold in thresholds:
            metrics = self._metrics_for_threshold(positives, negatives, threshold)
            sweep.append(metrics)
            rank_key = (
                float(metrics["f1"]),
                float(metrics["precision"]),
                float(metrics["recall"]),
                float(metrics["accuracy"]),
                -abs(float(metrics["threshold"]) - self.default_threshold),
            )
            if best_key is None or rank_key > best_key:
                best_key = rank_key
                best = metrics

        quality = self._assess_calibration_quality(
            positives=positives,
            negatives=negatives,
            best_metrics=best or {},
        )
        is_reliable = bool(quality.get("reliable"))
        return {
            "status": "ok" if is_reliable else "warning",
            "recommended_similarity_min_score": best["threshold"] if (best and is_reliable) else None,
            "best_threshold_metrics": best,
            "threshold_sweep": sweep,
            "quality_assessment": quality,
        }

    def save_report(self, report: Dict[str, Any], output_path: str) -> str:
        out = Path(output_path)
        if not out.is_absolute():
            out = Path.cwd() / out
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        return str(out.resolve())

    def load_manifest(self, manifest_path: str) -> List[CalibrationSample]:
        path = Path(manifest_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"manifest not found: {path}")

        suffix = path.suffix.lower()
        rows: List[Dict[str, Any]] = []
        if suffix == ".jsonl":
            for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid jsonl at line {line_no}: {exc}") from exc
                if isinstance(item, dict):
                    rows.append(item)
        elif suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("samples"), list):
                rows = [item for item in payload["samples"] if isinstance(item, dict)]
            elif isinstance(payload, list):
                rows = [item for item in payload if isinstance(item, dict)]
            else:
                raise ValueError("json manifest must be a list or an object containing `samples`")
        elif suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as fh:
                rows = [dict(item) for item in csv.DictReader(fh)]
        else:
            raise ValueError("manifest extension must be one of: .json, .jsonl, .csv")

        samples: List[CalibrationSample] = []
        for idx, row in enumerate(rows):
            sample = self._row_to_sample(row=row, row_index=idx, base_dir=path.parent)
            samples.append(sample)
        if len(samples) < 2:
            raise ValueError("manifest must contain at least 2 valid samples")
        return samples

    def extract_embeddings(
        self,
        samples: List[CalibrationSample],
    ) -> Tuple[List[EmbeddingRecord], List[str]]:
        face_inputs = [{"face_ref": item.sample_id, "path": item.path} for item in samples]
        raw = self.embedder.extract(face_inputs, include_vectors=True)
        embeddings = (raw.get("embeddings") if isinstance(raw, dict) else []) or []

        by_ref: Dict[str, Dict[str, Any]] = {}
        for item in embeddings:
            if not isinstance(item, dict):
                continue
            key = str(item.get("face_ref") or "").strip()
            if not key:
                continue
            by_ref[key] = item

        records: List[EmbeddingRecord] = []
        skipped: List[str] = []
        for sample in samples:
            payload = by_ref.get(sample.sample_id)
            vector_raw = payload.get("vector") if isinstance(payload, dict) else None
            vector = self._to_vector(vector_raw)
            if not vector:
                skipped.append(sample.sample_id)
                continue
            records.append(
                EmbeddingRecord(
                    sample_id=sample.sample_id,
                    identity=sample.identity,
                    path=sample.path,
                    provider=str(payload.get("provider") or "unknown"),
                    vector=vector,
                )
            )
        return records, skipped

    def build_pair_scores(self, records: List[EmbeddingRecord]) -> Tuple[List[float], List[float]]:
        positives: List[float] = []
        negatives: List[float] = []
        for idx, left in enumerate(records):
            for right in records[idx + 1 :]:
                score = self._cosine_similarity(left.vector, right.vector)
                if left.identity == right.identity:
                    positives.append(score)
                else:
                    negatives.append(score)

        positives = self._downsample_scores(positives, self.max_pairs_per_class)
        negatives = self._downsample_scores(negatives, self.max_pairs_per_class)
        return positives, negatives

    def _row_to_sample(self, *, row: Dict[str, Any], row_index: int, base_dir: Path) -> CalibrationSample:
        sample_id = str(row.get("sample_id") or row.get("id") or f"sample_{row_index + 1}").strip()
        identity = str(
            row.get("identity")
            or row.get("person_id")
            or row.get("label")
            or row.get("target")
            or ""
        ).strip()
        path_value = str(row.get("path") or row.get("image_path") or row.get("file") or "").strip()

        if not sample_id:
            raise ValueError(f"manifest row {row_index + 1}: missing sample_id")
        if not identity:
            raise ValueError(f"manifest row {row_index + 1}: missing identity")
        if not path_value:
            raise ValueError(f"manifest row {row_index + 1}: missing path")

        sample_path = Path(path_value)
        if not sample_path.is_absolute():
            sample_path = (base_dir / sample_path).resolve()
        if not sample_path.exists() or not sample_path.is_file():
            raise FileNotFoundError(f"manifest row {row_index + 1}: image not found: {sample_path}")

        return CalibrationSample(sample_id=sample_id, identity=identity, path=str(sample_path))

    def _build_thresholds(self) -> List[float]:
        values: List[float] = []
        current = self.min_threshold
        safety = 0
        while current <= self.max_threshold + 1e-9 and safety < 5000:
            values.append(self._round(current))
            current += self.step
            safety += 1
        if not values or values[-1] < self.max_threshold:
            values.append(self._round(self.max_threshold))
        return values

    def _metrics_for_threshold(
        self,
        positives: List[float],
        negatives: List[float],
        threshold: float,
    ) -> Dict[str, Any]:
        tp = sum(1 for score in positives if score >= threshold)
        fn = len(positives) - tp
        fp = sum(1 for score in negatives if score >= threshold)
        tn = len(negatives) - fp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / (len(positives) + len(negatives))
        f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0.0 else 0.0
        far = fp / len(negatives) if negatives else 0.0
        frr = fn / len(positives) if positives else 0.0

        return {
            "threshold": self._round(threshold),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "precision": self._round(precision),
            "recall": self._round(recall),
            "f1": self._round(f1),
            "accuracy": self._round(accuracy),
            "far": self._round(far),
            "frr": self._round(frr),
        }

    def _downsample_scores(self, scores: List[float], limit: int) -> List[float]:
        if len(scores) <= limit:
            return [self._clip_score(value) for value in scores]
        ordered = sorted(scores)
        step = len(ordered) / float(limit)
        sampled = [ordered[min(len(ordered) - 1, int(i * step))] for i in range(limit)]
        return [self._clip_score(value) for value in sampled]

    def _assess_calibration_quality(
        self,
        *,
        positives: List[float],
        negatives: List[float],
        best_metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        pos_mean = self._mean(positives)
        neg_mean = self._mean(negatives)
        separation_gap = pos_mean - neg_mean
        unique_score_count = len({self._round(v) for v in (positives + negatives)})

        reasons: List[str] = []
        if unique_score_count <= 2:
            reasons.append("degenerate_similarity_distribution")
        if abs(separation_gap) < 0.03:
            reasons.append("low_positive_negative_separation")
        if float(best_metrics.get("far") or 0.0) > 0.35:
            reasons.append("high_false_accept_rate")
        if float(best_metrics.get("precision") or 0.0) < 0.75:
            reasons.append("low_precision")

        return {
            "reliable": len(reasons) == 0,
            "reasons": reasons,
            "separation_gap": self._round(separation_gap),
            "unique_score_count": int(unique_score_count),
            "positive_stddev": self._round(self._stddev(positives)),
            "negative_stddev": self._round(self._stddev(negatives)),
        }

    @staticmethod
    def _to_vector(value: Any) -> List[float]:
        if not isinstance(value, list):
            return []
        out: List[float] = []
        for item in value:
            try:
                out.append(float(item))
            except (TypeError, ValueError):
                return []
        return out

    @staticmethod
    def _cosine_similarity(left: List[float], right: List[float]) -> float:
        if not left or not right or len(left) != len(right):
            return 0.0
        dot = sum(a * b for a, b in zip(left, right))
        norm_left = math.sqrt(sum(a * a for a in left))
        norm_right = math.sqrt(sum(b * b for b in right))
        if norm_left <= 0.0 or norm_right <= 0.0:
            return 0.0
        return dot / (norm_left * norm_right)

    @staticmethod
    def _mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def _stddev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        return math.sqrt(max(0.0, variance))

    @staticmethod
    def _percentile(values: List[float], percentile: int) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        rank = int(round((max(0, min(100, percentile)) / 100.0) * (len(ordered) - 1)))
        return float(ordered[rank])

    @staticmethod
    def _clip_score(value: float) -> float:
        return max(-1.0, min(1.0, float(value)))

    @staticmethod
    def _round(value: float) -> float:
        return round(float(value), 6)
