import asyncio
import datetime
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import ValidationError

from osint_framework.api.main import app
from osint_framework.api.schemas import ScanRequest
from osint_framework.core.config import settings
from osint_framework.core.correlation import Correlator
from osint_framework.core.pipeline import PipelineContext, PipelineRunner
from osint_framework.core.case_manager import case_manager
from osint_framework.core.database import db_manager
from osint_framework.core.engine import engine
from osint_framework.core.redis_event_bus import RedisEventBus
from osint_framework.core.security import api_security
from osint_framework.job_queue.job_manager import job_manager
from osint_framework.job_queue.redis_queue_backend import RedisQueueBackend
from osint_framework.job_queue.redis_worker_service import RedisWorkerService
from osint_framework.core.config import JWTUserConfig
from osint_framework.plugins.base import BaseModule
from osint_framework.plugins.person.username import UsernameModule
from osint_framework.plugins.registry import registry
from osint_framework.plugins.vision.calibration_apply import apply_calibration_report
from osint_framework.plugins.vision.calibration import VisionThresholdCalibrator
from osint_framework.plugins.vision.dataset_manifest import VisionCalibrationManifestBuilder
from osint_framework.plugins.vision.face_detector import VisionFaceDetector
from osint_framework.plugins.vision.identity_matcher import VisionIdentityMatcher
from osint_framework.plugins.vision.face_review import VisionFaceReviewSession
from osint_framework.plugins.vision.similarity_search import FaceSimilaritySearcher
from osint_framework.plugins.vision.vision_pipeline import DetectAndCropStage, FaceEmbeddingStage
from osint_framework.reports.ai_summary import ai_reporter


class FakeDomainModule(BaseModule):
    name = "FakeDomain"
    description = "Deterministic test module"
    target_types = ["domain"]
    timeout = 3

    async def run(self, target: str) -> Dict[str, Any]:
        await asyncio.sleep(0.05)
        return {"echo": target, "status": "ok"}


class SchemaValidationTests(unittest.TestCase):
    def test_scan_request_rejects_invalid_ip(self):
        with self.assertRaises(ValidationError):
            ScanRequest(target="999.1.1.1", target_type="ip")

    def test_scan_request_accepts_domain(self):
        req = ScanRequest(target=" example.com ", target_type="domain")
        self.assertEqual(req.target, "example.com")
        self.assertEqual(req.target_type, "domain")

    def test_scan_request_accepts_person_name_unicode(self):
        req = ScanRequest(target=" Muhammet Fatih Çetintaş ", target_type="person_name")
        self.assertEqual(req.target, "Muhammet Fatih Çetintaş")
        self.assertEqual(req.target_type, "person_name")

    def test_scan_request_accepts_image_target(self):
        req = ScanRequest(target="https://example.com/photo.jpg", target_type="image")
        self.assertEqual(req.target, "https://example.com/photo.jpg")
        self.assertEqual(req.target_type, "image")


class CorrelationNormalizationTests(unittest.TestCase):
    def test_correlator_builds_normalized_entities_relations_evidence(self):
        results = [
            {
                "module": "Person_Name_Handle_Generator",
                "data": {
                    "target_person_name": "Muhammet Fatih Çetintaş",
                    "normalized_name": "Muhammet Fatih Çetintaş",
                    "username_candidates": {
                        "conservative": ["muhammetfatihcetintas", "m.f.cetintas"]
                    },
                    "email_local_part_candidates": ["muhammet.fatih.cetintas"],
                },
            },
            {
                "module": "Username_Checker",
                "data": {
                    "target_username": "muhammetfatihcetintas",
                    "profiles": [
                        {
                            "site": "GitHub",
                            "url": "https://github.com/muhammetfatihcetintas",
                            "http_status": 200,
                        }
                    ],
                },
            },
            {
                "module": "Person_Name_Search_Dorks",
                "data": {
                    "target_person_name": "Muhammet Fatih Çetintaş",
                    "quick_links": [
                        {
                            "label": "LinkedIn profiles",
                            "google": "https://www.google.com/search?q=foo",
                            "bing": "https://www.bing.com/search?q=foo",
                        }
                    ],
                },
            },
            {
                "module": "Subdomain_Scanner",
                "data": {
                    "target_domain": "example.com",
                    "subdomains": ["api.example.com", "dev.example.com"],
                },
            },
        ]

        correlated = Correlator.analyze(
            results, target="Muhammet Fatih Çetintaş", target_type="person_name"
        )
        normalized = correlated.get("normalized")
        self.assertIsInstance(normalized, dict)
        self.assertEqual(normalized.get("schema_version"), "1.0")

        entities = normalized.get("entities") or []
        relations = normalized.get("relations") or []
        evidence = normalized.get("evidence") or []
        entity_types = {e.get("type") for e in entities}
        relation_types = {r.get("type") for r in relations}

        self.assertIn("person_name", entity_types)
        self.assertIn("username_candidate", entity_types)
        self.assertIn("url", entity_types)
        self.assertIn("search_url", entity_types)
        self.assertIn("candidate_username_for", relation_types)
        self.assertIn("has_profile", relation_types)
        self.assertGreaterEqual(len(evidence), 4)



    def test_correlator_normalizes_vision_entities(self):
        results = [
            {
                "module": "Vision_Image_OSINT",
                "data": {
                    "image_target": "/tmp/unit.jpg",
                    "image_path": "/tmp/unit.jpg",
                    "faces": [{"face_id": "face_1", "bbox": [0, 0, 10, 10]}],
                    "reverse_image_results": [
                        {"face_id": "face_1", "url": "https://example.com/profile/john", "provider": "pivot"}
                    ],
                    "similarity_matches": [
                        {
                            "face_ref": "face_1",
                            "score": 0.94,
                            "matched_image_path": "/tmp/known.jpg",
                            "matched_face_ref": "face_1",
                            "matched_provider": "deepface"
                        }
                    ],
                    "entities": [
                        {"type": "username", "value": "john_doe", "source_url": "https://example.com/profile/john"}
                    ],
                },
            }
        ]

        correlated = Correlator.analyze(results, target="/tmp/unit.jpg", target_type="image")
        normalized = correlated.get("normalized") or {}
        entity_types = {ent.get("type") for ent in (normalized.get("entities") or [])}
        relation_types = {rel.get("type") for rel in (normalized.get("relations") or [])}

        self.assertIn("image", entity_types)
        self.assertIn("face", entity_types)
        self.assertIn("url", entity_types)
        self.assertIn("contains_face", relation_types)
        self.assertIn("reverse_image_hit", relation_types)
        self.assertIn("similar_to_image", relation_types)
        self.assertIn("similar_to_face_reference", relation_types)


class PipelineRunnerMetricsTests(unittest.TestCase):
    def test_pipeline_events_include_duration(self):
        class Stage:
            def __init__(self, name: str):
                self.name = name

            async def run(self, context):
                await asyncio.sleep(0)

        context = PipelineContext(target="example.com", target_type="domain")
        runner = PipelineRunner([Stage("collect"), Stage("normalize")])
        asyncio.run(runner.execute(context))

        completed = [e for e in context.events if e.get("status") == "completed"]
        self.assertEqual(len(completed), 2)
        self.assertTrue(all(isinstance(e.get("duration_ms"), int) for e in completed))
        self.assertTrue(all("at_ms" in e for e in completed))


class VisionFaceDetectorQualityTests(unittest.TestCase):
    def test_detector_filters_low_quality_faces(self):
        detector = VisionFaceDetector()
        detector.min_confidence = 0.5
        detector.min_size_px = 30
        detector.iou_threshold = 0.45
        detector.max_faces = 5
        detector.allow_full_image_fallback = False

        detector._probe_dimensions = lambda _: (200, 200)

        def retina_provider(_):
            return {
                "status": "ok",
                "provider": "retinaface",
                "faces": [
                    {"face_id": "face_a", "bbox": [10, 10, 80, 80], "confidence": 0.95},
                    {"face_id": "face_b", "bbox": [12, 12, 78, 78], "confidence": 0.88},
                    {"face_id": "face_c", "bbox": [100, 100, 120, 120], "confidence": 0.99},
                    {"face_id": "face_d", "bbox": [30, 30, 90, 90], "confidence": 0.2},
                ],
            }

        def opencv_provider(_):
            return {"status": "ok", "provider": "opencv_haar", "faces": []}

        detector._detect_with_retinaface = retina_provider
        detector._detect_with_opencv = opencv_provider

        result = detector.detect_faces("dummy.jpg")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["provider"], "retinaface")
        self.assertEqual(len(result["faces"]), 1)
        self.assertEqual(result["faces"][0]["face_id"], "face_a")
        self.assertEqual(result["quality"]["rejected"]["below_confidence"], 1)
        self.assertEqual(result["quality"]["rejected"]["too_small"], 1)
        self.assertGreaterEqual(result["quality"]["nms_suppressed"], 1)

    def test_detector_returns_error_if_no_face_and_fallback_disabled(self):
        detector = VisionFaceDetector()
        detector.allow_full_image_fallback = False
        detector._probe_dimensions = lambda _: (160, 160)
        detector._detect_with_retinaface = lambda _: {"status": "ok", "provider": "retinaface", "faces": []}
        detector._detect_with_opencv = lambda _: {"status": "ok", "provider": "opencv_haar", "faces": []}

        result = detector.detect_faces("dummy.jpg")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["provider"], "none")
        self.assertEqual(result["faces"], [])
        self.assertIn("fallback disabled", result["reason"])


class VisionCropBoxTests(unittest.TestCase):
    def test_crop_box_applies_padding_and_square(self):
        stage = DetectAndCropStage()
        stage.crop_padding_ratio = 0.2
        stage.crop_square = True

        crop_bbox = stage._build_crop_bbox([40, 30, 70, 80], width=140, height=120)
        self.assertIsNotNone(crop_bbox)
        x1, y1, x2, y2 = crop_bbox
        self.assertGreaterEqual(x1, 0)
        self.assertGreaterEqual(y1, 0)
        self.assertLessEqual(x2, 140)
        self.assertLessEqual(y2, 120)
        self.assertEqual(x2 - x1, y2 - y1)
        self.assertLessEqual(x1, 40)
        self.assertLessEqual(y1, 30)
        self.assertGreaterEqual(x2, 70)
        self.assertGreaterEqual(y2, 80)


class VisionEmbeddingStageSelectionTests(unittest.TestCase):
    def test_stage_forces_top_face_when_all_are_below_threshold(self):
        stage = FaceEmbeddingStage()
        stage.min_face_confidence = 0.95
        stage.max_faces = 3
        stage.force_top_face = True
        captured = {}

        def fake_extract(face_inputs, include_vectors=False):
            captured["face_inputs"] = list(face_inputs)
            return {
                "status": "ok",
                "embeddings": [
                    {"face_ref": item["face_ref"], "vector": [0.1, 0.2], "provider": "unit"}
                    for item in face_inputs
                ],
            }

        stage.embedder.extract = fake_extract

        context = PipelineContext(target="dummy.jpg", target_type="image")
        context.data["faces"] = [
            {"face_id": "face_a", "bbox": [10, 10, 50, 50], "crop_path": "/tmp/a.jpg", "confidence": 0.30},
            {"face_id": "face_b", "bbox": [60, 20, 100, 80], "crop_path": "/tmp/b.jpg", "confidence": 0.15},
        ]

        asyncio.run(stage.run(context))

        selected = captured.get("face_inputs") or []
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["face_ref"], "face_a")
        self.assertEqual(context.data["embedding_inputs"]["used_total"], 1)
        self.assertEqual(context.data["embedding_inputs"]["forced_low_confidence"], 1)
        self.assertEqual(context.data["embedding_inputs"]["skipped_low_confidence"], 1)

    def test_stage_respects_max_faces_limit(self):
        stage = FaceEmbeddingStage()
        stage.min_face_confidence = 0.4
        stage.max_faces = 2
        stage.force_top_face = False
        captured = {}

        def fake_extract(face_inputs, include_vectors=False):
            captured["face_inputs"] = list(face_inputs)
            return {
                "status": "ok",
                "embeddings": [
                    {"face_ref": item["face_ref"], "vector": [0.1, 0.2], "provider": "unit"}
                    for item in face_inputs
                ],
            }

        stage.embedder.extract = fake_extract

        context = PipelineContext(target="dummy.jpg", target_type="image")
        context.data["faces"] = [
            {"face_id": "face_1", "bbox": [5, 5, 45, 45], "crop_path": "/tmp/1.jpg", "confidence": 0.91},
            {"face_id": "face_2", "bbox": [50, 10, 90, 50], "crop_path": "/tmp/2.jpg", "confidence": 0.83},
            {"face_id": "face_3", "bbox": [95, 15, 130, 55], "crop_path": "/tmp/3.jpg", "confidence": 0.77},
            {"face_id": "face_4", "bbox": [20, 60, 45, 85], "crop_path": "/tmp/4.jpg", "confidence": 0.10},
        ]

        asyncio.run(stage.run(context))

        selected = captured.get("face_inputs") or []
        self.assertEqual([item["face_ref"] for item in selected], ["face_1", "face_2"])
        self.assertEqual(context.data["embedding_inputs"]["used_total"], 2)
        self.assertEqual(context.data["embedding_inputs"]["trimmed_by_max_faces"], 1)
        self.assertEqual(context.data["embedding_inputs"]["skipped_low_confidence"], 1)


class VisionCalibrationTests(unittest.TestCase):
    def test_calibrator_recommends_reasonable_threshold(self):
        calibrator = VisionThresholdCalibrator(
            min_threshold=0.5,
            max_threshold=0.95,
            step=0.05,
            default_threshold=0.82,
        )
        report = calibrator.calibrate_from_scores(
            positive_scores=[0.93, 0.91, 0.88, 0.84],
            negative_scores=[0.15, 0.22, 0.33, 0.41, 0.55, 0.58],
        )

        self.assertEqual(report["status"], "ok")
        recommended = float(report["recommended_similarity_min_score"])
        self.assertGreaterEqual(recommended, 0.75)
        self.assertLessEqual(recommended, 0.85)
        best = report["best_threshold_metrics"]
        self.assertGreaterEqual(float(best["precision"]), 0.99)
        self.assertGreaterEqual(float(best["recall"]), 0.99)
        self.assertGreaterEqual(float(best["f1"]), 0.99)

    def test_calibrator_returns_error_with_insufficient_pairs(self):
        calibrator = VisionThresholdCalibrator()
        report = calibrator.calibrate_from_scores(
            positive_scores=[0.91, 0.89],
            negative_scores=[],
        )
        self.assertEqual(report["status"], "error")
        self.assertIn("insufficient_pairs", report["reason"])

    def test_calibrator_marks_warning_for_degenerate_distribution(self):
        calibrator = VisionThresholdCalibrator()
        report = calibrator.calibrate_from_scores(
            positive_scores=[1.0, 1.0, 1.0, 1.0],
            negative_scores=[1.0, 1.0, 1.0],
        )
        self.assertEqual(report["status"], "warning")
        self.assertIsNone(report["recommended_similarity_min_score"])
        quality = report.get("quality_assessment") or {}
        self.assertFalse(bool(quality.get("reliable")))
        self.assertIn("degenerate_similarity_distribution", quality.get("reasons", []))


class VisionCalibrationManifestBuilderTests(unittest.TestCase):
    def test_builder_subdirs_mode(self):
        with tempfile.TemporaryDirectory(prefix="vision_manifest_subdirs_") as tmpdir:
            base = Path(tmpdir)
            (base / "alice").mkdir(parents=True, exist_ok=True)
            (base / "bob").mkdir(parents=True, exist_ok=True)
            (base / "alice" / "a1.jpg").write_bytes(b"a1")
            (base / "alice" / "a2.jpg").write_bytes(b"a2")
            (base / "bob" / "b1.jpg").write_bytes(b"b1")
            (base / "bob" / "b2.jpg").write_bytes(b"b2")

            output = base / "manifest.json"
            builder = VisionCalibrationManifestBuilder()
            report = builder.build(
                dataset_dir=str(base),
                output_path=str(output),
                mode="subdirs",
                min_samples_per_identity=2,
            )

            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["identities_total"], 2)
            self.assertEqual(report["samples_total"], 4)
            self.assertTrue(output.exists())
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 4)
            self.assertEqual({item["identity"] for item in data}, {"alice", "bob"})

    def test_builder_prefix_mode(self):
        with tempfile.TemporaryDirectory(prefix="vision_manifest_prefix_") as tmpdir:
            base = Path(tmpdir)
            (base / "alice_01.jpg").write_bytes(b"a1")
            (base / "alice_02.jpg").write_bytes(b"a2")
            (base / "bob_01.jpg").write_bytes(b"b1")
            (base / "bob_02.jpg").write_bytes(b"b2")
            (base / "charlie_01.jpg").write_bytes(b"c1")

            output = base / "manifest_prefix.json"
            builder = VisionCalibrationManifestBuilder()
            report = builder.build(
                dataset_dir=str(base),
                output_path=str(output),
                mode="prefix",
                min_samples_per_identity=2,
            )

            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["mode"], "prefix")
            self.assertEqual(report["identities_total"], 2)
            self.assertEqual(report["samples_total"], 4)
            dropped = report["dropped_identities"]
            self.assertIn("charlie", dropped)
            self.assertEqual(int(dropped["charlie"]), 1)

    def test_builder_prefix_mode_skips_test_like_files(self):
        with tempfile.TemporaryDirectory(prefix="vision_manifest_filter_") as tmpdir:
            base = Path(tmpdir)
            (base / "20260101_010101_unit_test_a.jpg").write_bytes(b"t1")
            (base / "20260101_010101_unit_test_b.jpg").write_bytes(b"t2")
            (base / "20260101_john_01.jpg").write_bytes(b"j1")
            (base / "20260102_john_02.jpg").write_bytes(b"j2")
            (base / "20260103_jane_01.jpg").write_bytes(b"k1")
            (base / "20260104_jane_02.jpg").write_bytes(b"k2")

            output = base / "manifest_filtered.json"
            builder = VisionCalibrationManifestBuilder()
            report = builder.build(
                dataset_dir=str(base),
                output_path=str(output),
                mode="prefix",
                min_samples_per_identity=2,
            )

            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["identities_total"], 2)
            self.assertEqual(set(report["identities"]), {"jane", "john"})
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual({item["identity"] for item in data}, {"jane", "john"})


class VisionCalibrationApplyTests(unittest.TestCase):
    def test_apply_calibration_updates_config_and_env(self):
        with tempfile.TemporaryDirectory(prefix="vision_apply_") as tmpdir:
            base = Path(tmpdir)
            config_path = base / "config.yaml"
            env_path = base / ".env.example"
            report_path = base / "report.json"

            config_path.write_text(
                "integrations:\n  vision:\n    similarity_min_score: 0.82\n",
                encoding="utf-8",
            )
            env_path.write_text(
                "OSINT_VISION_SIMILARITY_MIN_SCORE=0.82\n",
                encoding="utf-8",
            )
            report_path.write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "recommended_similarity_min_score": 0.91,
                    }
                ),
                encoding="utf-8",
            )

            result = apply_calibration_report(
                report_path=str(report_path),
                config_path=str(config_path),
                env_example_path=str(env_path),
            )
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["config"]["status"], "updated")
            self.assertEqual(result["env_example"]["status"], "updated")
            self.assertIn("similarity_min_score: 0.91", config_path.read_text(encoding="utf-8"))
            self.assertIn("OSINT_VISION_SIMILARITY_MIN_SCORE=0.91", env_path.read_text(encoding="utf-8"))

    def test_apply_calibration_rejects_unreliable_report(self):
        with tempfile.TemporaryDirectory(prefix="vision_apply_warn_") as tmpdir:
            base = Path(tmpdir)
            config_path = base / "config.yaml"
            env_path = base / ".env.example"
            report_path = base / "report_warning.json"

            config_path.write_text(
                "integrations:\n  vision:\n    similarity_min_score: 0.82\n",
                encoding="utf-8",
            )
            env_path.write_text(
                "OSINT_VISION_SIMILARITY_MIN_SCORE=0.82\n",
                encoding="utf-8",
            )
            report_path.write_text(
                json.dumps(
                    {
                        "status": "warning",
                        "recommended_similarity_min_score": None,
                    }
                ),
                encoding="utf-8",
            )

            result = apply_calibration_report(
                report_path=str(report_path),
                config_path=str(config_path),
                env_example_path=str(env_path),
            )
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["reason"], "report_not_reliable_for_apply")
            self.assertIn("similarity_min_score: 0.82", config_path.read_text(encoding="utf-8"))
            self.assertIn("OSINT_VISION_SIMILARITY_MIN_SCORE=0.82", env_path.read_text(encoding="utf-8"))


class VisionFaceReviewTests(unittest.TestCase):
    def test_create_review_and_export_approved_faces(self):
        with tempfile.TemporaryDirectory(prefix="vision_review_") as tmpdir:
            base = Path(tmpdir)
            image_path = base / "group.jpg"
            review_dir = base / "review_session"
            dataset_dir = base / "dataset"

            # Small synthetic image for deterministic crop writes.
            from PIL import Image  # type: ignore

            Image.new("RGB", (800, 600), color=(120, 120, 120)).save(image_path, format="JPEG")

            session = VisionFaceReviewSession(min_size_px=40, max_faces=10)
            session.detector.detect_faces = lambda _: {
                "status": "ok",
                "provider": "unit",
                "faces": [
                    {"face_id": "face_1", "bbox": [100, 100, 300, 320], "confidence": 0.9},
                    {"face_id": "face_2", "bbox": [380, 120, 620, 360], "confidence": 0.88},
                ],
                "quality": {},
            }

            created = session.create_review(str(image_path), str(review_dir))
            self.assertEqual(created["status"], "ok")
            review_path = Path(created["review_path"])
            self.assertTrue(review_path.exists())

            doc = json.loads(review_path.read_text(encoding="utf-8"))
            self.assertEqual(doc["faces_total"], 2)
            faces = doc["faces"]
            faces[0]["approved"] = True
            faces[0]["identity"] = "alice"
            faces[1]["approved"] = True
            faces[1]["identity"] = "bob"
            review_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

            exported = session.export_approved_dataset(
                review_json_path=str(review_path),
                dataset_dir=str(dataset_dir),
                min_samples_per_identity=1,
            )
            self.assertEqual(exported["status"], "ok")
            self.assertEqual(exported["written_total"], 2)
            self.assertEqual(set(exported["identities"]), {"alice", "bob"})
            self.assertTrue((dataset_dir / "alice" / "sample_001.jpg").exists())
            self.assertTrue((dataset_dir / "bob" / "sample_001.jpg").exists())


class VisionSimilarityTests(unittest.TestCase):
    def test_similarity_index_matches_second_similar_face(self):
        with tempfile.TemporaryDirectory(prefix="vision_sim_") as tmpdir:
            index_path = os.path.join(tmpdir, "face_similarity_index.json")
            searcher = FaceSimilaritySearcher(
                index_path=index_path,
                min_score=0.8,
                top_k=3,
                max_items=100,
            )

            first = searcher.search_and_update(
                embeddings=[
                    {
                        "face_ref": "face_1",
                        "dimension": 4,
                        "vector": [1.0, 0.0, 0.0, 0.0],
                        "vector_sha256_head": "a1",
                        "provider": "unit",
                    }
                ],
                current_image_path="/tmp/a.jpg",
                image_source="path",
            )
            self.assertEqual(first["status"], "ok")
            self.assertEqual(first["matches_total"], 0)
            self.assertEqual(first["indexed_count"], 1)

            second = searcher.search_and_update(
                embeddings=[
                    {
                        "face_ref": "face_1",
                        "dimension": 4,
                        "vector": [0.99, 0.01, 0.0, 0.0],
                        "vector_sha256_head": "b1",
                        "provider": "unit",
                    }
                ],
                current_image_path="/tmp/b.jpg",
                image_source="path",
            )
            self.assertEqual(second["status"], "ok")
            self.assertGreaterEqual(second["matches_total"], 1)
            top = second["matches"][0]
            self.assertEqual(top["matched_image_path"], "/tmp/a.jpg")
            self.assertGreater(top["score"], 0.9)


class VisionIdentityMatcherTests(unittest.TestCase):
    def test_matcher_fuses_reverse_hits_and_entities(self):
        matcher = VisionIdentityMatcher(max_candidates=3, min_confidence=0.2)
        payload = matcher.match(
            image_target="/tmp/unit.jpg",
            reverse_search={
                "results": [
                    {
                        "url": "https://github.com/alice",
                        "title": "alice (GitHub)",
                        "match_type": "page_match",
                    }
                ]
            },
            scraped={
                "pages": [
                    {
                        "url": "https://github.com/alice",
                        "final_url": "https://github.com/alice",
                        "title": "alice (GitHub)",
                    }
                ],
                "entities": [
                    {
                        "type": "username",
                        "value": "alice",
                        "platform": "github",
                        "source_url": "https://github.com/alice",
                    },
                    {
                        "type": "person_name",
                        "value": "Alice Doe",
                        "source_url": "https://github.com/alice",
                    },
                    {
                        "type": "email",
                        "value": "alice@example.com",
                        "source_url": "https://github.com/alice",
                    },
                ],
            },
            similarity={"matches_total": 1},
        )

        self.assertEqual(payload["status"], "ok")
        self.assertGreaterEqual(payload["candidates_total"], 1)
        best = payload["best_candidate"]
        self.assertIsNotNone(best)
        self.assertTrue(any(u["platform"] == "github" for u in best.get("usernames", [])))
        self.assertIn("alice@example.com", best.get("emails", []))


class ApiBehaviorTests(unittest.TestCase):
    def test_importable_app_and_phone_target_is_listed(self):
        with TestClient(app) as client:
            resp = client.get("/api/v1/modules")
            self.assertEqual(resp.status_code, 200)
            module_names = {m["name"] for m in resp.json()}
            self.assertIn("Phone_Lookup", module_names)
            self.assertIn("Person_Name_Analyzer", module_names)

    def test_audit_endpoint_returns_items(self):
        with TestClient(app) as client:
            status_resp = client.get("/api/v1/status")
            self.assertEqual(status_resp.status_code, 200)

            audit_resp = client.get("/api/v1/audit?limit=20")
            self.assertEqual(audit_resp.status_code, 200)
            payload = audit_resp.json()
            self.assertIn("items", payload)
            paths = [item["path"] for item in payload["items"]]
            self.assertIn("/api/v1/status", paths)

    def test_plugin_registry_includes_new_modules(self):
        registry.discover()
        module_names = {m["name"] for m in registry.list_all()}
        self.assertIn("Phone_Lookup", module_names)
        self.assertIn("Email_Verify", module_names)
        self.assertIn("ASN_Lookup", module_names)
        self.assertIn("Person_Name_Analyzer", module_names)
        self.assertIn("Person_Name_Handle_Generator", module_names)
        self.assertIn("Person_Name_Search_Dorks", module_names)
        self.assertIn("Vision_Image_OSINT", module_names)

    def test_image_scan_upload_endpoint(self):
        with TestClient(app) as client:
            payload = {"file": ("unit_test.jpg", b"fake-image-bytes", "image/jpeg")}
            response = client.post("/api/v1/scan/image", files=payload)
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertIn("job_id", body)
            self.assertIn("status", body)

    def test_case_crud_endpoints(self):
        with TestClient(app) as client:
            create_resp = client.post(
                "/api/v1/cases",
                json={
                    "title": "Unit Test Case",
                    "description": "Track a target across scans",
                    "tags": ["unit", "regression"],
                    "priority": "high",
                },
            )
            self.assertEqual(create_resp.status_code, 200)
            case = create_resp.json()
            self.assertEqual(case["title"], "Unit Test Case")
            self.assertEqual(case["priority"], "high")
            case_id = case["id"]

            note_resp = client.post(
                f"/api/v1/cases/{case_id}/notes",
                json={"content": "Initial scoping completed", "author": "tester"},
            )
            self.assertEqual(note_resp.status_code, 200)
            self.assertEqual(note_resp.json()["author"], "tester")

            list_resp = client.get("/api/v1/cases?limit=10")
            self.assertEqual(list_resp.status_code, 200)
            items = list_resp.json()["items"]
            self.assertTrue(any(item["id"] == case_id for item in items))

            detail_resp = client.get(f"/api/v1/cases/{case_id}")
            self.assertEqual(detail_resp.status_code, 200)
            detail = detail_resp.json()
            self.assertEqual(detail["id"], case_id)
            self.assertGreaterEqual(detail["counts"]["notes"], 1)
            self.assertTrue(any(note["content"] == "Initial scoping completed" for note in detail["notes"]))


class SecurityMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.original_security = settings.security.model_copy(deep=True)
        self.original_rate_limit = settings.api.rate_limit
        asyncio.run(api_security.reset_rate_limiters())

    def tearDown(self):
        settings.security = self.original_security
        settings.api.rate_limit = self.original_rate_limit
        asyncio.run(api_security.reset_rate_limiters())

    def test_api_key_auth_blocks_and_allows(self):
        settings.security.enabled = True
        settings.security.api_keys = ["test-secret"]
        settings.security.protect_read_endpoints = False
        settings.security.audit_logging = False

        with TestClient(app) as client:
            no_key = client.post(
                "/api/v1/scan",
                json={"target": "999.1.1.1", "target_type": "ip"},
            )
            self.assertEqual(no_key.status_code, 401)

            ok = client.post(
                "/api/v1/scan",
                json={"target": "999.1.1.1", "target_type": "ip"},
                headers={"X-API-Key": "test-secret"},
            )
            self.assertNotEqual(ok.status_code, 401)
            self.assertEqual(ok.status_code, 422)  # route validation reached

    def test_rate_limit_returns_429(self):
        settings.security.enabled = False
        settings.security.audit_logging = False
        settings.api.rate_limit = "1/minute"

        with TestClient(app) as client:
            first = client.get("/api/v1/status")
            second = client.get("/api/v1/status")
            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 429)
            self.assertIn("retry_after", second.json())

    def test_jwt_issue_me_and_rbac(self):
        settings.security.enabled = False
        settings.security.audit_logging = False
        settings.security.jwt.enabled = True
        settings.security.jwt.secret = "unit-test-secret"
        settings.security.jwt.rbac_enabled = True
        settings.security.protect_read_endpoints = True
        settings.security.jwt.users = [
            JWTUserConfig(username="viewer", password="pw", roles=["viewer"]),
            JWTUserConfig(username="admin", password="pw", roles=["admin"]),
        ]

        with TestClient(app) as client:
            viewer_token_resp = client.post(
                "/api/v1/auth/token", json={"username": "viewer", "password": "pw"}
            )
            self.assertEqual(viewer_token_resp.status_code, 200)
            viewer_token = viewer_token_resp.json()["access_token"]

            me_resp = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {viewer_token}"},
            )
            self.assertEqual(me_resp.status_code, 200)
            self.assertTrue(me_resp.json()["authenticated"])

            audit_forbidden = client.get(
                "/api/v1/audit", headers={"Authorization": f"Bearer {viewer_token}"}
            )
            self.assertEqual(audit_forbidden.status_code, 403)

            admin_token_resp = client.post(
                "/api/v1/auth/token", json={"username": "admin", "password": "pw"}
            )
            self.assertEqual(admin_token_resp.status_code, 200)
            admin_token = admin_token_resp.json()["access_token"]
            audit_ok = client.get(
                "/api/v1/audit", headers={"Authorization": f"Bearer {admin_token}"}
            )
            self.assertEqual(audit_ok.status_code, 200)


class UsernameMaigretIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_maigret_cfg = settings.integrations.maigret.model_copy(deep=True)
        self.original_env_enabled = os.environ.get("OSINT_MAIGRET_ENABLED")
        self.original_env_command = os.environ.get("OSINT_MAIGRET_COMMAND")
        os.environ.pop("OSINT_MAIGRET_ENABLED", None)
        os.environ.pop("OSINT_MAIGRET_COMMAND", None)

        self.temp_dir = tempfile.TemporaryDirectory()
        self.fake_cli_path = os.path.join(self.temp_dir.name, "fake_maigret_cli.py")
        script = r'''
import json
import os
import sys

def get_arg_value(flag, default=None):
    if flag in sys.argv:
        idx = sys.argv.index(flag)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return default

def main():
    username = None
    for arg in sys.argv[1:]:
        if arg.startswith("-"):
            continue
        username = arg
        break
    username = username or "unknown"
    folder = get_arg_value("--folderoutput", ".")
    report_type = get_arg_value("--json", "simple")
    os.makedirs(folder, exist_ok=True)
    report_path = os.path.join(folder, f"{username}_{report_type}.json")
    payload = {
        "GitHub": {
            "url_user": f"https://github.com/{username}",
            "http_status": 200,
            "status": {"status": "CLAIMED", "tags": ["dev"], "ids_data": {"name": "Alice"}}
        },
        "Reddit": {
            "url_user": f"https://www.reddit.com/user/{username}",
            "http_status": 200,
            "status": {"status": "CLAIMED", "tags": ["forum"], "ids_data": {}}
        }
    }
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    print(f"wrote {report_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
        with open(self.fake_cli_path, "w", encoding="utf-8") as fh:
            fh.write(script)

    async def asyncTearDown(self):
        settings.integrations.maigret = self.original_maigret_cfg
        if self.original_env_enabled is None:
            os.environ.pop("OSINT_MAIGRET_ENABLED", None)
        else:
            os.environ["OSINT_MAIGRET_ENABLED"] = self.original_env_enabled
        if self.original_env_command is None:
            os.environ.pop("OSINT_MAIGRET_COMMAND", None)
        else:
            os.environ["OSINT_MAIGRET_COMMAND"] = self.original_env_command
        self.temp_dir.cleanup()

    async def test_username_module_parses_maigret_json_report(self):
        settings.integrations.maigret.enabled = True
        settings.integrations.maigret.command = f"{sys.executable} {self.fake_cli_path}"
        settings.integrations.maigret.top_sites = 20
        settings.integrations.maigret.timeout = 5
        settings.integrations.maigret.retries = 1
        settings.integrations.maigret.json_report_type = "simple"
        settings.integrations.maigret.all_sites = False

        result = await UsernameModule().run("alice")

        self.assertEqual(result["provider"], "maigret")
        self.assertEqual(result["target_username"], "alice")
        self.assertEqual(result["found_on"], 2)
        self.assertIn("GitHub", result["details"])
        self.assertIn("profiles", result)
        self.assertEqual(result["maigret"]["status"], "ok")
        self.assertEqual(result["maigret"]["top_sites"], 20)


class _FakeRedisPipeline:
    def __init__(self, client):
        self.client = client
        self._ops = []

    def llen(self, key):
        self._ops.append(("llen", key))
        return self

    async def execute(self):
        out = []
        for op, key in self._ops:
            if op == "llen":
                out.append(len(self.client._lists.get(key, [])))
        return out


class _FakeAsyncRedisClient:
    def __init__(self):
        self._lists = {}
        self.closed = False

    async def ping(self):
        return True

    async def close(self):
        self.closed = True

    async def lpush(self, key, raw):
        self._lists.setdefault(key, []).insert(0, raw)
        return len(self._lists[key])

    async def brpoplpush(self, src, dst, timeout=0):
        return await self.rpoplpush(src, dst)

    async def rpoplpush(self, src, dst):
        src_list = self._lists.setdefault(src, [])
        if not src_list:
            return None
        raw = src_list.pop()
        self._lists.setdefault(dst, []).insert(0, raw)
        return raw

    async def lrem(self, key, count, raw):
        values = self._lists.setdefault(key, [])
        removed = 0
        remaining = []
        for item in values:
            if removed < abs(count) and item == raw:
                removed += 1
                continue
            remaining.append(item)
        self._lists[key] = remaining
        return removed

    async def lrange(self, key, start, end):
        values = list(self._lists.setdefault(key, []))
        if end == -1:
            end = len(values) - 1
        if not values:
            return []
        return values[start : end + 1]

    def pipeline(self):
        return _FakeRedisPipeline(self)


class _FakePubSub:
    def __init__(self, messages=None):
        self.messages = list(messages or [])
        self.subscribed = []
        self.closed = False

    async def subscribe(self, channel):
        self.subscribed.append(channel)

    async def get_message(self, ignore_subscribe_messages=True, timeout=0):
        if self.messages:
            return self.messages.pop(0)
        await asyncio.sleep(0)
        return None

    async def unsubscribe(self, channel):
        return None

    async def close(self):
        self.closed = True


class _FakeEventRedisClient(_FakeAsyncRedisClient):
    def __init__(self, pubsub_messages=None):
        super().__init__()
        self.published = []
        self._pubsub = _FakePubSub(pubsub_messages)

    async def publish(self, channel, payload):
        self.published.append((channel, payload))
        return 1

    def pubsub(self):
        return self._pubsub


class RedisQueueBackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_queue = settings.queue.model_copy(deep=True)
        settings.queue.mode = "redis"
        settings.queue.redis_pending_key = "test:pending"
        settings.queue.redis_processing_key = "test:processing"
        settings.queue.reserve_timeout_seconds = 1
        self.client = _FakeAsyncRedisClient()
        self.backend = RedisQueueBackend(client=self.client)

    async def asyncTearDown(self):
        settings.queue = self.original_queue

    async def test_enqueue_reserve_ack_and_requeue(self):
        await self.backend.enqueue("job-a")
        await self.backend.enqueue("job-b")
        added = await self.backend.enqueue_if_missing("job-a")
        self.assertFalse(added)
        added = await self.backend.enqueue_if_missing("job-c")
        self.assertTrue(added)

        lengths = await self.backend.lengths()
        self.assertEqual(lengths["pending"], 3)
        self.assertEqual(lengths["processing"], 0)

        first = await self.backend.reserve()
        self.assertIsNotNone(first)
        self.assertEqual(first.job_id, "job-a")  # FIFO

        lengths = await self.backend.lengths()
        self.assertEqual(lengths["pending"], 2)
        self.assertEqual(lengths["processing"], 1)

        moved = await self.backend.requeue_all_inflight()
        self.assertEqual(moved, 1)
        lengths = await self.backend.lengths()
        self.assertEqual(lengths["pending"], 3)
        self.assertEqual(lengths["processing"], 0)

        item = await self.backend.reserve()
        self.assertIn(item.job_id, {"job-a", "job-b"})
        await self.backend.ack(item)
        lengths = await self.backend.lengths()
        self.assertEqual(lengths["processing"], 0)


class RedisEventBusTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_queue = settings.queue.model_copy(deep=True)
        settings.queue.mode = "redis"
        settings.queue.redis_events_channel = "test:events"

    async def asyncTearDown(self):
        settings.queue = self.original_queue

    async def test_publish_and_decode_envelope_roundtrip(self):
        client = _FakeEventRedisClient()
        bus = RedisEventBus(client=client)
        event = {"type": "job_update", "job_id": "abc", "status": "running"}
        await bus.publish(event, source="worker-1")
        self.assertEqual(len(client.published), 1)
        channel, raw = client.published[0]
        self.assertEqual(channel, "test:events")
        envelope = RedisEventBus.decode_envelope(raw)
        self.assertEqual(envelope["source"], "worker-1")
        self.assertEqual(envelope["event"], event)

    async def test_listen_forever_dispatches_and_ignores_self_source(self):
        self_source = "api-self"
        other_source = "worker-x"
        ignored = json.dumps({"source": self_source, "event": {"type": "job_update"}})
        accepted = json.dumps(
            {
                "source": other_source,
                "sent_at_ms": 1,
                "event": {"type": "module_result", "job_id": "j1", "module": "DNS_Enum"},
            }
        )
        client = _FakeEventRedisClient(
            pubsub_messages=[
                {"type": "message", "data": ignored},
                {"type": "message", "data": accepted},
            ]
        )
        bus = RedisEventBus(client=client)
        stop_event = asyncio.Event()
        seen = []

        async def handler(event, envelope):
            seen.append((event, envelope))
            stop_event.set()

        await bus.listen_forever(handler, stop_event, ignore_sources={self_source}, poll_interval_seconds=0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0]["type"], "module_result")
        self.assertEqual(seen[0][1]["source"], other_source)


class RedisWorkerServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_once_processes_and_acks(self):
        fake_item = SimpleNamespace(job_id="job-123", raw="raw")

        class FakeQueueBackend:
            enabled = True
            consumer_name = "fake-worker"

            def __init__(self):
                self.acked = []

            async def reserve(self):
                return fake_item

            async def ack(self, item):
                self.acked.append(item.job_id)

        backend = FakeQueueBackend()
        processed = []
        queue_calls = []

        class FakeEngine:
            def __init__(self):
                self.config = SimpleNamespace(
                    queue=SimpleNamespace(worker_lease_seconds=30, worker_heartbeat_interval_seconds=60)
                )
                self.queue = SimpleNamespace(
                    claim_worker_lease=self._claim,
                    heartbeat_worker_lease=self._heartbeat,
                    clear_worker_lease=self._clear,
                    reset_job_for_retry=self._reset,
                    update_job_status=self._update_status,
                )

            async def _claim(self, *args, **kwargs):
                queue_calls.append(("claim", args, kwargs))
                return True

            async def _heartbeat(self, *args, **kwargs):
                queue_calls.append(("heartbeat", args, kwargs))
                return True

            async def _clear(self, *args, **kwargs):
                queue_calls.append(("clear", args, kwargs))

            async def _reset(self, *args, **kwargs):
                queue_calls.append(("reset", args, kwargs))

            async def _update_status(self, *args, **kwargs):
                queue_calls.append(("status", args, kwargs))

            async def process_persisted_job(self, job_id):
                processed.append(job_id)

        service = RedisWorkerService(FakeEngine(), queue_backend=backend)
        did_work = await service.run_once()
        self.assertTrue(did_work)
        self.assertEqual(processed, ["job-123"])
        self.assertEqual(backend.acked, ["job-123"])
        self.assertIn("claim", [c[0] for c in queue_calls])
        self.assertIn("reset", [c[0] for c in queue_calls])
        self.assertIn("clear", [c[0] for c in queue_calls])


class JobLeaseRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await db_manager.init_db()

    async def test_recover_stale_running_job_requeues_and_clears_lease(self):
        job_id = await job_manager.create_job(
            f"lease-recovery-{int(time.time() * 1000)}.example.com",
            "domain",
        )
        await job_manager.update_job_status(job_id, "running")
        await job_manager.claim_worker_lease(job_id, worker_id="worker-test", lease_seconds=5)

        # Force lease expiry by writing a past expiry timestamp.
        async with db_manager.async_session_maker() as session:
            from sqlalchemy import select
            from osint_framework.core.models import Scan
            import uuid as _uuid
            res = await session.execute(select(Scan).where(Scan.id == _uuid.UUID(job_id)))
            scan = res.scalar_one()
            scan.worker_lease_expires_at = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(seconds=1)
            await session.commit()

        recovery = await job_manager.recover_stale_running_jobs(action="requeue")
        self.assertGreaterEqual(recovery["count"], 1)
        recovered_job = next((j for j in recovery["jobs"] if j["job_id"] == job_id), None)
        self.assertIsNotNone(recovered_job)
        self.assertEqual(recovered_job["to_status"], "queued")

        job = await job_manager.get_job(job_id)
        self.assertEqual(job["status"], "queued")
        self.assertIsNone(job.get("worker_lease_owner"))
        self.assertIsNone(job.get("worker_heartbeat_at"))
        self.assertIsNone(job.get("worker_lease_expires_at"))


class EnginePersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await db_manager.init_db()
        self.original_modules = dict(registry._modules)
        self.original_ai_generate = ai_reporter.generate_summary
        registry._modules = {FakeDomainModule.name: FakeDomainModule}

        async def fake_summary(job_data: Dict[str, Any]) -> str:
            return f"summary for {job_data.get('target')}"

        ai_reporter.generate_summary = fake_summary
        await engine.start()

    async def asyncTearDown(self):
        await engine.stop()
        registry._modules = self.original_modules
        ai_reporter.generate_summary = self.original_ai_generate

    async def test_job_fields_persist_modules_total_and_correlated_intel(self):
        case = await case_manager.create_case(
            title=f"Engine persistence case {int(time.time() * 1000)}",
            tags=["engine-test"],
        )
        target = f"example-{int(time.time() * 1000)}.com"
        job_id = await engine.queue_scan(target, "domain", case_id=case["id"])

        for _ in range(50):
            job = await engine.get_merged_results(job_id)
            if job.get("status") in {"completed", "error"}:
                break
            await asyncio.sleep(0.1)

        job = await engine.get_merged_results(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job.get("case_id"), case["id"])
        self.assertEqual(job["modules_total"], 1)
        self.assertEqual(job["modules_done"], 1)
        self.assertIn("correlated_intel", job)
        self.assertIsInstance(job["correlated_intel"], dict)
        self.assertEqual(job["correlated_intel"].get("summary"), f"summary for {target}")
        self.assertIsInstance(job["correlated_intel"].get("normalized"), dict)
        self.assertEqual(
            job["correlated_intel"]["normalized"].get("schema_version"),
            "1.0",
        )

        persisted = await job_manager.get_job(job_id)
        self.assertEqual(persisted.get("case_id"), case["id"])
        self.assertEqual(persisted["modules_total"], 1)
        self.assertIsNotNone(persisted["correlated_intel"])
        self.assertEqual(
            persisted["correlated_intel"].get("summary"), f"summary for {target}"
        )
        self.assertIsInstance(persisted["correlated_intel"].get("normalized"), dict)

        case_detail = await case_manager.get_case(case["id"])
        self.assertIsNotNone(case_detail)
        self.assertEqual(case_detail["counts"]["scans"], 1)
        self.assertEqual(case_detail["counts"]["targets"], 1)
        self.assertTrue(any(t["target"] == target for t in case_detail["tracked_targets"]))
        self.assertTrue(any(j["job_id"] == job_id for j in case_detail["recent_jobs"]))


if __name__ == "__main__":
    unittest.main()
