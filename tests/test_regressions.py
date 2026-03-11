import asyncio
import datetime
import json
import os
import sys
import tempfile
import time
import unittest
from typing import Any, Dict
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import ValidationError

from osint_framework.api.main import app
from osint_framework.api.schemas import ScanRequest
from osint_framework.core.config import settings
from osint_framework.core.correlation import Correlator
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
