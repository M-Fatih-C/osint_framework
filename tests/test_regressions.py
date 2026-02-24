import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from typing import Any, Dict

from fastapi.testclient import TestClient
from pydantic import ValidationError

from osint_framework.api.main import app
from osint_framework.api.schemas import ScanRequest
from osint_framework.core.config import settings
from osint_framework.core.database import db_manager
from osint_framework.core.engine import engine
from osint_framework.core.security import api_security
from osint_framework.job_queue.job_manager import job_manager
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
        target = f"example-{int(time.time() * 1000)}.com"
        job_id = await engine.queue_scan(target, "domain")

        for _ in range(50):
            job = await engine.get_merged_results(job_id)
            if job.get("status") in {"completed", "error"}:
                break
            await asyncio.sleep(0.1)

        job = await engine.get_merged_results(job_id)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["modules_total"], 1)
        self.assertEqual(job["modules_done"], 1)
        self.assertIn("correlated_intel", job)
        self.assertIsInstance(job["correlated_intel"], dict)
        self.assertEqual(job["correlated_intel"].get("summary"), f"summary for {target}")

        persisted = await job_manager.get_job(job_id)
        self.assertEqual(persisted["modules_total"], 1)
        self.assertIsNotNone(persisted["correlated_intel"])
        self.assertEqual(
            persisted["correlated_intel"].get("summary"), f"summary for {target}"
        )


if __name__ == "__main__":
    unittest.main()
