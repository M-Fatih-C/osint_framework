import asyncio
import importlib.util
import json
import os
import shlex
import shutil
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from osint_framework.core.config import settings
from osint_framework.core.logger import logger
from osint_framework.plugins.base import BaseModule


@dataclass
class UsernameProviderOutcome:
    provider: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = field(default_factory=dict)


class UsernameProvider(ABC):
    provider_name: str = "base"

    def __init__(self, module: BaseModule):
        self.module = module

    @abstractmethod
    async def scan(self, target: str) -> UsernameProviderOutcome:
        """Attempt a username scan and return a normalized provider outcome."""

    @property
    def module_name(self) -> str:
        return getattr(self.module, "name", self.__class__.__name__)

    def _trim_text(self, text: str, max_len: int = 2000) -> str:
        text = (text or "").strip()
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."


class MaigretUsernameProvider(UsernameProvider):
    provider_name = "maigret"

    async def scan(self, target: str) -> UsernameProviderOutcome:
        cfg = settings.integrations.maigret
        if not self._maigret_enabled():
            return UsernameProviderOutcome(
                provider=self.provider_name,
                success=False,
                meta={"status": "disabled", "reason": "Maigret integration is disabled."},
            )

        command = self._resolve_maigret_command(cfg.command)
        if not command:
            return UsernameProviderOutcome(
                provider=self.provider_name,
                success=False,
                meta={
                    "status": "unavailable",
                    "reason": (
                        "Maigret executable/module not found. Install `maigret` or "
                        "configure integrations.maigret.command."
                    ),
                },
            )

        json_report_type = (
            cfg.json_report_type if cfg.json_report_type in {"simple", "ndjson"} else "simple"
        )

        with tempfile.TemporaryDirectory(prefix="osint_maigret_") as tmpdir:
            cmd = self._build_maigret_command(
                base_command=command,
                target=target,
                folderoutput=tmpdir,
                json_report_type=json_report_type,
            )
            start = time.perf_counter()
            stdout_text = ""
            stderr_text = ""

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                logger.warning("[%s] Maigret command not found: %s", self.module_name, exc)
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={"status": "unavailable", "reason": str(exc), "command": command},
                )
            except Exception as exc:
                logger.warning("[%s] Failed to start Maigret: %s", self.module_name, exc)
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={"status": "error", "reason": str(exc), "command": command},
                )

            process_timeout = self._maigret_process_timeout_seconds()
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=process_timeout
                )
                stdout_text = (stdout_bytes or b"").decode("utf-8", errors="ignore")
                stderr_text = (stderr_bytes or b"").decode("utf-8", errors="ignore")
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.communicate()
                except Exception:
                    pass
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={
                        "status": "timeout",
                        "reason": f"Maigret process exceeded {process_timeout}s",
                        "command": cmd,
                    },
                )

            duration_ms = int((time.perf_counter() - start) * 1000)
            if proc.returncode != 0:
                logger.warning("[%s] Maigret returned code %s", self.module_name, proc.returncode)
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={
                        "status": "error",
                        "reason": f"Maigret exited with code {proc.returncode}",
                        "command": cmd,
                        "return_code": proc.returncode,
                        "stdout": self._trim_text(stdout_text),
                        "stderr": self._trim_text(stderr_text),
                        "duration_ms": duration_ms,
                    },
                )

            report_file = self._locate_maigret_report_file(tmpdir, json_report_type)
            if not report_file:
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={
                        "status": "error",
                        "reason": "Maigret completed but no JSON report file was found.",
                        "command": cmd,
                        "stdout": self._trim_text(stdout_text),
                        "stderr": self._trim_text(stderr_text),
                        "duration_ms": duration_ms,
                    },
                )

            try:
                report_data = self._load_maigret_report(report_file, json_report_type)
            except Exception as exc:
                logger.warning("[%s] Failed to parse Maigret JSON report: %s", self.module_name, exc)
                return UsernameProviderOutcome(
                    provider=self.provider_name,
                    success=False,
                    meta={
                        "status": "error",
                        "reason": f"Failed to parse Maigret report: {exc}",
                        "report_file": str(report_file),
                        "duration_ms": duration_ms,
                    },
                )

            normalized = self._normalize_maigret_report(target, report_data)
            normalized["maigret"] = {
                "status": "ok",
                "provider": "maigret",
                "command": cmd,
                "json_report_type": json_report_type,
                "top_sites": None if cfg.all_sites else cfg.top_sites,
                "all_sites": cfg.all_sites,
                "timeout_per_request_s": cfg.timeout,
                "duration_ms": duration_ms,
                "report_file": report_file.name,
                "stdout_tail": self._trim_text(stdout_text, max_len=800),
                "stderr_tail": self._trim_text(stderr_text, max_len=800),
            }
            return UsernameProviderOutcome(
                provider=self.provider_name,
                success=True,
                data=normalized,
                meta={"status": "ok"},
            )

    def _maigret_enabled(self) -> bool:
        env_value = os.getenv("OSINT_MAIGRET_ENABLED")
        if env_value is not None:
            return env_value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(settings.integrations.maigret.enabled)

    def _resolve_maigret_command(self, configured_command: Optional[str]) -> Optional[List[str]]:
        env_command = os.getenv("OSINT_MAIGRET_COMMAND")
        if env_command:
            return shlex.split(env_command)

        if configured_command:
            return shlex.split(configured_command)

        if importlib.util.find_spec("maigret") is not None:
            return [sys.executable, "-m", "maigret"]

        maigret_bin = shutil.which("maigret")
        if maigret_bin:
            return [maigret_bin]

        return None

    def _build_maigret_command(
        self,
        base_command: List[str],
        target: str,
        folderoutput: str,
        json_report_type: str,
    ) -> List[str]:
        cfg = settings.integrations.maigret
        cmd = [
            *base_command,
            target,
            "--json",
            json_report_type,
            "--folderoutput",
            folderoutput,
            "--timeout",
            str(cfg.timeout),
            "--retries",
            str(cfg.retries),
        ]

        if cfg.all_sites:
            cmd.append("--all-sites")
        else:
            cmd.extend(["--top-sites", str(cfg.top_sites)])

        if cfg.no_progressbar:
            cmd.append("--no-progressbar")
        if cfg.no_color:
            cmd.append("--no-color")
        if cfg.no_recursion:
            cmd.append("--no-recursion")
        if cfg.no_extracting:
            cmd.append("--no-extracting")

        return cmd

    def _maigret_process_timeout_seconds(self) -> int:
        cfg = settings.integrations.maigret
        # Keep a buffer under the outer module timeout to cleanly kill subprocesses.
        outer_timeout = int(getattr(self.module, "timeout", 90))
        upper_bound = max(15, outer_timeout - 5)
        estimated = max(20, cfg.timeout * 6)
        return min(upper_bound, estimated)

    def _locate_maigret_report_file(
        self, folderoutput: str, json_report_type: str
    ) -> Optional[Path]:
        folder = Path(folderoutput)
        preferred = sorted(
            folder.glob(f"*_{json_report_type}.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if preferred:
            return preferred[0]

        any_json = sorted(
            folder.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return any_json[0] if any_json else None

    def _load_maigret_report(self, report_file: Path, json_report_type: str) -> Dict[str, Any]:
        if json_report_type == "ndjson":
            rows: Dict[str, Any] = {}
            with report_file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    sitename = item.get("sitename") or item.get("site", {}).get("name")
                    if sitename:
                        rows[sitename] = item
            return rows

        with report_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}

    def _normalize_maigret_report(self, target: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        profiles: List[Dict[str, Any]] = []
        status_map: Dict[str, str] = {}
        raw_sites = report_data if isinstance(report_data, dict) else {}

        for sitename, site_result in raw_sites.items():
            if not isinstance(site_result, dict):
                continue

            status_info = site_result.get("status")
            if isinstance(status_info, dict):
                status_value = str(status_info.get("status") or "")
                tags = status_info.get("tags") or []
                ids_data = status_info.get("ids_data") or {}
                status_url = status_info.get("site_url_user")
            else:
                status_value = str(status_info or "")
                tags = []
                ids_data = {}
                status_url = None

            profile_url = site_result.get("url_user") or status_url
            profile = {
                "site": sitename,
                "url": profile_url,
                "http_status": site_result.get("http_status"),
                "status": status_value or "CLAIMED",
                "tags": tags if isinstance(tags, list) else [],
                "ids_data": ids_data if isinstance(ids_data, dict) else {},
            }
            profiles.append(profile)
            status_map[sitename] = "Found"

        profiles.sort(key=lambda item: (item.get("site") or "").lower())

        return {
            "provider": "maigret",
            "target_username": target,
            "total_platforms_checked": len(raw_sites),
            "found_on": len(profiles),
            "details": status_map,
            "profiles": profiles,
            "raw_sites_returned": len(raw_sites),
        }


class BasicHttpUsernameProvider(UsernameProvider):
    provider_name = "basic_http_fallback"

    def __init__(self, module: BaseModule, platforms: Mapping[str, str]):
        super().__init__(module)
        self.platforms = dict(platforms)

    async def scan(self, target: str) -> UsernameProviderOutcome:
        logger.debug("[%s] Falling back to lightweight HTTP checks for: %s", self.module_name, target)

        results: Dict[str, str] = {}

        async def check_platform(name: str, url_template: str):
            url = url_template.format(target)
            async with self.module.get_client() as client:
                try:
                    resp = await client.get(url, follow_redirects=False, timeout=10)
                    if resp.status_code == 200:
                        results[name] = "Found"
                    elif resp.status_code == 404:
                        results[name] = "Not Found"
                    else:
                        results[name] = f"Unknown (HTTP {resp.status_code})"
                except Exception as exc:
                    results[name] = f"Error: {str(exc)}"

        tasks = [check_platform(name, url) for name, url in self.platforms.items()]
        await asyncio.gather(*tasks)

        found_count = sum(1 for status in results.values() if status == "Found")
        data = {
            "provider": self.provider_name,
            "target_username": target,
            "total_platforms_checked": len(self.platforms),
            "found_on": found_count,
            "details": results,
        }
        return UsernameProviderOutcome(
            provider=self.provider_name,
            success=True,
            data=data,
            meta={"status": "ok"},
        )
