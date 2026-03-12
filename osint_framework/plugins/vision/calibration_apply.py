from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict


_YAML_SCORE_RE = re.compile(r"(^\s*similarity_min_score:\s*)([0-9]*\.?[0-9]+)\s*$", re.MULTILINE)
_ENV_SCORE_RE = re.compile(
    r"(^\s*OSINT_VISION_SIMILARITY_MIN_SCORE\s*=\s*)([0-9]*\.?[0-9]+)\s*$",
    re.MULTILINE,
)


def apply_calibration_report(
    *,
    report_path: str,
    config_path: str = "osint_framework/config.yaml",
    env_example_path: str = ".env.example",
) -> Dict[str, Any]:
    report_file = _resolve_file(report_path)
    report = json.loads(report_file.read_text(encoding="utf-8"))

    status = str(report.get("status") or "").strip().lower()
    recommended = report.get("recommended_similarity_min_score")
    if status != "ok" or recommended is None:
        return {
            "status": "error",
            "reason": "report_not_reliable_for_apply",
            "report_status": status,
            "recommended_similarity_min_score": recommended,
        }

    value = round(float(recommended), 6)
    config_result = _apply_value_in_file(
        file_path=config_path,
        pattern=_YAML_SCORE_RE,
        value=value,
    )
    env_result = _apply_value_in_file(
        file_path=env_example_path,
        pattern=_ENV_SCORE_RE,
        value=value,
    )

    return {
        "status": "ok",
        "applied_similarity_min_score": value,
        "config": config_result,
        "env_example": env_result,
    }


def _apply_value_in_file(*, file_path: str, pattern: re.Pattern[str], value: float) -> Dict[str, Any]:
    target = _resolve_file(file_path)
    content = target.read_text(encoding="utf-8")
    match = pattern.search(content)
    if not match:
        return {
            "status": "skipped",
            "path": str(target),
            "reason": "pattern_not_found",
        }

    old_value = float(match.group(2))
    new_value = float(value)
    if abs(old_value - new_value) < 1e-9:
        return {
            "status": "unchanged",
            "path": str(target),
            "old_value": old_value,
            "new_value": new_value,
        }

    replaced = pattern.sub(lambda m: f"{m.group(1)}{new_value}", content, count=1)
    target.write_text(replaced, encoding="utf-8")
    return {
        "status": "updated",
        "path": str(target),
        "old_value": old_value,
        "new_value": new_value,
    }


def _resolve_file(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    return path
