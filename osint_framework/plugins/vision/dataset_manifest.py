from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple


class VisionCalibrationManifestBuilder:
    """Builds calibration manifests from local face dataset folders."""

    IMAGE_EXTENSIONS = {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".bmp",
        ".tif",
        ".tiff",
    }
    _SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9]+")
    _EXCLUDE_NAME_RE = re.compile(
        r"(unit[_-]?test|dummy|mock|placeholder|sample[_-]?test|fixture)",
        re.IGNORECASE,
    )
    _TOKEN_SPLIT_RE = re.compile(r"[_\-\s]+")
    _TOKEN_STOPWORDS = {"img", "image", "photo", "pic", "face", "crop", "frame", "snapshot"}

    def build(
        self,
        *,
        dataset_dir: str,
        output_path: str,
        mode: str = "auto",
        min_samples_per_identity: int = 2,
    ) -> Dict[str, object]:
        root = self._resolve_dir(dataset_dir)
        selected_mode, groups, dropped = self._collect_groups(
            root=root,
            mode=mode,
            min_samples=max(1, int(min_samples_per_identity)),
        )

        manifest = self._to_manifest(groups)
        saved_path = self._write_manifest(manifest, output_path)
        identities = sorted(groups.keys())
        return {
            "status": "ok",
            "mode": selected_mode,
            "dataset_dir": str(root),
            "output_path": saved_path,
            "identities_total": len(identities),
            "samples_total": len(manifest),
            "identities": identities,
            "samples_per_identity": {key: len(groups[key]) for key in identities},
            "dropped_identities": dropped,
        }

    def _resolve_dir(self, dataset_dir: str) -> Path:
        root = Path(dataset_dir)
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"dataset directory not found: {root}")
        return root

    def _collect_groups(
        self,
        *,
        root: Path,
        mode: str,
        min_samples: int,
    ) -> Tuple[str, Dict[str, List[Path]], Dict[str, int]]:
        normalized_mode = (mode or "auto").strip().lower()
        if normalized_mode not in {"auto", "subdirs", "prefix"}:
            raise ValueError("mode must be one of: auto, subdirs, prefix")

        if normalized_mode == "subdirs":
            groups = self._group_by_subdirs(root)
        elif normalized_mode == "prefix":
            groups = self._group_by_prefix(root)
        else:
            subdir_groups = self._group_by_subdirs(root)
            if len(subdir_groups) >= 2:
                groups = subdir_groups
                normalized_mode = "subdirs"
            else:
                groups = self._group_by_prefix(root)
                normalized_mode = "prefix"

        filtered, dropped = self._filter_groups(groups, min_samples=min_samples)
        if len(filtered) < 2:
            raise ValueError(
                "need at least 2 identities with enough samples for calibration"
            )
        return normalized_mode, filtered, dropped

    def _group_by_subdirs(self, root: Path) -> Dict[str, List[Path]]:
        groups: Dict[str, List[Path]] = {}
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            files = self._list_images(child)
            if not files:
                continue
            groups[child.name.strip()] = files
        return groups

    def _group_by_prefix(self, root: Path) -> Dict[str, List[Path]]:
        groups: Dict[str, List[Path]] = {}
        for file_path in self._list_images(root):
            identity = self._identity_from_filename(file_path)
            groups.setdefault(identity, []).append(file_path)
        return groups

    def _filter_groups(
        self,
        groups: Dict[str, List[Path]],
        *,
        min_samples: int,
    ) -> Tuple[Dict[str, List[Path]], Dict[str, int]]:
        kept: Dict[str, List[Path]] = {}
        dropped: Dict[str, int] = {}
        for identity, items in sorted(groups.items()):
            clean_identity = self._clean_identity(identity)
            clean_items = sorted(items)
            if len(clean_items) < min_samples:
                dropped[clean_identity] = len(clean_items)
                continue
            kept[clean_identity] = clean_items
        return kept, dropped

    def _to_manifest(self, groups: Dict[str, List[Path]]) -> List[Dict[str, str]]:
        manifest: List[Dict[str, str]] = []
        for identity in sorted(groups.keys()):
            files = groups[identity]
            safe_identity = self._clean_identity(identity)
            for idx, file_path in enumerate(files, start=1):
                sample_id = f"{safe_identity}_{idx:04d}"
                manifest.append(
                    {
                        "sample_id": sample_id,
                        "identity": safe_identity,
                        "path": str(file_path.resolve()),
                    }
                )
        return manifest

    def _write_manifest(self, manifest: List[Dict[str, str]], output_path: str) -> str:
        target = Path(output_path)
        if not target.is_absolute():
            target = (Path.cwd() / target).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
        return str(target)

    def _list_images(self, root: Path) -> List[Path]:
        files: List[Path] = []
        for item in root.rglob("*"):
            if not item.is_file():
                continue
            if item.suffix.lower() not in self.IMAGE_EXTENSIONS:
                continue
            if self._EXCLUDE_NAME_RE.search(item.name):
                continue
            files.append(item)
        return sorted(files)

    def _identity_from_filename(self, file_path: Path) -> str:
        stem = file_path.stem.strip().lower()
        if not stem:
            return "unknown"
        tokens = [token.strip() for token in self._TOKEN_SPLIT_RE.split(stem) if token.strip()]
        for token in tokens:
            if token in self._TOKEN_STOPWORDS:
                continue
            if token.isdigit() and len(token) >= 4:
                continue
            if token in {"unit", "test"}:
                continue
            return token
        return tokens[0] if tokens else stem

    def _clean_identity(self, value: str) -> str:
        raw = value.strip().lower()
        if not raw:
            return "unknown"
        cleaned = self._SAFE_ID_RE.sub("_", raw).strip("_")
        return cleaned or "unknown"
