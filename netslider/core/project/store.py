"""Portable project directory format (R5 skeleton).

Layout::

    project.netslider.json
    captures/
    action_logs/
    interpretations/
    observations/
    validations/
    settings.json
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_MANIFEST = "project.netslider.json"
LEGACY_MANIFEST = "project.madrigal.json"
SETTINGS_FILE = "settings.json"
FORMAT_VERSION = 1

SUBDIRS = (
    "captures",
    "action_logs",
    "interpretations",
    "observations",
    "validations",
)


class ProjectError(Exception):
    """Raised when a project cannot be created, opened, or saved."""


@dataclass
class ProjectMeta:
    name: str
    created_at: str
    format_version: int = FORMAT_VERSION
    description: str = ""
    captures: list[str] = field(default_factory=list)
    action_logs: list[str] = field(default_factory=list)
    interpretations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "format_version": self.format_version,
            "description": self.description,
            "captures": list(self.captures),
            "action_logs": list(self.action_logs),
            "interpretations": list(self.interpretations),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectMeta:
        return cls(
            name=str(data.get("name", "untitled")),
            created_at=str(data.get("created_at", "")),
            format_version=int(data.get("format_version", FORMAT_VERSION)),
            description=str(data.get("description", "")),
            captures=list(data.get("captures", [])),
            action_logs=list(data.get("action_logs", [])),
            interpretations=list(data.get("interpretations", [])),
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_settings() -> dict[str, Any]:
    return {
        "tcp": {
            "overlap_policy": "first_seen",
            "checksum_policy": "warn",
        },
        "ui": {
            "hex_bytes_per_row": 16,
        },
        "limits": {
            "max_capture_bytes": 200 * 1024 * 1024,  # 200 MiB soft warn
            "max_packets": 500_000,
            "warn_capture_bytes": 100 * 1024 * 1024,
            "warn_packets": 250_000,
        },
    }


class ProjectStore:
    """Create / open / save a portable netSlider project directory."""

    def __init__(self, root: Path, meta: ProjectMeta, settings: dict[str, Any]):
        self.root = root.resolve()
        self.meta = meta
        self.settings = settings

    @property
    def manifest_path(self) -> Path:
        return self.root / PROJECT_MANIFEST

    @classmethod
    def create(cls, root: Path, name: str, description: str = "") -> ProjectStore:
        root = root.resolve()
        if root.exists() and any(root.iterdir()):
            raise ProjectError(f"Directory is not empty: {root}")
        root.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (root / sub).mkdir(exist_ok=True)

        meta = ProjectMeta(name=name, created_at=_utc_now_iso(), description=description)
        settings = default_settings()
        store = cls(root, meta, settings)
        store.save()
        return store

    @classmethod
    def open(cls, root: Path) -> ProjectStore:
        root = root.resolve()
        manifest = root / PROJECT_MANIFEST
        legacy = root / LEGACY_MANIFEST
        if not manifest.is_file() and legacy.is_file():
            manifest = legacy
        if not manifest.is_file():
            raise ProjectError(f"Not a netSlider project (missing {PROJECT_MANIFEST}): {root}")
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProjectError(f"Corrupt project manifest: {exc}") from exc
        meta = ProjectMeta.from_dict(data)

        settings_path = root / SETTINGS_FILE
        if settings_path.is_file():
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        else:
            settings = default_settings()

        for sub in SUBDIRS:
            (root / sub).mkdir(exist_ok=True)

        store = cls(root, meta, settings)
        # Migrate legacy manifest filename on open
        if manifest.name == LEGACY_MANIFEST:
            store.save()
            try:
                legacy.unlink(missing_ok=True)
            except OSError:
                pass
        return store

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (self.root / sub).mkdir(exist_ok=True)
        self.manifest_path.write_text(
            json.dumps(self.meta.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (self.root / SETTINGS_FILE).write_text(
            json.dumps(self.settings, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def import_capture(self, src: Path, dest_name: str | None = None) -> Path:
        """Copy a capture into the project (never rewrite the source)."""
        src = src.resolve()
        if not src.is_file():
            raise ProjectError(f"Capture not found: {src}")
        name = dest_name or src.name
        dest = self.root / "captures" / name
        if dest.resolve() != src:
            shutil.copy2(src, dest)
        rel = f"captures/{name}"
        if rel not in self.meta.captures:
            self.meta.captures.append(rel)
        self.save()
        return dest

    def import_action_log(self, src: Path, dest_name: str | None = None) -> Path:
        src = src.resolve()
        if not src.is_file():
            raise ProjectError(f"Action log not found: {src}")
        name = dest_name or src.name
        dest = self.root / "action_logs" / name
        if dest.resolve() != src:
            shutil.copy2(src, dest)
        rel = f"action_logs/{name}"
        if rel not in self.meta.action_logs:
            self.meta.action_logs.append(rel)
        self.save()
        return dest

    def save_interpretation(self, name: str, content: str) -> Path:
        """Write an interpretation YAML/JSON/Python file into the project."""
        safe = Path(name).name
        if not safe:
            raise ProjectError("Interpretation name is required")
        if Path(safe).suffix.lower() not in {".yaml", ".yml", ".json", ".py"}:
            safe = f"{safe}.yaml"
        dest = self.root / "interpretations" / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        rel = f"interpretations/{safe}"
        if rel not in self.meta.interpretations:
            self.meta.interpretations.append(rel)
        self.save()
        return dest

    def import_interpretation(self, src: Path, dest_name: str | None = None) -> Path:
        src = src.resolve()
        if not src.is_file():
            raise ProjectError(f"Interpretation not found: {src}")
        name = dest_name or src.name
        dest = self.root / "interpretations" / name
        if dest.resolve() != src:
            shutil.copy2(src, dest)
        rel = f"interpretations/{name}"
        if rel not in self.meta.interpretations:
            self.meta.interpretations.append(rel)
        self.save()
        return dest

    def list_interpretations(self) -> list[Path]:
        """Return interpretation files (manifest + directory scan)."""
        found: list[Path] = []
        seen: set[str] = set()
        for rel in self.meta.interpretations:
            path = self.root / rel
            if path.is_file():
                found.append(path)
                seen.add(path.resolve().as_posix())
        interp_dir = self.root / "interpretations"
        if interp_dir.is_dir():
            for path in sorted(interp_dir.iterdir()):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in {".yaml", ".yml", ".json", ".py"}:
                    continue
                key = path.resolve().as_posix()
                if key not in seen:
                    found.append(path)
                    seen.add(key)
        return found

    def save_validation(self, name: str, payload: dict[str, Any]) -> Path:
        """Persist a validation result JSON under validations/."""
        safe = Path(name).name
        if not safe:
            raise ProjectError("Validation name is required")
        if not safe.endswith(".json"):
            safe = f"{safe}.json"
        dest = self.root / "validations" / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return dest

    def list_validations(self) -> list[Path]:
        vdir = self.root / "validations"
        if not vdir.is_dir():
            return []
        return sorted(p for p in vdir.iterdir() if p.is_file() and p.suffix == ".json")

    def load_validation_json(self, path: Path) -> dict[str, Any]:
        path = path.resolve()
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProjectError(f"Failed to load validation: {exc}") from exc

    def relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def resolve_rel(self, rel: str) -> Path:
        """Resolve a project-relative path; reject absolute / escape attempts."""
        rel = rel.replace("\\", "/").lstrip("/")
        if not rel or rel.startswith("..") or "/../" in f"/{rel}/":
            raise ProjectError(f"Invalid project-relative path: {rel}")
        path = (self.root / rel).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ProjectError(f"Path escapes project root: {rel}") from exc
        return path

    def save_observation(self, name: str, payload: dict[str, Any]) -> Path:
        safe = Path(name).name
        if not safe:
            raise ProjectError("Observation name is required")
        if not safe.endswith(".json"):
            safe = f"{safe}.json"
        dest = self.root / "observations" / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return dest

    def list_observations(self) -> list[Path]:
        odir = self.root / "observations"
        if not odir.is_dir():
            return []
        return sorted(p for p in odir.iterdir() if p.is_file() and p.suffix == ".json")

    def primary_interpretation(self) -> Path | None:
        """First interpretation from manifest, else first on disk."""
        interps = self.list_interpretations()
        return interps[0] if interps else None

    def assert_portable(self) -> list[str]:
        """Return warnings if manifest entries look non-portable (absolute paths)."""
        warnings: list[str] = []
        for field_name in ("captures", "action_logs", "interpretations"):
            for rel in getattr(self.meta, field_name):
                if Path(rel).is_absolute() or rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
                    warnings.append(f"{field_name} has absolute path: {rel}")
                elif ".." in Path(rel).parts:
                    warnings.append(f"{field_name} escapes with ..: {rel}")
        return warnings

    def package_zip(self, dest: Path | None = None) -> Path:
        """Zip the project directory for transfer (relative layout preserved)."""
        import zipfile

        dest = dest or (self.root.parent / f"{self.root.name}.netslider.zip")
        dest = dest.resolve()
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(self.root.rglob("*")):
                if not path.is_file():
                    continue
                if path.name.startswith("."):
                    continue
                arc = path.relative_to(self.root).as_posix()
                zf.write(path, arcname=arc)
        return dest
