"""Resource limit checks against project settings / NFR profile."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LimitCheck:
    ok: bool
    warnings: list[str]
    errors: list[str]

    @property
    def blocked(self) -> bool:
        return bool(self.errors)


def default_limits() -> dict[str, int]:
    return {
        "max_capture_bytes": 200 * 1024 * 1024,
        "max_packets": 500_000,
        "warn_capture_bytes": 100 * 1024 * 1024,
        "warn_packets": 250_000,
    }


def merge_limits(settings: dict[str, Any] | None) -> dict[str, int]:
    base = default_limits()
    if not settings:
        return base
    raw = settings.get("limits") or {}
    for key in base:
        if key in raw:
            base[key] = int(raw[key])
    return base


def check_capture_file(path: Path, settings: dict[str, Any] | None = None) -> LimitCheck:
    limits = merge_limits(settings)
    warnings: list[str] = []
    errors: list[str] = []
    size = path.stat().st_size if path.is_file() else 0
    if size > limits["max_capture_bytes"]:
        errors.append(
            f"Capture {path.name} is {size} bytes "
            f"(limit {limits['max_capture_bytes']})"
        )
    elif size > limits["warn_capture_bytes"]:
        warnings.append(
            f"Capture {path.name} is {size} bytes "
            f"(NFR warn threshold {limits['warn_capture_bytes']})"
        )
    return LimitCheck(ok=not errors, warnings=warnings, errors=errors)


def check_packet_count(count: int, settings: dict[str, Any] | None = None) -> LimitCheck:
    limits = merge_limits(settings)
    warnings: list[str] = []
    errors: list[str] = []
    if count > limits["max_packets"]:
        errors.append(f"Packet count {count} exceeds limit {limits['max_packets']}")
    elif count > limits["warn_packets"]:
        warnings.append(
            f"Packet count {count} exceeds NFR warn threshold {limits['warn_packets']}"
        )
    return LimitCheck(ok=not errors, warnings=warnings, errors=errors)
