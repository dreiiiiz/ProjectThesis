"""Shared helpers for offline Windows registry hive parsers."""

from __future__ import annotations

from codecs import decode as codec_decode
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from normalizer import ImageLabel, Severity, UnifiedArtifact

try:
    from Registry import Registry
    from Registry import RegistryParse
except ModuleNotFoundError:  # pragma: no cover - exercised only without dependency.
    Registry = None
    RegistryParse = None


UNKNOWN_TIMESTAMP = "1970-01-01T00:00:00Z"


def open_hive(hive_path: str | Path):
    """Open a registry hive with python-registry."""
    if Registry is None:
        raise RuntimeError(
            "Missing dependency: install python-registry with "
            "`pip install python-registry` before parsing registry hives."
        )
    try:
        return Registry.Registry(str(hive_path))
    except PermissionError as exc:
        raise RuntimeError(
            f"Permission denied while reading registry hive: {hive_path}. "
            "Run the terminal as Administrator or copy the hive to a writable "
            "local folder first, then parse the copied file."
        ) from exc


def get_key(registry, path: str):
    """Return a key by path, or None if it does not exist."""
    try:
        return registry.open(path)
    except Exception:
        return None


def get_value(key, name: str):
    """Return a registry value by name, or None when absent."""
    try:
        return key.value(name).value()
    except Exception:
        return None


def iter_subkeys(key) -> Iterable:
    """Safely iterate subkeys."""
    if key is None:
        return ()
    try:
        return key.subkeys()
    except Exception:
        return ()


def iter_values(key) -> Iterable:
    """Safely iterate values."""
    if key is None:
        return ()
    try:
        return key.values()
    except Exception:
        return ()


def timestamp_from_key(key) -> str:
    """Convert a registry key last-write timestamp to ISO 8601 UTC."""
    try:
        value = key.timestamp()
    except Exception:
        return UNKNOWN_TIMESTAMP

    if value is None:
        return UNKNOWN_TIMESTAMP
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def value_to_text(value) -> str:
    """Convert common registry value payloads into compact text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return "; ".join(value_to_text(item) for item in value)
    return str(value)


def rot13(text: str) -> str:
    """Decode ROT13-encoded UserAssist names."""
    return codec_decode(text, "rot_13")


def artifact(
    *,
    timestamp: str,
    artifact_type: str,
    user: str | None,
    event_description: str,
    source: str,
    raw_value: str,
    severity: Severity,
    image_label: ImageLabel,
) -> UnifiedArtifact:
    """Create a unified artifact with one import point for schema changes."""
    return UnifiedArtifact(
        timestamp=timestamp,
        artifact_type=artifact_type,
        user=user,
        event_description=event_description,
        source=source,
        raw_value=raw_value,
        severity=severity,
        image_label=image_label,
    )


def key_source(hive_path: str | Path, key_path: str) -> str:
    """Build a readable source string for reports."""
    return f"{Path(hive_path).name}\\{key_path}"


def value_name(value) -> str:
    """Return a stable display name for a registry value."""
    try:
        name = value.name()
    except Exception:
        return "(unknown)"
    return "(default)" if name == "" else name
