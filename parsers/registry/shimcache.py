"""ShimCache parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    get_value,
    key_source,
    open_hive,
    timestamp_from_key,
    value_to_text,
)

APPCOMPAT_PATHS = (
    r"ControlSet001\Control\Session Manager\AppCompatCache",
    r"ControlSet002\Control\Session Manager\AppCompatCache",
)


def parse_shimcache(hive_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract AppCompatCache value metadata from a SYSTEM hive.

    Full ShimCache binary carving is intentionally deferred until sample hives
    are available, because layouts differ across Windows versions.
    """
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []

    for key_path in APPCOMPAT_PATHS:
        key = get_key(registry, key_path)
        value = get_value(key, "AppCompatCache") if key is not None else None
        if value is None:
            continue
        artifacts.append(
            artifact(
                timestamp=timestamp_from_key(key),
                artifact_type="SHIMCACHE",
                user=None,
                event_description="AppCompatCache value found in SYSTEM hive",
                source=key_source(hive_path, key_path),
                raw_value=f"AppCompatCache={value_to_text(value)[:2048]}",
                severity="MEDIUM",
                image_label=image_label,
            )
        )

    return artifacts
