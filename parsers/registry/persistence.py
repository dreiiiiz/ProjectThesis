"""Registry persistence parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    iter_values,
    key_source,
    open_hive,
    timestamp_from_key,
    value_name,
    value_to_text,
)

PERSISTENCE_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)


def parse_persistence(
    hive_path: str | Path,
    image_label: ImageLabel,
    user: str | None = None,
) -> list[UnifiedArtifact]:
    """Scan common registry persistence keys in SOFTWARE or NTUSER.DAT hives."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []

    for key_path in PERSISTENCE_PATHS:
        key = get_key(registry, key_path)
        for value in iter_values(key):
            artifacts.append(
                artifact(
                    timestamp=timestamp_from_key(key),
                    artifact_type="PERSISTENCE_KEY",
                    user=user,
                    event_description=f"Registry persistence value found: {value_name(value)}",
                    source=key_source(hive_path, key_path),
                    raw_value=f"{value_name(value)}={value_to_text(value.value())}",
                    severity="HIGH",
                    image_label=image_label,
                )
            )

    return artifacts
