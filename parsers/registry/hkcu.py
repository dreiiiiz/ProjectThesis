"""HKCU NTUSER.DAT parser."""

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

RUN_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
TYPED_PATHS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"


def parse_hkcu(
    hive_path: str | Path,
    image_label: ImageLabel,
    user: str | None = None,
) -> list[UnifiedArtifact]:
    """Extract per-user Run keys and typed Explorer paths from NTUSER.DAT."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []
    artifacts.extend(_parse_user_run_keys(registry, hive_path, image_label, user))
    artifacts.extend(_parse_typed_paths(registry, hive_path, image_label, user))
    return artifacts


def _parse_user_run_keys(registry, hive_path: str | Path, image_label: ImageLabel, user: str | None):
    rows: list[UnifiedArtifact] = []
    for run_path in RUN_PATHS:
        key = get_key(registry, run_path)
        for value in iter_values(key):
            rows.append(
                artifact(
                    timestamp=timestamp_from_key(key),
                    artifact_type="PERSISTENCE_KEY",
                    user=user,
                    event_description=f"User persistence value in {run_path}: {value_name(value)}",
                    source=key_source(hive_path, run_path),
                    raw_value=f"{value_name(value)}={value_to_text(value.value())}",
                    severity="HIGH",
                    image_label=image_label,
                )
            )
    return rows


def _parse_typed_paths(registry, hive_path: str | Path, image_label: ImageLabel, user: str | None):
    key = get_key(registry, TYPED_PATHS)
    rows: list[UnifiedArtifact] = []
    for value in iter_values(key):
        rows.append(
            artifact(
                timestamp=timestamp_from_key(key),
                artifact_type="REGISTRY_HKCU",
                user=user,
                event_description=f"Explorer typed path recorded: {value_to_text(value.value())}",
                source=key_source(hive_path, TYPED_PATHS),
                raw_value=f"{value_name(value)}={value_to_text(value.value())}",
                severity="LOW",
                image_label=image_label,
            )
        )
    return rows
