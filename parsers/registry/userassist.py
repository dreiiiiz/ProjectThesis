"""UserAssist parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    iter_subkeys,
    iter_values,
    key_source,
    open_hive,
    rot13,
    timestamp_from_key,
    value_name,
    value_to_text,
)

USERASSIST_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def parse_userassist(
    hive_path: str | Path,
    image_label: ImageLabel,
    user: str | None = None,
) -> list[UnifiedArtifact]:
    """Extract ROT13-decoded UserAssist execution entries from NTUSER.DAT."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []
    base_key = get_key(registry, USERASSIST_PATH)

    for guid_key in iter_subkeys(base_key):
        count_key = get_key(registry, rf"{USERASSIST_PATH}\{guid_key.name()}\Count")
        for value in iter_values(count_key):
            decoded_name = rot13(value_name(value))
            artifacts.append(
                artifact(
                    timestamp=timestamp_from_key(count_key),
                    artifact_type="USERASSIST",
                    user=user,
                    event_description=f"GUI program execution evidence: {decoded_name}",
                    source=key_source(hive_path, rf"{USERASSIST_PATH}\{guid_key.name()}\Count"),
                    raw_value=f"{decoded_name}={value_to_text(value.value())}",
                    severity="MEDIUM",
                    image_label=image_label,
                )
            )

    return artifacts
