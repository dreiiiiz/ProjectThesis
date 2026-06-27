"""SAM hive parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    iter_subkeys,
    key_source,
    open_hive,
    timestamp_from_key,
    value_to_text,
)

USERS_KEY = r"SAM\Domains\Account\Users"
NAMES_KEY = USERS_KEY + r"\Names"


def parse_sam(hive_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract local account metadata from a SAM hive."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []

    names_key = get_key(registry, NAMES_KEY)
    for name_key in iter_subkeys(names_key):
        username = name_key.name()
        rid = _rid_from_name_key(name_key)
        severity = "HIGH" if rid is not None and rid >= 1000 else "LOW"
        artifacts.append(
            artifact(
                timestamp=timestamp_from_key(name_key),
                artifact_type="REGISTRY_SAM",
                user=username,
                event_description=f"Local SAM account discovered: {username}",
                source=key_source(hive_path, f"{NAMES_KEY}\\{username}"),
                raw_value=f"RID={rid if rid is not None else 'UNKNOWN'}",
                severity=severity,
                image_label=image_label,
            )
        )

    users_key = get_key(registry, USERS_KEY)
    for user_key in iter_subkeys(users_key):
        if user_key.name() == "Names":
            continue
        artifacts.append(
            artifact(
                timestamp=timestamp_from_key(user_key),
                artifact_type="REGISTRY_SAM",
                user=None,
                event_description=f"SAM user record present for RID key {user_key.name()}",
                source=key_source(hive_path, f"{USERS_KEY}\\{user_key.name()}"),
                raw_value=_summarize_values(user_key),
                severity="LOW",
                image_label=image_label,
            )
        )

    return artifacts


def _rid_from_name_key(name_key) -> int | None:
    try:
        default_value = name_key.value("")
        return default_value.value_type()
    except Exception:
        return None


def _summarize_values(key) -> str:
    parts = []
    for value in key.values():
        parts.append(f"{value.name() or '(default)'}={value_to_text(value.value())[:120]}")
    return ", ".join(parts)
