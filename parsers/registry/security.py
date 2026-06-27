"""SECURITY hive parser."""

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
    timestamp_from_key,
    value_name,
    value_to_text,
)


def parse_security(hive_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract audit policy and LSA secret metadata from a SECURITY hive."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []

    artifacts.extend(_parse_key_values(registry, hive_path, r"Policy\PolAdtEv", image_label))

    secrets_key = get_key(registry, r"Policy\Secrets")
    for secret_key in iter_subkeys(secrets_key):
        artifacts.append(
            artifact(
                timestamp=timestamp_from_key(secret_key),
                artifact_type="REGISTRY_SECURITY",
                user=None,
                event_description=f"LSA secret metadata present: {secret_key.name()}",
                source=key_source(hive_path, rf"Policy\Secrets\{secret_key.name()}"),
                raw_value="Secret value intentionally not exported",
                severity="MEDIUM",
                image_label=image_label,
            )
        )

    return artifacts


def _parse_key_values(registry, hive_path: str | Path, key_path: str, image_label: ImageLabel):
    key = get_key(registry, key_path)
    rows: list[UnifiedArtifact] = []
    for value in iter_values(key):
        rows.append(
            artifact(
                timestamp=timestamp_from_key(key),
                artifact_type="REGISTRY_SECURITY",
                user=None,
                event_description=f"Security policy value found: {value_name(value)}",
                source=key_source(hive_path, key_path),
                raw_value=f"{value_name(value)}={value_to_text(value.value())}",
                severity="LOW",
                image_label=image_label,
            )
        )
    return rows
