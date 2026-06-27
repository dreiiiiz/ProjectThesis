"""Shellbags parser."""

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
)

SHELLBAG_ROOTS = (
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
)


def parse_shellbags(
    hive_path: str | Path,
    image_label: ImageLabel,
    user: str | None = None,
) -> list[UnifiedArtifact]:
    """Extract Shellbag key traversal evidence from NTUSER.DAT or UsrClass.dat."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []

    for root_path in SHELLBAG_ROOTS:
        root_key = get_key(registry, root_path)
        _walk_shellbag_key(root_key, hive_path, root_path, image_label, user, artifacts)

    return artifacts


def _walk_shellbag_key(
    key,
    hive_path: str | Path,
    key_path: str,
    image_label: ImageLabel,
    user: str | None,
    artifacts: list[UnifiedArtifact],
) -> None:
    if key is None:
        return

    artifacts.append(
        artifact(
            timestamp=timestamp_from_key(key),
            artifact_type="SHELLBAG",
            user=user,
            event_description=f"Shellbag folder access key observed: {key.name()}",
            source=key_source(hive_path, key_path),
            raw_value=f"Subkey={key.name()}",
            severity="LOW",
            image_label=image_label,
        )
    )

    for subkey in iter_subkeys(key):
        _walk_shellbag_key(
            subkey,
            hive_path,
            rf"{key_path}\{subkey.name()}",
            image_label,
            user,
            artifacts,
        )
