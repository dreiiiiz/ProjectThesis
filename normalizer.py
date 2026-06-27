"""Unified artifact schema and normalization helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ImageLabel = Literal["MALICIOUS", "NORMAL"]


@dataclass(frozen=True)
class UnifiedArtifact:
    """Single row in the unified CSV/MD artifact output."""

    timestamp: str
    artifact_type: str
    user: str | None
    event_description: str
    source: str
    raw_value: str
    severity: Severity
    image_label: ImageLabel

    def to_dict(self) -> dict[str, str | None]:
        """Return a dict that matches the unified output schema."""
        return asdict(self)


UNIFIED_SCHEMA_COLUMNS = (
    "timestamp",
    "artifact_type",
    "user",
    "event_description",
    "source",
    "raw_value",
    "severity",
    "image_label",
)


def artifact_template() -> dict[str, str | None]:
    """Return an empty artifact dict with the required schema keys."""
    return {column: None for column in UNIFIED_SCHEMA_COLUMNS}
