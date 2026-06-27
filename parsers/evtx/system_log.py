"""System.evtx parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.evtx.common import data_map, event_id, first_present, iter_event_records, make_artifact


SYSTEM_RULES = {
    "7045": ("New service installed", "HIGH"),
    "6005": ("Event log service started / system boot", "LOW"),
    "6006": ("Event log service stopped / system shutdown", "LOW"),
}


def parse_system_log(evtx_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract key System.evtx events."""
    artifacts: list[UnifiedArtifact] = []
    for root in iter_event_records(evtx_path):
        current_event_id = event_id(root)
        if current_event_id not in SYSTEM_RULES:
            continue

        fields = data_map(root)
        base_description, severity = SYSTEM_RULES[current_event_id]
        detail = _system_detail(current_event_id, fields)
        artifacts.append(
            make_artifact(
                root=root,
                evtx_path=evtx_path,
                artifact_type="EVTX_SYSTEM",
                user=None,
                event_description=f"{base_description}: {detail}" if detail else base_description,
                severity=severity,
                image_label=image_label,
            )
        )
    return artifacts


def _system_detail(current_event_id: str, fields: dict[str, str]) -> str:
    if current_event_id == "7045":
        service = first_present(fields, ("ServiceName", "param1"))
        image_path = first_present(fields, ("ImagePath", "param2"))
        return ", ".join(
            part
            for part in (
                f"service={service}" if service else "",
                f"image_path={image_path}" if image_path else "",
            )
            if part
        )
    return ""
