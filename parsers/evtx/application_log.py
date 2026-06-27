"""Application.evtx parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.evtx.common import data_map, event_id, first_present, iter_event_records, make_artifact, provider


APPLICATION_RULES = {
    "1000": ("Application crash", "MEDIUM"),
}


def parse_application_log(evtx_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract key Application.evtx events."""
    artifacts: list[UnifiedArtifact] = []
    for root in iter_event_records(evtx_path):
        current_event_id = event_id(root)
        if current_event_id not in APPLICATION_RULES:
            continue

        fields = data_map(root)
        base_description, severity = APPLICATION_RULES[current_event_id]
        app_name = first_present(fields, ("AppName", "ApplicationName", "param1"))
        description = base_description
        if app_name:
            description = f"{base_description}: {app_name}"
        elif provider(root) != "UNKNOWN":
            description = f"{base_description}: provider={provider(root)}"

        artifacts.append(
            make_artifact(
                root=root,
                evtx_path=evtx_path,
                artifact_type="EVTX_APPLICATION",
                user=None,
                event_description=description,
                severity=severity,
                image_label=image_label,
            )
        )
    return artifacts
