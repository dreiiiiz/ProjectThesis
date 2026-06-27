"""Security.evtx parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.evtx.common import data_map, event_id, first_present, iter_event_records, make_artifact


SECURITY_RULES = {
    "4624": ("Successful logon", "LOW"),
    "4625": ("Failed logon attempt", "MEDIUM"),
    "4688": ("Process created", "MEDIUM"),
    "4720": ("Local or domain account created", "HIGH"),
    "1102": ("Security event log cleared", "CRITICAL"),
}


def parse_security_log(evtx_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract key Security.evtx events."""
    artifacts: list[UnifiedArtifact] = []
    for root in iter_event_records(evtx_path):
        current_event_id = event_id(root)
        if current_event_id not in SECURITY_RULES:
            continue

        fields = data_map(root)
        base_description, severity = SECURITY_RULES[current_event_id]
        user = first_present(
            fields,
            ("TargetUserName", "SubjectUserName", "AccountName", "UserName"),
        )
        detail = _security_detail(current_event_id, fields)
        description = f"{base_description}: {detail}" if detail else base_description
        artifacts.append(
            make_artifact(
                root=root,
                evtx_path=evtx_path,
                artifact_type="EVTX_SECURITY",
                user=user,
                event_description=description,
                severity=severity,
                image_label=image_label,
            )
        )
    return artifacts


def _security_detail(current_event_id: str, fields: dict[str, str]) -> str:
    if current_event_id in {"4624", "4625"}:
        user = first_present(fields, ("TargetUserName", "AccountName", "UserName"))
        ip_address = first_present(fields, ("IpAddress", "WorkstationName", "SourceNetworkAddress"))
        logon_type = fields.get("LogonType")
        parts = [
            f"user={user}" if user else "",
            f"logon_type={logon_type}" if logon_type else "",
            f"source={ip_address}" if ip_address else "",
        ]
        return ", ".join(part for part in parts if part)
    if current_event_id == "4688":
        process = first_present(fields, ("NewProcessName", "ProcessName"))
        parent = fields.get("ParentProcessName")
        return ", ".join(part for part in (f"process={process}" if process else "", f"parent={parent}" if parent else "") if part)
    if current_event_id == "4720":
        return f"account={fields.get('TargetUserName', '')}".strip("=")
    if current_event_id == "1102":
        return "audit trail clearing event"
    return ""
