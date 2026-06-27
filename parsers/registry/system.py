"""SYSTEM hive parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    get_value,
    iter_subkeys,
    key_source,
    open_hive,
    timestamp_from_key,
)


def parse_system(hive_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract service, timezone, and network metadata from a SYSTEM hive."""
    registry = open_hive(hive_path)
    control_set = _current_control_set(registry)
    artifacts: list[UnifiedArtifact] = []
    artifacts.extend(_parse_timezone(registry, hive_path, control_set, image_label))
    artifacts.extend(_parse_services(registry, hive_path, control_set, image_label))
    artifacts.extend(_parse_network_interfaces(registry, hive_path, control_set, image_label))
    return artifacts


def _current_control_set(registry) -> str:
    select_key = get_key(registry, "Select")
    current = get_value(select_key, "Current") if select_key is not None else None
    if isinstance(current, int):
        return f"ControlSet{current:03d}"
    return "ControlSet001"


def _parse_timezone(registry, hive_path: str | Path, control_set: str, image_label: ImageLabel):
    key_path = rf"{control_set}\Control\TimeZoneInformation"
    key = get_key(registry, key_path)
    if key is None:
        return []
    tz_name = get_value(key, "TimeZoneKeyName") or get_value(key, "StandardName") or "Unknown"
    return [
        artifact(
            timestamp=timestamp_from_key(key),
            artifact_type="REGISTRY_SYSTEM",
            user=None,
            event_description=f"System timezone configured: {tz_name}",
            source=key_source(hive_path, key_path),
            raw_value=f"TimeZoneKeyName={tz_name}",
            severity="LOW",
            image_label=image_label,
        )
    ]


def _parse_services(registry, hive_path: str | Path, control_set: str, image_label: ImageLabel):
    rows: list[UnifiedArtifact] = []
    services_path = rf"{control_set}\Services"
    services_key = get_key(registry, services_path)
    for service_key in iter_subkeys(services_key):
        image_path = get_value(service_key, "ImagePath")
        display_name = get_value(service_key, "DisplayName") or service_key.name()
        start_type = get_value(service_key, "Start")
        if image_path is None and start_type is None:
            continue
        rows.append(
            artifact(
                timestamp=timestamp_from_key(service_key),
                artifact_type="REGISTRY_SYSTEM",
                user=None,
                event_description=f"Service configuration found: {display_name}",
                source=key_source(hive_path, rf"{services_path}\{service_key.name()}"),
                raw_value=f"ImagePath={image_path}, Start={start_type}",
                severity="MEDIUM" if image_path else "LOW",
                image_label=image_label,
            )
        )
    return rows


def _parse_network_interfaces(registry, hive_path: str | Path, control_set: str, image_label: ImageLabel):
    rows: list[UnifiedArtifact] = []
    interfaces_path = rf"{control_set}\Services\Tcpip\Parameters\Interfaces"
    interfaces_key = get_key(registry, interfaces_path)
    for iface_key in iter_subkeys(interfaces_key):
        ip_address = get_value(iface_key, "IPAddress") or get_value(iface_key, "DhcpIPAddress")
        name_server = get_value(iface_key, "NameServer") or get_value(iface_key, "DhcpNameServer")
        if not ip_address and not name_server:
            continue
        rows.append(
            artifact(
                timestamp=timestamp_from_key(iface_key),
                artifact_type="REGISTRY_SYSTEM",
                user=None,
                event_description=f"Network interface configuration found: {iface_key.name()}",
                source=key_source(hive_path, rf"{interfaces_path}\{iface_key.name()}"),
                raw_value=f"IPAddress={ip_address}, NameServer={name_server}",
                severity="LOW",
                image_label=image_label,
            )
        )
    return rows
