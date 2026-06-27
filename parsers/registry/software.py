"""SOFTWARE hive parser."""

from __future__ import annotations

from pathlib import Path

from normalizer import ImageLabel, UnifiedArtifact
from parsers.registry.common import (
    artifact,
    get_key,
    get_value,
    iter_subkeys,
    iter_values,
    key_source,
    open_hive,
    timestamp_from_key,
    value_name,
    value_to_text,
)

CURRENT_VERSION = r"Microsoft\Windows NT\CurrentVersion"
UNINSTALL_PATHS = (
    r"Microsoft\Windows\CurrentVersion\Uninstall",
    r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)
RUN_PATHS = (
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
)


def parse_software(hive_path: str | Path, image_label: ImageLabel) -> list[UnifiedArtifact]:
    """Extract OS, installed application, and machine Run key artifacts."""
    registry = open_hive(hive_path)
    artifacts: list[UnifiedArtifact] = []
    artifacts.extend(_parse_os_info(registry, hive_path, image_label))
    artifacts.extend(_parse_installed_apps(registry, hive_path, image_label))
    artifacts.extend(_parse_run_keys(registry, hive_path, image_label))
    return artifacts


def _parse_os_info(registry, hive_path: str | Path, image_label: ImageLabel):
    key = get_key(registry, CURRENT_VERSION)
    if key is None:
        return []
    product_name = get_value(key, "ProductName") or "Unknown Windows"
    build = get_value(key, "CurrentBuild") or get_value(key, "CurrentBuildNumber") or "Unknown"
    install_date = get_value(key, "InstallDate")
    raw = f"ProductName={product_name}, CurrentBuild={build}, InstallDate={install_date}"
    return [
        artifact(
            timestamp=timestamp_from_key(key),
            artifact_type="REGISTRY_SOFTWARE",
            user=None,
            event_description=f"Windows installation identified: {product_name} build {build}",
            source=key_source(hive_path, CURRENT_VERSION),
            raw_value=raw,
            severity="LOW",
            image_label=image_label,
        )
    ]


def _parse_installed_apps(registry, hive_path: str | Path, image_label: ImageLabel):
    rows: list[UnifiedArtifact] = []
    for base_path in UNINSTALL_PATHS:
        base_key = get_key(registry, base_path)
        for app_key in iter_subkeys(base_key):
            display_name = get_value(app_key, "DisplayName")
            if not display_name:
                continue
            version = get_value(app_key, "DisplayVersion") or ""
            publisher = get_value(app_key, "Publisher") or ""
            rows.append(
                artifact(
                    timestamp=timestamp_from_key(app_key),
                    artifact_type="REGISTRY_SOFTWARE",
                    user=None,
                    event_description=f"Installed application discovered: {display_name}",
                    source=key_source(hive_path, rf"{base_path}\{app_key.name()}"),
                    raw_value=f"DisplayName={display_name}, DisplayVersion={version}, Publisher={publisher}",
                    severity="LOW",
                    image_label=image_label,
                )
            )
    return rows


def _parse_run_keys(registry, hive_path: str | Path, image_label: ImageLabel):
    rows: list[UnifiedArtifact] = []
    for run_path in RUN_PATHS:
        key = get_key(registry, run_path)
        for value in iter_values(key):
            rows.append(
                artifact(
                    timestamp=timestamp_from_key(key),
                    artifact_type="PERSISTENCE_KEY",
                    user=None,
                    event_description=f"Machine persistence value in {run_path}: {value_name(value)}",
                    source=key_source(hive_path, run_path),
                    raw_value=f"{value_name(value)}={value_to_text(value.value())}",
                    severity="HIGH",
                    image_label=image_label,
                )
            )
    return rows
