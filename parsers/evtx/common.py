"""Shared helpers for Windows EVTX parsers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from normalizer import ImageLabel, Severity, UnifiedArtifact

try:
    from Evtx.Evtx import Evtx
except ModuleNotFoundError:  # pragma: no cover - exercised only without dependency.
    Evtx = None


EVTX_NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
UNKNOWN_TIMESTAMP = "1970-01-01T00:00:00Z"


def iter_event_records(evtx_path: str | Path):
    """Yield parsed XML roots from an EVTX file."""
    if Evtx is None:
        raise RuntimeError(
            "Missing dependency: install python-evtx with "
            "`pip install python-evtx` before parsing EVTX logs."
        )

    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                try:
                    yield ElementTree.fromstring(record.xml())
                except ElementTree.ParseError:
                    continue
    except PermissionError as exc:
        raise RuntimeError(
            f"Permission denied while reading EVTX log: {evtx_path}. "
            "Run the terminal as Administrator or copy the log to a writable "
            "local folder first, then parse the copied file."
        ) from exc


def event_id(root: ElementTree.Element) -> str:
    """Return the Windows Event ID as text."""
    node = root.find("./e:System/e:EventID", EVTX_NAMESPACE)
    return (node.text or "UNKNOWN") if node is not None else "UNKNOWN"


def timestamp(root: ElementTree.Element) -> str:
    """Return the event SystemTime as normalized ISO 8601 UTC."""
    node = root.find("./e:System/e:TimeCreated", EVTX_NAMESPACE)
    if node is None:
        return UNKNOWN_TIMESTAMP
    value = node.attrib.get("SystemTime")
    if not value:
        return UNKNOWN_TIMESTAMP
    return normalize_timestamp(value)


def provider(root: ElementTree.Element) -> str:
    """Return the event provider name."""
    node = root.find("./e:System/e:Provider", EVTX_NAMESPACE)
    if node is None:
        return "UNKNOWN"
    return node.attrib.get("Name", "UNKNOWN")


def computer(root: ElementTree.Element) -> str:
    """Return the source computer name."""
    node = root.find("./e:System/e:Computer", EVTX_NAMESPACE)
    return (node.text or "") if node is not None else ""


def data_map(root: ElementTree.Element) -> dict[str, str]:
    """Return named EventData/UserData fields where available."""
    data: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", EVTX_NAMESPACE):
        name = node.attrib.get("Name")
        text = node.text or ""
        if name:
            data[name] = text
    for node in root.findall(".//e:UserData//*", EVTX_NAMESPACE):
        tag_name = node.tag.rsplit("}", 1)[-1]
        text = node.text or ""
        if text.strip():
            data[tag_name] = text
    return data


def raw_summary(root: ElementTree.Element) -> str:
    """Create compact raw data text for a unified artifact."""
    fields = data_map(root)
    pairs = [f"EventID={event_id(root)}", f"Provider={provider(root)}"]
    pairs.extend(f"{key}={value}" for key, value in fields.items() if value != "")
    return ", ".join(pairs)[:4096]


def normalize_timestamp(value: str) -> str:
    """Normalize common EVTX timestamp forms to ISO 8601 UTC."""
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def make_artifact(
    *,
    root: ElementTree.Element,
    evtx_path: str | Path,
    artifact_type: str,
    user: str | None,
    event_description: str,
    severity: Severity,
    image_label: ImageLabel,
) -> UnifiedArtifact:
    """Create a unified artifact from an EVTX XML root."""
    return UnifiedArtifact(
        timestamp=timestamp(root),
        artifact_type=artifact_type,
        user=user,
        event_description=event_description,
        source=f"{Path(evtx_path).name}:{event_id(root)}",
        raw_value=raw_summary(root),
        severity=severity,
        image_label=image_label,
    )


def first_present(fields: dict[str, str], names: tuple[str, ...]) -> str | None:
    """Return the first non-empty field value from candidate names."""
    for name in names:
        value = fields.get(name)
        if value:
            return value
    return None
