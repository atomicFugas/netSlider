"""Declarative interpretation schema (YAML/JSON)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from netslider.core.investigate.framing import parse_magic_string


class SchemaError(Exception):
    """Raised when an interpretation document is invalid."""


@dataclass
class FramingHeader:
    magic: bytes | None = None
    magic_offset: int = 0
    len_offset: int = 4
    len_size: int = 2
    endian: str = "be"  # be | le
    len_includes_header: bool = False


@dataclass
class FramingSpec:
    type: str = "length_prefixed"
    header: FramingHeader = field(default_factory=FramingHeader)


@dataclass
class WhenClause:
    field: str
    eq: int | str | None = None
    ne: int | str | None = None


@dataclass
class FieldSpec:
    name: str
    offset: int
    type: str
    hypothesis: str | None = None
    status: str | None = None  # observation | rule | hypothesis | unverified


@dataclass
class MessageRule:
    when: WhenClause | None
    fields: list[FieldSpec]
    name: str | None = None


@dataclass
class ScopeSpec:
    protocol: str = ""
    versions: list[str] = field(default_factory=list)


@dataclass
class InterpretationDoc:
    id: str
    framing: FramingSpec
    messages: list[MessageRule]
    scope: ScopeSpec = field(default_factory=ScopeSpec)
    unknown_policy: str = "leave_unparsed"
    description: str = ""
    source_path: Path | None = None
    raw_text: str = ""

    @property
    def content_for_hash(self) -> str:
        """Stable text used for stale-result hashing (prefer raw file)."""
        if self.raw_text:
            return self.raw_text
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scope": {
                "protocol": self.scope.protocol,
                "versions": list(self.scope.versions),
            },
            "framing": {
                "type": self.framing.type,
                "header": {
                    "magic": (
                        self.framing.header.magic.decode("latin-1")
                        if self.framing.header.magic
                        else None
                    ),
                    "magic_offset": self.framing.header.magic_offset,
                    "len_offset": self.framing.header.len_offset,
                    "len_size": self.framing.header.len_size,
                    "endian": self.framing.header.endian,
                    "len_includes_header": self.framing.header.len_includes_header,
                },
            },
            "messages": [
                {
                    "name": m.name,
                    "when": (
                        {"field": m.when.field, "eq": m.when.eq, "ne": m.when.ne}
                        if m.when
                        else None
                    ),
                    "fields": [
                        {
                            "name": f.name,
                            "offset": f.offset,
                            "type": f.type,
                            "hypothesis": f.hypothesis,
                            "status": f.status,
                        }
                        for f in m.fields
                    ],
                }
                for m in self.messages
            ],
            "unknown_policy": self.unknown_policy,
            "description": self.description,
        }


def _parse_intish(value: Any) -> int | str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    s = str(value).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 10)
    except ValueError:
        return s


def _parse_header(data: dict[str, Any]) -> FramingHeader:
    magic_raw = data.get("magic")
    magic: bytes | None = None
    if magic_raw is not None and magic_raw != "":
        if isinstance(magic_raw, bytes):
            magic = magic_raw
        else:
            magic = parse_magic_string(str(magic_raw))
    endian = str(data.get("endian", "be")).lower()
    if endian not in ("be", "le"):
        raise SchemaError(f"Invalid endian: {endian}")
    len_size = int(data.get("len_size", 2))
    if len_size not in (1, 2, 4):
        raise SchemaError(f"Invalid len_size: {len_size}")
    return FramingHeader(
        magic=magic,
        magic_offset=int(data.get("magic_offset", 0)),
        len_offset=int(data.get("len_offset", 4)),
        len_size=len_size,
        endian=endian,
        len_includes_header=bool(data.get("len_includes_header", False)),
    )


def _parse_when(data: Any) -> WhenClause | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise SchemaError("when must be a mapping")
    field = str(data.get("field", "")).strip()
    if not field:
        raise SchemaError("when.field is required")
    return WhenClause(
        field=field,
        eq=_parse_intish(data.get("eq")),
        ne=_parse_intish(data.get("ne")),
    )


def _parse_field(data: dict[str, Any]) -> FieldSpec:
    name = str(data.get("name", "")).strip()
    if not name:
        raise SchemaError("field.name is required")
    type_name = str(data.get("type", "")).strip()
    if not type_name:
        raise SchemaError(f"field.type is required for {name}")
    return FieldSpec(
        name=name,
        offset=int(data.get("offset", 0)),
        type=type_name,
        hypothesis=(str(data["hypothesis"]) if data.get("hypothesis") is not None else None),
        status=(str(data["status"]) if data.get("status") is not None else None),
    )


def interpretation_from_dict(
    data: dict[str, Any],
    *,
    source_path: Path | None = None,
    raw_text: str = "",
) -> InterpretationDoc:
    if not isinstance(data, dict):
        raise SchemaError("Interpretation root must be a mapping")
    interp_id = str(data.get("id", "")).strip()
    if not interp_id:
        raise SchemaError("id is required")

    framing_data = data.get("framing") or {}
    if not isinstance(framing_data, dict):
        raise SchemaError("framing must be a mapping")
    header_data = framing_data.get("header") or {}
    if not isinstance(header_data, dict):
        raise SchemaError("framing.header must be a mapping")
    framing = FramingSpec(
        type=str(framing_data.get("type", "length_prefixed")),
        header=_parse_header(header_data),
    )
    if framing.type != "length_prefixed":
        raise SchemaError(f"Unsupported framing.type: {framing.type}")

    messages_raw = data.get("messages") or []
    if not isinstance(messages_raw, list):
        raise SchemaError("messages must be a list")
    messages: list[MessageRule] = []
    for item in messages_raw:
        if not isinstance(item, dict):
            raise SchemaError("each message rule must be a mapping")
        fields_raw = item.get("fields") or []
        if not isinstance(fields_raw, list):
            raise SchemaError("message.fields must be a list")
        messages.append(
            MessageRule(
                when=_parse_when(item.get("when")),
                fields=[_parse_field(f) for f in fields_raw if isinstance(f, dict)],
                name=(str(item["name"]) if item.get("name") is not None else None),
            )
        )

    scope_raw = data.get("scope") or {}
    if not isinstance(scope_raw, dict):
        raise SchemaError("scope must be a mapping")
    versions = scope_raw.get("versions") or []
    if not isinstance(versions, list):
        raise SchemaError("scope.versions must be a list")
    scope = ScopeSpec(
        protocol=str(scope_raw.get("protocol", "")),
        versions=[str(v) for v in versions],
    )

    return InterpretationDoc(
        id=interp_id,
        framing=framing,
        messages=messages,
        scope=scope,
        unknown_policy=str(data.get("unknown_policy", "leave_unparsed")),
        description=str(data.get("description", "")),
        source_path=source_path,
        raw_text=raw_text,
    )


def load_interpretation(path: Path) -> InterpretationDoc:
    path = path.resolve()
    if not path.is_file():
        raise SchemaError(f"Interpretation not found: {path}")
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        elif suffix == ".json":
            data = json.loads(text)
        else:
            # Try YAML first, then JSON
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                data = json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise SchemaError(f"Failed to parse {path.name}: {exc}") from exc
    if data is None:
        raise SchemaError(f"Empty interpretation: {path}")
    return interpretation_from_dict(data, source_path=path, raw_text=text)


def parse_interpretation_text(text: str, *, source_path: Path | None = None) -> InterpretationDoc:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SchemaError(f"Invalid YAML: {exc}") from exc
    if data is None:
        raise SchemaError("Empty interpretation text")
    return interpretation_from_dict(data, source_path=source_path, raw_text=text)


DEMO_DEVICE_V1_YAML = """\
id: device_v1
description: Demo MD01 length-prefixed device protocol
scope:
  protocol: demo-device
  versions: ["1"]
framing:
  type: length_prefixed
  header:
    magic: MD01
    magic_offset: 0
    len_offset: 4
    len_size: 2
    endian: be
    len_includes_header: false
messages:
  - name: read_param
    when: { field: opcode, eq: 0x01 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: param_id, offset: 1, type: u16le, hypothesis: "parameter id" }
  - name: set_param
    when: { field: opcode, eq: 0x02 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: param_id, offset: 1, type: u16le }
      - { name: value, offset: 3, type: u16le, hypothesis: "setpoint" }
  - name: param_value
    when: { field: opcode, eq: 0x03 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: param_id, offset: 1, type: u16le }
      - { name: value, offset: 3, type: u16le, status: observation }
  - name: read_measurement
    when: { field: opcode, eq: 0x10 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: sensor_id, offset: 1, type: u8 }
  - name: measurement_data
    when: { field: opcode, eq: 0x11 }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: sensor_id, offset: 1, type: u8 }
      - { name: n_bytes, offset: 2, type: u16le }
      - { name: data, offset: 4, type: bytes, hypothesis: "measurement payload" }
  - name: error
    when: { field: opcode, eq: 0x7F }
    fields:
      - { name: opcode, offset: 0, type: u8 }
      - { name: code, offset: 1, type: u8 }
unknown_policy: leave_unparsed
"""
