"""sce_sys/param.json reader. Version fields are hex strings of 64-bit values,
e.g. "requiredSystemSoftwareVersion": "0x0400000000000000" (major.minor in the top bytes)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def _hex(v) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v, 16)
        except ValueError:
            return None
    return None


def fw64_str(v: int | None) -> str:
    if not v:
        return "?"
    return f"{(v >> 56) & 0xFF:x}.{(v >> 48) & 0xFF:02x}"


@dataclass
class ParamJson:
    path: Path
    raw: dict = field(repr=False)
    title_id: str = ""
    title: str = ""
    content_id: str = ""
    content_version: str = ""
    sdk_version: int | None = None
    required_fw: int | None = None

    @classmethod
    def load(cls, path: Path) -> "ParamJson":
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        loc = raw.get("localizedParameters", {}) or {}
        lang = loc.get("defaultLanguage", "en-US")
        title = (loc.get(lang) or loc.get("en-US") or {}).get("titleName", "") if isinstance(loc, dict) else ""
        return cls(
            path=Path(path), raw=raw,
            title_id=raw.get("titleId", ""), title=title,
            content_id=raw.get("contentId", ""),
            content_version=raw.get("contentVersion", "") or raw.get("masterVersion", ""),
            sdk_version=_hex(raw.get("sdkVersion")),
            required_fw=_hex(raw.get("requiredSystemSoftwareVersion")),
        )
