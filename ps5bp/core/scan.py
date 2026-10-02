"""Game-folder scanner: everything `ps5bp analyze` reports, no modification."""
from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import dynamic, sdk
from .binary import Binary, EncryptedError, FormatError, sniff
from .nid import nid
from .paramjson import ParamJson

EXEC_EXTS = {".bin", ".elf", ".self", ".prx", ".sprx"}

NID_PRO_QUERY = "NH6xARDOVv8"
NID_TRINITY = nid("sceKernelIsTrinityMode")

# flag -> human description (used by reports/GUI)
FLAGS = {
    "pro-query": "queries Pro hardware (NH6xARDOVv8) — has a PS5 Pro code path",
    "trinity-query": "calls sceKernelIsTrinityMode — has a PS5 Pro code path",
    "pssr": "uses PSSR/MFSR upscaling (libScePsml)",
    "pssr2-model": "loads the PSSR 2 model KPN9_v070.psp from the system (absent on older FW)",
    "pssr2-app0": "loads a PSSR 2 model bundled at /app0/ (k9.psp-style fix present)",
    "audioout2": "uses libSceAudioOut2 (12-channel audio patches may apply)",
}


@dataclass
class BinaryInfo:
    path: str                       # relative to game root
    kind: str = ""                  # self | elf | encrypted | error
    role: str = ""                  # eboot | module | fakelib
    size: int = 0
    module: str = ""
    sdk_kind: str = ""
    sdk_ps5: int | None = None
    sdk_ps4: int | None = None
    needed: list[str] = field(default_factory=list)
    import_libs: dict[str, str] = field(default_factory=dict)     # lib name -> version
    export_libs: list[str] = field(default_factory=list)
    n_imports: int = 0
    n_exports: int = 0
    imports_by_lib: dict[str, list[str]] = field(default_factory=dict)
    imports_by_module: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)                # NIDs (own module)
    stubbed_by_module: dict[str, list[str]] = field(default_factory=dict)
    plt_patched: dict[str, dict[str, str]] = field(default_factory=dict)  # module -> {nid: stub body hex}
    sha256: str = ""
    flags: list[str] = field(default_factory=list)
    error: str = ""

    def sdk_str(self) -> str:
        return sdk.fw_str(self.sdk_ps5) if self.sdk_ps5 is not None else "-"


@dataclass
class GameScan:
    root: str
    title_id: str = ""
    title: str = ""
    content_version: str = ""
    param_sdk: int | None = None
    param_required_fw: int | None = None
    binaries: list[BinaryInfo] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)          # backport artefacts (k9.psp ...)
    flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def eboot(self) -> BinaryInfo | None:
        return next((b for b in self.binaries if b.role == "eboot"), None)

    @property
    def has_fakelib(self) -> bool:
        return any(b.role == "fakelib" for b in self.binaries)

    def max_sdk(self) -> int | None:
        v = [b.sdk_ps5 for b in self.binaries if b.sdk_ps5 is not None and b.role != "fakelib"]
        return max(v) if v else None

    def needs_downgrade(self, target: int, minor: int = 0) -> list[BinaryInfo]:
        ps5, _ = sdk.target_pair(target, minor)
        return [b for b in self.binaries if b.sdk_ps5 is not None and b.sdk_ps5 > ps5]

    def to_dict(self) -> dict:
        return asdict(self)


def _flags(b: Binary, d: dynamic.Dynamic | None) -> list[str]:
    out = []
    if d:
        imp = d.imported_nids()
        libs = {lib.name for lib in d.import_libs.values()}
        if NID_PRO_QUERY in imp:
            out.append("pro-query")
        if NID_TRINITY in imp:
            out.append("trinity-query")
        if any(n.startswith("libScePsml") for n in libs) or any(n.startswith("libScePsml") for n in d.needed):
            out.append("pssr")
        if "libSceAudioOut2" in libs:
            out.append("audioout2")
    if b.find(b"KPN9_v070.psp"):
        out.append("pssr2-model")
    if b.find(b"/app0/k9.psp"):
        out.append("pssr2-app0")
    return out


def scan_binary(path: Path, root: Path, role: str) -> BinaryInfo:
    info = BinaryInfo(path=str(path.relative_to(root)), role=role, size=path.stat().st_size)
    try:
        b = Binary.load(path)
    except EncryptedError as e:
        info.kind, info.error = "encrypted", str(e)
        return info
    except FormatError as e:
        info.kind, info.error = "error", str(e)
        return info
    info.kind = b.kind
    try:
        p = sdk.find(b)
        if p:
            info.sdk_kind, info.sdk_ps5, info.sdk_ps4 = p.kind, p.ps5, p.ps4
    except ValueError as e:
        info.error = str(e)
    d = dynamic.parse(b)
    if d:
        info.module = d.module.name if d.module else ""
        info.needed = d.needed
        info.import_libs = {lib.name: lib.ver_str for lib in d.import_libs.values()}
        info.export_libs = [lib.name for lib in d.export_libs.values()]
        info.n_imports = len(d.imports())
        info.n_exports = len(d.exports())
        info.imports_by_lib = {k: sorted(v) for k, v in d.imports_by_lib().items()}
        info.imports_by_module = {k: sorted(v) for k, v in d.imports_by_module().items()}
        info.exports = sorted(d.exported_nids())
        info.stubbed_by_module = {k: sorted(v) for k, v in d.stubbed_by_module().items()}
        info.plt_patched = plt_patched(b, d, 0x400000 if role == "eboot" else 0)
    info.sha256 = hashlib.sha256(b.data).hexdigest()
    info.flags = _flags(b, d)
    return info


LOADING_LAYERS = ("libSceAmpr", "libScePlayGo")


def is_loading_layer(module: str) -> bool:
    """Ampr / PlayGo emulation shipped with dumps and kits: needed for newer games to load
    at all, independent of firmware — never a FW fakelib, never FW evidence."""
    return module.startswith(LOADING_LAYERS)


def plt_patched(b: Binary, d, base: int) -> dict[str, dict[str, str]]:
    """Imports whose PLT entry a backporter overwrote with a stub: module -> {nid: body hex}."""
    from .asm import canonical_plt, plt_entries, stub_body
    mod_of = {s.name: d.module_name(s) for s in d.imports()}
    out: dict[str, dict[str, str]] = {}
    try:
        entries = plt_entries(b, d, base)
    except Exception:                                    # noqa: BLE001 — odd PLT: no stub info
        return out
    for name, va, e in entries:
        if canonical_plt(e):
            continue
        body = stub_body(e, va)
        if body is None or name not in mod_of:
            continue
        out.setdefault(mod_of[name], {})[name.split("#")[0]] = body.hex()
    return out


def iter_binaries(root: Path):
    for dp, dn, fn in os.walk(root, followlinks=True):
        dn.sort()
        for f in sorted(fn):
            p = Path(dp) / f
            if p.suffix.lower() in EXEC_EXTS and sniff(p) in ("self", "elf"):
                yield p


def scan_game(root: Path | str, progress: Callable[[int, int, str], None] | None = None) -> GameScan:
    root = Path(root)
    gs = GameScan(root=str(root))
    pj = root / "sce_sys" / "param.json"
    if pj.is_file():
        try:
            p = ParamJson.load(pj)
            gs.title_id, gs.title, gs.content_version = p.title_id, p.title, p.content_version
            gs.param_sdk, gs.param_required_fw = p.sdk_version, p.required_fw
        except (ValueError, OSError) as e:
            gs.warnings.append(f"param.json unreadable: {e}")
    else:
        gs.warnings.append("no sce_sys/param.json — is this a game root?")
    files = list(iter_binaries(root))
    for i, path in enumerate(files):
        rel = path.relative_to(root)
        role = "fakelib" if rel.parts[0] == "fakelib" else ("eboot" if str(rel) == "eboot.bin" else "module")
        if progress:
            progress(i, len(files), str(rel))
        gs.binaries.append(scan_binary(path, root, role))
    if not gs.eboot:
        gs.warnings.append("no eboot.bin at the folder root")
    for name in ("k9.psp",):
        if (root / name).exists():
            gs.extra_files.append(name)
    seen = []
    for b in gs.binaries:
        if b.role == "fakelib":
            continue
        for f in b.flags:
            if f not in seen:
                seen.append(f)
        if b.error:
            gs.warnings.append(f"{b.path}: {b.error}")
    gs.flags = seen
    if any(b.role == "fakelib" and "pssr2-app0" in b.flags for b in gs.binaries):
        gs.flags.append("pssr2-app0")
    return gs
