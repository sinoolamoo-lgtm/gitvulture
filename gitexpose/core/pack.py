"""Pack file & pack-index discovery + parsing using dulwich."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin

from dulwich.pack import Pack  # type: ignore[import-not-found]

from ..http_client import HttpClient
from ..logger import get_logger

PACK_NAME_RE = re.compile(rb"pack-([0-9a-f]{40})\.(pack|idx)")
HREF_PACK_RE = re.compile(rb'href="(pack-[0-9a-f]{40}\.(?:pack|idx))"')


async def discover_pack_names(client: HttpClient, git_root: str) -> set[str]:
    """Return set of sha names without extension, e.g. {'pack-abc...'}."""
    log = get_logger()
    names: set[str] = set()

    # 1) objects/info/packs (most reliable)
    r = await client.get(urljoin(git_root, "objects/info/packs"))
    if r.ok:
        for line in r.body.splitlines():
            line = line.strip()
            if line.startswith(b"P ") and line.endswith(b".pack"):
                names.add(line[2:-5].decode())
        log.debug(f"objects/info/packs listed {len(names)} packs")

    # 2) Try directory listing of objects/pack/
    r = await client.get(urljoin(git_root, "objects/pack/"))
    if r.ok:
        for m in HREF_PACK_RE.finditer(r.body):
            fname = m.group(1).decode()
            names.add(fname.rsplit(".", 1)[0])
        for m in PACK_NAME_RE.finditer(r.body):
            names.add("pack-" + m.group(1).decode())
        log.debug(f"directory listing yielded {len(names)} pack names")

    return names


async def download_pack(
    client: HttpClient, git_root: str, name: str, dest_root: Path
) -> tuple[Path | None, Path | None]:
    """Download one pack (.pack + .idx) into dest_root/objects/pack/."""
    log = get_logger()
    out_dir = dest_root / "objects" / "pack"
    out_dir.mkdir(parents=True, exist_ok=True)
    pack_path = out_dir / f"{name}.pack"
    idx_path = out_dir / f"{name}.idx"

    pack_url = urljoin(git_root, f"objects/pack/{name}.pack")
    idx_url = urljoin(git_root, f"objects/pack/{name}.idx")

    idx_resp = await client.get(idx_url)
    if not idx_resp.ok:
        log.warning(f"missing pack index for {name}")
        return None, None
    idx_path.write_bytes(idx_resp.body)
    log.success(f"saved {idx_path.name} ({len(idx_resp.body)}B)")

    pack_resp = await client.get(pack_url)
    if not pack_resp.ok:
        log.warning(f"missing pack data for {name}")
        return None, idx_path
    pack_path.write_bytes(pack_resp.body)
    log.success(f"saved {pack_path.name} ({len(pack_resp.body)}B)")
    return pack_path, idx_path


def explode_pack(pack_path: Path, dest_root: Path) -> int:
    """Explode pack into loose objects under dest_root/objects/aa/bb..."""
    log = get_logger()
    count = 0
    basename = str(pack_path).removesuffix(".pack")
    # dulwich Pack API differs across versions; try keyword first, fall back
    try:
        from dulwich.object_format import SHA1  # type: ignore[import-not-found]
        pack = Pack(basename, object_format=SHA1)
    except Exception:
        try:
            pack = Pack(basename)
        except Exception as e:
            log.warning(f"could not open pack {basename}: {e}")
            return 0
    try:
        import zlib

        for obj in pack.iterobjects():
            data = obj.as_raw_string()
            type_name = (
                obj.type_name.decode()
                if isinstance(obj.type_name, bytes)
                else obj.type_name
            )
            header = f"{type_name} {len(data)}".encode() + b"\0"
            sha_hex = obj.id.decode() if isinstance(obj.id, bytes) else obj.id
            obj_path = dest_root / "objects" / sha_hex[:2] / sha_hex[2:]
            obj_path.parent.mkdir(parents=True, exist_ok=True)
            if not obj_path.exists():
                obj_path.write_bytes(zlib.compress(header + data))
            count += 1
    finally:
        try:
            pack.close()
        except Exception:
            pass
    log.success(f"exploded {pack_path.name}: {count} loose objects")
    return count
