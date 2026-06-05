"""Git object handling: loose object parsing & validation.

We use dulwich for the heavy lifting but add:
- SHA-1 verification (some servers serve corrupted/cached objects)
- Tolerant parsing that yields referenced SHAs even when a sub-object fails
"""
from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from dulwich.objects import ShaFile  # type: ignore[import-not-found]

SHA1_HEX = re.compile(rb"\b[0-9a-f]{40}\b")


@dataclass
class ParsedObject:
    sha: str
    type: str  # blob, tree, commit, tag
    size: int
    content: bytes
    referenced_shas: list[str]


def sha_path(sha: str) -> str:
    """Relative .git path for a loose object."""
    return f"objects/{sha[:2]}/{sha[2:]}"


def parse_loose(data: bytes, expected_sha: str | None = None) -> ParsedObject | None:
    """Decompress + validate a loose object."""
    try:
        raw = zlib.decompress(data)
    except zlib.error:
        return None

    header, _, content = raw.partition(b"\0")
    if b" " not in header:
        return None
    try:
        type_name_b, size_b = header.split(b" ", 1)
        size = int(size_b)
    except ValueError:
        return None

    type_name = type_name_b.decode("ascii", "replace")
    if type_name not in {"blob", "tree", "commit", "tag"}:
        return None
    if size != len(content):
        # Don't reject: many servers ship correct content with truncated size
        pass

    sha = hashlib.sha1(header + b"\0" + content).hexdigest()
    if expected_sha and sha != expected_sha.lower():
        return None

    referenced = extract_referenced_shas(type_name, content)
    return ParsedObject(sha=sha, type=type_name, size=len(content),
                        content=content, referenced_shas=referenced)


def extract_referenced_shas(type_name: str, content: bytes) -> list[str]:
    """Return shas referenced by the given object."""
    refs: list[str] = []
    if type_name == "tree":
        # Format: <mode> <name>\0<20 raw bytes>
        i = 0
        while i < len(content):
            sp = content.find(b" ", i)
            if sp == -1:
                break
            nul = content.find(b"\0", sp)
            if nul == -1 or nul + 20 > len(content):
                break
            sha = content[nul + 1 : nul + 21].hex()
            refs.append(sha)
            i = nul + 21
    elif type_name in ("commit", "tag"):
        # First lines (text) reference shas; body may also.
        for m in SHA1_HEX.finditer(content):
            refs.append(m.group(0).decode("ascii"))
    return refs


def dump_object(sha: str, parsed: ParsedObject, root: Path) -> Path:
    """Persist a *parsed* loose object as a real .git/objects entry."""
    obj_path = root / "objects" / sha[:2] / sha[2:]
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    if obj_path.exists():
        return obj_path
    header = f"{parsed.type} {parsed.size}".encode() + b"\0"
    obj_path.write_bytes(zlib.compress(header + parsed.content))
    return obj_path


def load_with_dulwich(data: bytes) -> ShaFile | None:
    """Convenience – let dulwich parse the loose blob."""
    try:
        return ShaFile.from_file(_ByteStream(data))  # type: ignore[arg-type]
    except Exception:
        return None


class _ByteStream:  # minimal file-like wrapper
    def __init__(self, data: bytes) -> None:
        from io import BytesIO

        self._b = BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._b.read(n)

    def close(self) -> None:
        self._b.close()


def iter_referenced(parsed_objects: Iterable[ParsedObject]) -> Iterator[str]:
    for obj in parsed_objects:
        yield from obj.referenced_shas
