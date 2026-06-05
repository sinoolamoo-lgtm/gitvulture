"""Parse .git/index (DIRC format) to extract file paths and blob SHAs.

The index file is a binary cache of the working tree. Even when objects/*
is blocked by the target, the index alone is enormously valuable: it gives
us the full repo file listing + per-file blob SHA + mode + timestamps.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class IndexEntry:
    ctime: int
    mtime: int
    mode: int
    sha1: str
    flags: int
    path: str


def parse_index(data: bytes) -> list[IndexEntry]:
    """Parse a git DIRC index v2/v3/v4. Returns the list of entries."""
    if len(data) < 12 or data[:4] != b"DIRC":
        return []
    version = struct.unpack(">I", data[4:8])[0]
    n = struct.unpack(">I", data[8:12])[0]
    offset = 12
    entries: list[IndexEntry] = []
    prev_path = b""
    for _ in range(n):
        if offset + 62 > len(data):
            break
        # 32-bit big-endian fields:
        # ctime sec, ctime nsec, mtime sec, mtime nsec, dev, ino, mode, uid, gid, size
        (ctime_s, _ctime_n, mtime_s, _mtime_n, _dev, _ino, mode, _uid, _gid, _size) = struct.unpack(
            ">10I", data[offset : offset + 40]
        )
        sha1 = data[offset + 40 : offset + 60].hex()
        flags = struct.unpack(">H", data[offset + 60 : offset + 62])[0]
        name_len = flags & 0x0FFF
        ext = flags & 0x4000
        path_offset = offset + 62
        # v3 has an extra 2-byte extended flag
        if version >= 3 and ext:
            path_offset += 2

        if version == 4:
            # Path is stored as (varint strip count) + (delta path) + NUL
            n_remove, n_bytes = _varint(data, path_offset)
            path_start = path_offset + n_bytes
            nul = data.find(b"\x00", path_start)
            if nul == -1:
                break
            delta = data[path_start:nul]
            path_bytes = prev_path[: len(prev_path) - n_remove] + delta
            offset = nul + 1
        else:
            path_start = path_offset
            if name_len < 0x0FFF:
                path_bytes = data[path_start : path_start + name_len]
                end = path_start + name_len
            else:
                nul = data.find(b"\x00", path_start)
                if nul == -1:
                    break
                path_bytes = data[path_start:nul]
                end = nul
            # Pad to 8-byte boundary
            total = end - offset + 1
            padding = (8 - (total % 8)) % 8
            offset = end + 1 + padding

        prev_path = path_bytes
        try:
            path_str = path_bytes.decode("utf-8", errors="replace")
        except Exception:
            path_str = repr(path_bytes)
        entries.append(IndexEntry(
            ctime=ctime_s, mtime=mtime_s, mode=mode,
            sha1=sha1, flags=flags, path=path_str,
        ))
    return entries


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    """Git's MSB-continuation varint (used in index v4)."""
    val = 0
    consumed = 0
    while True:
        b = data[offset + consumed]
        consumed += 1
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            break
        val += 1
    return val, consumed
