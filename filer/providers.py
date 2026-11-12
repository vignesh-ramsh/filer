"""filer.providers
-------------------
Storage backends, one `Protocol` implementation per provider — the same
shape mail/mail/providers.py already uses for pluggable SMTP backends.
`PROVIDERS` is a plain dict registry keyed by `FilerFile.storage`; adding a
new backend is "write the class, add it here, add the option string to
FilerFile.json's `storage` SELECT" — no other file needs to change.

Every blocking call (disk I/O, boto3) is wrapped in `asyncio.to_thread` —
this codebase's established convention for blocking I/O (mail's own
attachment reads) rather than adding an async-native dependency
(aiofiles/aioboto3) nothing else here uses.

One rule goes with that: SETTINGS ARE READ BEFORE THE THREAD HOP, never inside
the function handed to `to_thread`. The settings store keeps a single SQLite
connection for the whole process, which two threads must not use at once (eight
threads reading settings together built different S3 clients in a test), so
each method reads what it needs on the event loop and passes it in.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import threading
from pathlib import Path
from typing import Any, AsyncIterator, Protocol

import arc
from arc import permissions

# Literal key, not imported from filer/__init__.py (this stays a leaf module, see LocalProvider._root).
STREAM_CHUNK_KB_KEY = "filer_stream_chunk_kb"
DEFAULT_STREAM_CHUNK_KB = 256
_MIN_STREAM_CHUNK_KB = 16
_MAX_STREAM_CHUNK_KB = 4096


def stream_chunk_bytes() -> int:
    """How much of a file one read of `read_stream` returns: `filer_stream_chunk_kb` (default 256), kept
    between 16 KB and 4 MB; anything unusable (not a number, 0 or less) means the default. Every chunk is one
    thread hop, so a small one costs CPU when many downloads run at once: reading a 256 MB file in 64 KB chunks
    measured 809 MB/s over 4,096 hops, 256 KB chunks 2,383 MB/s."""
    try:
        kb = int(arc.settings.get(STREAM_CHUNK_KB_KEY) or 0)
    except (TypeError, ValueError):
        kb = 0
    if kb <= 0:
        kb = DEFAULT_STREAM_CHUNK_KB
    return min(max(kb, _MIN_STREAM_CHUNK_KB), _MAX_STREAM_CHUNK_KB) * 1024


class StorageProvider(Protocol):
    async def save(self, key: str, content: bytes, *, content_type: str) -> None: ...
    async def read(self, key: str) -> bytes: ...
    async def read_stream(self, key: str, chunk_size: int | None = None) -> AsyncIterator[bytes]: ...
    async def delete(self, key: str) -> None: ...
    async def link_or_copy(self, existing_key: str, new_key: str) -> None: ...


class PathEscapeError(RuntimeError):
    """A resolved local path fell outside the configured storage root —
    should be unreachable given `storage_key` is always server-generated
    (never derived from user input), but checked on every read/write
    anyway as defense in depth, not the only defense."""


class LocalProvider:
    """Root: `find_project_root() / "files"` by default, overridable via
    the `filer_local_root` setting — read fresh on every call rather than
    cached at construction time, since this object is a long-lived
    module-level singleton (`PROVIDERS["local"]`) constructed before
    settings are necessarily readable, and a setting change should take
    effect without a process restart."""

    def _root(self) -> Path:
        from arc.runtime import find_project_root

        # Literal key, not imported from filer/__init__.py — providers.py
        # stays a leaf module with no import back into the package's own
        # __init__ (mail/providers.py follows the identical direction).
        override = arc.settings.get("filer_local_root")
        root = Path(override) if override else find_project_root() / "files"
        return root.resolve()

    def _resolve(self, key: str, root: Path | None = None) -> Path:
        """The absolute path of `key` under the storage root. Pass `root` (read with `_root()` on the event
        loop) when calling from a worker thread: `_root()` reads a setting, which a thread must not do."""
        root = root if root is not None else self._root()
        path = (root / key).resolve()
        if path != root and root not in path.parents:
            raise PathEscapeError(f"storage_key {key!r} resolves outside the storage root {root}")
        return path

    def _make_dirs(self, directory: Path, root: Path | None = None) -> None:
        """Create `directory` and every missing folder above it (down from the storage root) closed to
        other users - 0750 - instead of the umask default, which on a typical machine is 0775. `root` as in
        `_resolve`."""
        current = root if root is not None else self._root()
        permissions.create_private_dir(current, permissions.SHARED_DIR_MODE)
        for part in directory.relative_to(current).parts:
            current = current / part
            permissions.create_private_dir(current, permissions.SHARED_DIR_MODE)

    async def save(self, key: str, content: bytes, *, content_type: str) -> None:
        root = self._root()  # a setting: read here on the event loop, not in the thread below

        def _do() -> None:
            path = self._resolve(key, root)
            self._make_dirs(path.parent, root)
            # created 0640 from the first byte, never written at the default mode and tightened later
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissions.SHARED_FILE_MODE)
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)

        await asyncio.to_thread(_do)

    async def read(self, key: str) -> bytes:
        return await asyncio.to_thread(self._resolve(key).read_bytes)

    async def read_stream(self, key: str, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        chunk_size = chunk_size or stream_chunk_bytes()
        path = self._resolve(key)

        def _open():
            return open(path, "rb")

        f = await asyncio.to_thread(_open)
        try:
            while True:
                chunk = await asyncio.to_thread(f.read, chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            await asyncio.to_thread(f.close)

    async def delete(self, key: str) -> None:
        root = self._root()

        def _do() -> None:
            path = self._resolve(key, root)
            path.unlink(missing_ok=True)

        await asyncio.to_thread(_do)

    async def link_or_copy(self, existing_key: str, new_key: str) -> None:
        root = self._root()  # once for the whole call: source, destination and folders share one root

        def _do() -> None:
            src = self._resolve(existing_key, root)
            dst = self._resolve(new_key, root)
            self._make_dirs(dst.parent, root)
            try:
                os.link(src, dst)  # hardlink: same inode (so the same closed mode), new directory entry
            except OSError:
                shutil.copyfile(src, dst)  # cross-device, unsupported FS, etc.
                os.chmod(dst, permissions.SHARED_FILE_MODE)

        await asyncio.to_thread(_do)


class S3Provider:
    """Every object is uploaded with a PRIVATE ACL, unconditionally —
    `FilerFile.private` is an ARC-layer decision (enforced by the serve
    endpoint), never delegated to the bucket. Dedup is a local-only
    mechanism in v1 (see docs/filer-attachment-storage-proposal.md §3) —
    `link_or_copy` here always raises so `upload()` never attempts it for
    S3-backed files; a miss just means a fresh byte upload."""

    def __init__(self) -> None:
        # One client for the current S3 settings (building one costs 12.5 ms the first time and 2.8 ms
        # warm, on every upload, download, delete and scan, and a boto3 client is safe to share between
        # threads). The settings are read on every call, as before, so a changed setting builds a new
        # client at once and the old one is dropped. Keyed by a hash of the values, so the secret itself
        # is never a dictionary key; the lock is because creating clients from several threads at once
        # (boto3's default session) is not safe.
        self._client_lock = threading.Lock()
        self._cached_client: tuple[str, Any] | None = None

    def _s3_settings(self) -> tuple[Any, Any, Any, Any]:
        """(region, endpoint, access key id, secret) as the settings hold them NOW. Read on the event loop,
        before a blocking call is handed to a worker thread: the settings store keeps one SQLite connection
        for the whole process, which several threads must not use at once (eight threads reading them at
        the same time built different clients, with garbled credentials, in a test)."""
        return (
            arc.settings.get("filer_s3_region"),
            arc.settings.get("filer_s3_endpoint_url"),
            arc.settings.get("filer_s3_access_key_id", reveal=True),
            arc.settings.get("filer_s3_secret_access_key", reveal=True),
        )

    def _client(self, values: tuple[Any, Any, Any, Any] | None = None) -> Any:
        """The client for `values` (read from the settings when not given: only do that on the event loop)."""
        values = values if values is not None else self._s3_settings()
        fingerprint = hashlib.sha256("\x00".join(str(v) for v in values).encode()).hexdigest()
        cached = self._cached_client
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
        with self._client_lock:
            cached = self._cached_client
            if cached is not None and cached[0] == fingerprint:
                return cached[1]
            import boto3

            region, endpoint_url, access_key_id, secret_access_key = values
            client = boto3.client(
                "s3",
                region_name=region,
                endpoint_url=endpoint_url,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
            )
            self._cached_client = (fingerprint, client)
            return client

    def _bucket(self) -> str:
        bucket = arc.settings.get("filer_s3_bucket")
        if not bucket:
            raise RuntimeError(
                "filer_s3_bucket is not set — run: arc settings set filer_s3_bucket <name>"
            )
        return bucket

    async def save(self, key: str, content: bytes, *, content_type: str) -> None:
        s3, bucket = self._s3_settings(), self._bucket()

        def _do() -> None:
            self._client(s3).put_object(
                Bucket=bucket,
                Key=key,
                Body=content,
                ContentType=content_type,
                ACL="private",
            )

        await asyncio.to_thread(_do)

    async def read(self, key: str) -> bytes:
        s3, bucket = self._s3_settings(), self._bucket()

        def _do() -> bytes:
            obj = self._client(s3).get_object(Bucket=bucket, Key=key)
            return obj["Body"].read()

        return await asyncio.to_thread(_do)

    async def read_stream(self, key: str, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        chunk_size = chunk_size or stream_chunk_bytes()
        s3, bucket = self._s3_settings(), self._bucket()

        def _open():
            return self._client(s3).get_object(Bucket=bucket, Key=key)["Body"]

        body = await asyncio.to_thread(_open)
        try:
            while True:
                chunk = await asyncio.to_thread(body.read, chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            await asyncio.to_thread(body.close)

    async def delete(self, key: str) -> None:
        s3, bucket = self._s3_settings(), self._bucket()

        def _do() -> None:
            self._client(s3).delete_object(Bucket=bucket, Key=key)

        await asyncio.to_thread(_do)

    async def link_or_copy(self, existing_key: str, new_key: str) -> None:
        raise NotImplementedError(
            "S3 dedup is a v1 non-goal — see docs/filer-attachment-storage-proposal.md §3"
        )


PROVIDERS: dict[str, StorageProvider] = {"local": LocalProvider(), "s3": S3Provider()}
