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
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any, AsyncIterator, Protocol

import arc


class StorageProvider(Protocol):
    async def save(self, key: str, content: bytes, *, content_type: str) -> None: ...
    async def read(self, key: str) -> bytes: ...
    async def read_stream(self, key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]: ...
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

    def _resolve(self, key: str) -> Path:
        root = self._root()
        path = (root / key).resolve()
        if path != root and root not in path.parents:
            raise PathEscapeError(f"storage_key {key!r} resolves outside the storage root {root}")
        return path

    async def save(self, key: str, content: bytes, *, content_type: str) -> None:
        def _do() -> None:
            path = self._resolve(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        await asyncio.to_thread(_do)

    async def read(self, key: str) -> bytes:
        return await asyncio.to_thread(self._resolve(key).read_bytes)

    async def read_stream(self, key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
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
        def _do() -> None:
            path = self._resolve(key)
            path.unlink(missing_ok=True)

        await asyncio.to_thread(_do)

    async def link_or_copy(self, existing_key: str, new_key: str) -> None:
        def _do() -> None:
            src = self._resolve(existing_key)
            dst = self._resolve(new_key)
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(src, dst)  # hardlink: same inode, new directory entry
            except OSError:
                shutil.copyfile(src, dst)  # cross-device, unsupported FS, etc.

        await asyncio.to_thread(_do)


class S3Provider:
    """Every object is uploaded with a PRIVATE ACL, unconditionally —
    `FilerFile.private` is an ARC-layer decision (enforced by the serve
    endpoint), never delegated to the bucket. Dedup is a local-only
    mechanism in v1 (see docs/filer-attachment-storage-proposal.md §3) —
    `link_or_copy` here always raises so `upload()` never attempts it for
    S3-backed files; a miss just means a fresh byte upload."""

    def _client(self) -> Any:
        import boto3

        return boto3.client(
            "s3",
            region_name=arc.settings.get("filer_s3_region"),
            endpoint_url=arc.settings.get("filer_s3_endpoint_url"),
            aws_access_key_id=arc.settings.get("filer_s3_access_key_id", reveal=True),
            aws_secret_access_key=arc.settings.get("filer_s3_secret_access_key", reveal=True),
        )

    def _bucket(self) -> str:
        bucket = arc.settings.get("filer_s3_bucket")
        if not bucket:
            raise RuntimeError(
                "filer_s3_bucket is not set — run: arc settings set filer_s3_bucket <name>"
            )
        return bucket

    async def save(self, key: str, content: bytes, *, content_type: str) -> None:
        def _do() -> None:
            self._client().put_object(
                Bucket=self._bucket(),
                Key=key,
                Body=content,
                ContentType=content_type,
                ACL="private",
            )

        await asyncio.to_thread(_do)

    async def read(self, key: str) -> bytes:
        def _do() -> bytes:
            obj = self._client().get_object(Bucket=self._bucket(), Key=key)
            return obj["Body"].read()

        return await asyncio.to_thread(_do)

    async def read_stream(self, key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        def _open():
            return self._client().get_object(Bucket=self._bucket(), Key=key)["Body"]

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
        def _do() -> None:
            self._client().delete_object(Bucket=self._bucket(), Key=key)

        await asyncio.to_thread(_do)

    async def link_or_copy(self, existing_key: str, new_key: str) -> None:
        raise NotImplementedError(
            "S3 dedup is a v1 non-goal — see docs/filer-attachment-storage-proposal.md §3"
        )


PROVIDERS: dict[str, StorageProvider] = {"local": LocalProvider(), "s3": S3Provider()}
