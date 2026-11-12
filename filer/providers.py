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
import errno
import hashlib
import os
import shutil
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

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
    async def save_file(self, key: str, source: Path, *, size: int, content_type: str, move: bool = False) -> None: ...
    async def read(self, key: str) -> bytes: ...
    async def read_stream(self, key: str, chunk_size: int | None = None) -> AsyncIterator[bytes]: ...
    async def delete(self, key: str) -> None: ...
    async def link_or_copy(self, existing_key: str, new_key: str) -> None: ...


def _copy_closed(source: Path, dst: Path) -> None:
    """Copy `source` to `dst` created 0640 from the first byte, flushed to disk before it is called stored."""
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissions.SHARED_FILE_MODE)
    with os.fdopen(fd, "wb") as target, open(source, "rb") as origin:
        shutil.copyfileobj(origin, target, 1024 * 1024)
        target.flush()
        os.fsync(target.fileno())


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

    def path_of(self, key: str) -> Path:
        """The file `key` is stored in, for a caller that hands it to the server to send (gateway FileResponse).
        Reads a setting: call it on the event loop."""
        return self._resolve(key)

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

    async def save_file(self, key: str, source: Path, *, size: int, content_type: str, move: bool = False) -> None:
        """Keep the file at `source` under `key`, without reading it into memory. `move=True` hands the source
        over: it is renamed into place (instant, nothing copied) when it is on the same filesystem as the
        storage root, and copied then removed when it is not. The stored file is created closed to other users
        (0640) either way. `size` and `content_type` are part of the provider contract (S3 uses them); a local
        file needs neither."""
        root = self._root()  # a setting: read here on the event loop, not in the thread below

        def _do() -> None:
            dst = self._resolve(key, root)
            self._make_dirs(dst.parent, root)
            if not move:
                _copy_closed(source, dst)
                return
            try:
                os.replace(source, dst)  # the spool is 0600: tighter than the stored mode, so never exposed
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                _copy_closed(source, dst)  # another filesystem: copy, then the source is no longer needed
                source.unlink(missing_ok=True)
                return
            os.chmod(dst, permissions.SHARED_FILE_MODE)

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


_S3_ADDRESSING_STYLES = ("auto", "path", "virtual")
_S3_CHECKSUM_MODES = ("auto", "when_supported", "when_required")
_MIN_S3_PART_MB = 5  # S3's own minimum size of every part but the last
_MAX_S3_PART_MB = 512
_MAX_S3_CONCURRENCY = 32


def _choice(key: str, allowed: tuple[str, ...], default: str) -> str:
    value = str(arc.settings.get(key) or default).strip().lower()
    if value not in allowed:
        raise RuntimeError(f"'{key}' is set to {value!r} - it must be one of {list(allowed)}.")
    return value


def _bounded(key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(arc.settings.get(key) or 0)
    except (TypeError, ValueError):
        value = 0
    return min(max(value, low), high) if value > 0 else default


@dataclass(frozen=True)
class S3Settings:
    """Every S3 setting a call needs, as the settings hold them NOW. Read on the event loop (`S3Settings.read`)
    before a blocking call is handed to a worker thread: the settings store keeps one SQLite connection for the
    whole process, which several threads must not use at once (eight threads reading them at the same time
    built different clients, with garbled credentials, in a test)."""

    region: Any = None
    endpoint_url: Any = None
    access_key_id: Any = None
    secret_access_key: Any = None
    addressing_style: str = "auto"
    checksum_mode: str = "auto"
    connect_timeout: int = 10
    read_timeout: int = 60
    max_attempts: int = 5
    # what an upload sends: not part of the client, so changing one does not build a new client
    send_acl: bool = True
    sse: str = ""
    sse_kms_key_id: str = ""
    part_size_mb: int = 8
    concurrency: int = 4
    # downloads: a big file is sent by redirecting the browser to S3 itself (see S3Provider.redirect_url)
    redirect_over_mb: int = 32
    public_endpoint_url: str = ""

    @classmethod
    def read(cls) -> S3Settings:
        sse = str(arc.settings.get("filer_s3_server_side_encryption") or "").strip()
        if sse not in ("", "AES256", "aws:kms"):
            raise RuntimeError(
                f"'filer_s3_server_side_encryption' is set to {sse!r} - it must be empty, AES256 or aws:kms."
            )
        return cls(
            # a blanked field is stored as an empty string: that means "not set" (boto3 rejects "" as an endpoint)
            region=arc.settings.get("filer_s3_region") or None,
            endpoint_url=arc.settings.get("filer_s3_endpoint_url") or None,
            access_key_id=arc.settings.get("filer_s3_access_key_id", reveal=True),
            secret_access_key=arc.settings.get("filer_s3_secret_access_key", reveal=True),
            addressing_style=_choice("filer_s3_addressing_style", _S3_ADDRESSING_STYLES, "auto"),
            checksum_mode=_choice("filer_s3_checksum_mode", _S3_CHECKSUM_MODES, "auto"),
            connect_timeout=_bounded("filer_s3_connect_timeout_seconds", 10, 1, 600),
            read_timeout=_bounded("filer_s3_read_timeout_seconds", 60, 1, 3600),
            max_attempts=_bounded("filer_s3_max_attempts", 5, 1, 20),
            send_acl=bool(arc.settings.get("filer_s3_send_acl")),
            sse=sse,
            sse_kms_key_id=str(arc.settings.get("filer_s3_sse_kms_key_id") or "").strip(),
            part_size_mb=_bounded("filer_s3_part_size_mb", 8, _MIN_S3_PART_MB, _MAX_S3_PART_MB),
            concurrency=_bounded("filer_s3_upload_concurrency", 4, 1, _MAX_S3_CONCURRENCY),
            redirect_over_mb=max(0, int(arc.settings.get("filer_s3_redirect_over_mb") or 0)),  # 0 = never
            public_endpoint_url=str(arc.settings.get("filer_s3_public_endpoint_url") or "").strip(),
        )

    def client_fingerprint(self) -> str:
        """A hash of what the client is built from, so the secret itself is never a dictionary key."""
        values = (
            self.region, self.endpoint_url, self.access_key_id, self.secret_access_key, self.addressing_style,
            self.checksum_mode, self.connect_timeout, self.read_timeout, self.max_attempts, self.concurrency,
        )
        return hashlib.sha256("\x00".join(str(v) for v in values).encode()).hexdigest()

    def extra_args(self, content_type: str) -> dict[str, str]:
        """What an upload tells S3 about the object. `ACL` only when the service takes one (Cloudflare R2 and
        Backblaze B2 refuse it: turn `filer_s3_send_acl` off and keep the bucket private)."""
        extra = {"ContentType": content_type}
        if self.send_acl:
            extra["ACL"] = "private"
        if self.sse:
            extra["ServerSideEncryption"] = self.sse
            if self.sse == "aws:kms" and self.sse_kms_key_id:
                extra["SSEKMSKeyId"] = self.sse_kms_key_id
        return extra


def _botocore_config(values: S3Settings) -> Any:
    from botocore.config import Config

    options: dict[str, Any] = {
        "signature_version": "s3v4",
        "connect_timeout": values.connect_timeout,
        "read_timeout": values.read_timeout,
        "retries": {"max_attempts": values.max_attempts, "mode": "standard"},
        "max_pool_connections": max(10, values.concurrency + 4),  # the default 10 starves a wide upload
    }
    if values.addressing_style in ("path", "virtual"):
        options["s3"] = {"addressing_style": values.addressing_style}
    mode = values.checksum_mode
    if mode == "auto":
        # botocore 1.36+ adds a CRC32 checksum to every upload by default. Amazon S3 takes it; many other
        # S3-compatible services (older MinIO and Ceph, some Backblaze and Wasabi setups) reject it.
        mode = "when_required" if values.endpoint_url else "when_supported"
    if mode == "when_required":
        options["request_checksum_calculation"] = "when_required"
        options["response_checksum_validation"] = "when_required"
    try:
        return Config(**options)
    except TypeError:
        # a botocore older than 1.36 never added those checksums: there is nothing to switch off
        options.pop("request_checksum_calculation", None)
        options.pop("response_checksum_validation", None)
        return Config(**options)


def _is_missing_object(exc: Exception) -> bool:
    code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
    return code in ("NoSuchKey", "404", "NotFound")


class S3Provider:
    """Every object is uploaded with a PRIVATE ACL (unless the service refuses ACLs: `filer_s3_send_acl`),
    unconditionally - `FilerFile.private` is an ARC-layer decision (enforced by the serve endpoint), never
    delegated to the bucket. Dedup is a local-only mechanism in v1 (see docs/filer-attachment-storage-proposal.md
    §3) - `link_or_copy` here always raises so `upload()` never attempts it for S3-backed files; a miss just
    means a fresh byte upload.

    Big files go up as an S3 multipart upload straight from the file on disk (`save_file`): memory is a few
    buffers of one part each, whatever the size, and a failed upload aborts its parts so none is left billing."""

    def __init__(self) -> None:
        # One client for the current S3 settings (building one costs 12.5 ms the first time and 2.8 ms
        # warm, on every upload, download, delete and scan, and a boto3 client is safe to share between
        # threads). The settings are read on every call, as before, so a changed setting builds a new
        # client at once and the old one is dropped. Keyed by a hash of the values, so the secret itself
        # is never a dictionary key; the lock is because creating clients from several threads at once
        # (boto3's default session) is not safe.
        self._client_lock = threading.Lock()
        self._cached_client: tuple[str, Any] | None = None
        # The client that signs download links when browsers reach S3 at another address than this server does.
        self._cached_signing_client: tuple[str, Any] | None = None

    def _s3_settings(self) -> S3Settings:
        """The S3 settings as they are NOW: read on the event loop, before a blocking call goes to a thread."""
        return S3Settings.read()

    def _client(self, values: S3Settings | None = None) -> Any:
        """The client for `values` (read from the settings when not given: only do that on the event loop)."""
        values = values if values is not None else self._s3_settings()
        return self._cached(values, "_cached_client")

    def _cached(self, values: S3Settings, slot: str) -> Any:
        fingerprint = values.client_fingerprint()
        cached = getattr(self, slot)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
        with self._client_lock:
            cached = getattr(self, slot)
            if cached is not None and cached[0] == fingerprint:
                return cached[1]
            import boto3

            client = boto3.client(
                "s3",
                region_name=values.region,
                endpoint_url=values.endpoint_url,
                aws_access_key_id=values.access_key_id,
                aws_secret_access_key=values.secret_access_key,
                config=_botocore_config(values),
            )
            setattr(self, slot, (fingerprint, client))
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
            self._client(s3).put_object(Bucket=bucket, Key=key, Body=content, **s3.extra_args(content_type))

        await asyncio.to_thread(_do)

    async def save_file(self, key: str, source: Path, *, size: int, content_type: str, move: bool = False) -> None:
        """Upload the file at `source` (S3 never takes it over: `move` makes no difference here). A file below
        one part goes up in a single request; a bigger one as a multipart upload, `filer_s3_upload_concurrency`
        parts at a time, each read from the disk when it is sent."""
        s3, bucket = self._s3_settings(), self._bucket()

        def _do() -> None:
            from boto3.s3.transfer import TransferConfig

            part = s3.part_size_mb * 1024 * 1024
            config = TransferConfig(
                multipart_threshold=part,
                multipart_chunksize=part,
                max_concurrency=s3.concurrency,
                use_threads=s3.concurrency > 1,
            )
            self._client(s3).upload_file(
                Filename=str(source), Bucket=bucket, Key=key, ExtraArgs=s3.extra_args(content_type), Config=config
            )

        await asyncio.to_thread(_do)

    async def redirect_url(
        self, key: str, size: int, *, content_type: str, content_disposition: str, expires: int = 300
    ) -> str | None:
        """A short-lived link that lets the BROWSER download the object from S3 itself, or None when this file
        should be sent through the server instead.

        Sending a big object through the worker costs memory: the server queues the chunks as fast as S3 supplies
        them, whatever pace the client reads at (a slow client on a 1 GiB file held about 1 GiB in the worker; see
        gateway.request.FileResponse). A redirect moves the bytes off the worker altogether. It applies when:

          * `filer_s3_redirect_over_mb` is above 0 and the object is bigger than that (default 32 MB: smaller files
            keep streaming, so what a browser sees only changes for big downloads);
          * the address in the link is one a browser can reach: Amazon S3 (no `filer_s3_endpoint_url`), or a
            service whose browser-facing address is given in `filer_s3_public_endpoint_url`. A custom endpoint
            alone is usually an internal address (a container name, a private IP), so it is never used in a link.

        The link carries the object's content type and the Content-Disposition the server would have sent, valid for
        `expires` seconds. The caller has already checked who may download the file."""
        s3 = self._s3_settings()  # a setting: read here on the event loop, not in the thread below
        if s3.redirect_over_mb <= 0 or size <= s3.redirect_over_mb * 1024 * 1024:
            return None
        if s3.endpoint_url and not s3.public_endpoint_url:
            return None
        bucket = self._bucket()
        signing = replace(s3, endpoint_url=s3.public_endpoint_url) if s3.endpoint_url else s3

        def _do() -> str:
            # Signing needs no request to S3 (but may resolve credentials, which can), so it stays off the loop.
            client = self._cached(signing, "_cached_signing_client" if s3.endpoint_url else "_cached_client")
            return client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": bucket,
                    "Key": key,
                    "ResponseContentType": content_type,
                    "ResponseContentDisposition": content_disposition,
                },
                ExpiresIn=expires,
            )

        return await asyncio.to_thread(_do)

    async def read(self, key: str) -> bytes:
        s3, bucket = self._s3_settings(), self._bucket()

        def _do() -> bytes:
            return self._get(s3, bucket, key)["Body"].read()

        return await asyncio.to_thread(_do)

    def _get(self, s3: S3Settings, bucket: str, key: str) -> Any:
        """get_object, with a missing object reported the way the local provider reports it."""
        try:
            return self._client(s3).get_object(Bucket=bucket, Key=key)
        except Exception as exc:  # noqa: BLE001 - botocore's ClientError, recognised by its error code
            if _is_missing_object(exc):
                raise FileNotFoundError(key) from exc
            raise

    async def read_stream(self, key: str, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        chunk_size = chunk_size or stream_chunk_bytes()
        s3, bucket = self._s3_settings(), self._bucket()

        def _open():
            return self._get(s3, bucket, key)["Body"]

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
