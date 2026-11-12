"""filer.uploads
---------------
Receiving an upload request's body into a private spool file, with the limits that make that safe at 1 GB.

`arc.filer.receive_upload(request)` is how a route takes a file: it reads the multipart body as it arrives
(gateway `stream_body` routes) and writes the file part to a temporary file while hashing it, so memory stays at
about one buffer however big the file is. What it adds on top of the gateway's parser, all decided BEFORE or WHILE
the body is read, never after:

  * a concurrency limit (`filer_max_concurrent_uploads` per worker): over it, the request is told to come back
    (503 + Retry-After) before a byte is read;
  * a disk check: the declared size plus a headroom (`filer_spool_min_free_mb`) must fit in the spool's
    filesystem, or the request is refused (507) instead of failing halfway;
  * a total time limit (`filer_upload_max_seconds`), on top of the gateway's idle limit;
  * the file's content type is checked against `filer_allowed_content_types` as its headers arrive;
  * the size limit (`filer_max_upload_bytes`) is enforced as the bytes arrive.

The spool is `files/.incoming` by default, the same filesystem as local storage, so keeping a received file is a
rename (nothing is copied). A leftover spool file (a crashed worker) is removed by `sweep_spool` (hourly task).

All settings are read on the event loop (`UploadSettings.read`), never in a worker thread: the settings store
keeps one SQLite connection for the whole process.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import secrets
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import arc

STREAMING_KEY = "filer_streaming_uploads"
SPOOL_DIR_KEY = "filer_spool_dir"
MAX_CONCURRENT_KEY = "filer_max_concurrent_uploads"
SPOOL_MIN_FREE_MB_KEY = "filer_spool_min_free_mb"
UPLOAD_MAX_SECONDS_KEY = "filer_upload_max_seconds"
SPOOL_MAX_AGE_HOURS_KEY = "filer_spool_max_age_hours"

DEFAULT_MAX_CONCURRENT = 8
DEFAULT_SPOOL_MIN_FREE_MB = 1024
DEFAULT_UPLOAD_MAX_SECONDS = 3600
DEFAULT_SPOOL_MAX_AGE_HOURS = 3
#: What a non-streaming request (an old route, or `filer_streaming_uploads` off) may hold in memory: the limit
#: every upload had before streaming existed.
BUFFERED_MAX_BYTES = 60 * 1024 * 1024
SPOOL_DIR_NAME = ".incoming"
_RETRY_AFTER_SECONDS = 5

_logger = logging.getLogger("arc.filer")


def declare_settings(kernel: Any) -> None:
    kernel.settings.declare(
        STREAMING_KEY,
        type=bool,
        default=True,
        doc="How file uploads are received. On (the default): the file is written to disk while it arrives, so a "
        "big upload uses almost no memory. Off: the old way, the whole request is held in memory (up to 60 MB). "
        "Leave it on; it exists to switch back quickly if streaming ever misbehaves. Takes effect for the next "
        "upload.",
    )
    kernel.settings.declare(
        SPOOL_DIR_KEY,
        operator_only=True,
        doc="The folder where an upload is kept while it is being received, before it is stored. If empty, ARC uses "
        "a `.incoming` folder inside the local storage folder, which makes storing a received file instant. It "
        "must have room for your biggest uploads. Changed on the server only (`arc settings set filer_spool_dir "
        "<folder>`).",
    )
    kernel.settings.declare(
        MAX_CONCURRENT_KEY,
        type=int,
        default=DEFAULT_MAX_CONCURRENT,
        doc="How many uploads one web worker receives at the same time (default 8; 0 means no limit). More than "
        "that are told to try again in a few seconds (a 503 answer). It bounds the disk space and connections "
        "that uploads can use at once.",
    )
    kernel.settings.declare(
        SPOOL_MIN_FREE_MB_KEY,
        type=int,
        default=DEFAULT_SPOOL_MIN_FREE_MB,
        doc="How many megabytes must stay free on the disk where uploads are received, over and above the upload "
        "itself (default 1024). An upload that would not leave that much room is refused at once with a 507 "
        "answer instead of filling the disk.",
    )
    kernel.settings.declare(
        UPLOAD_MAX_SECONDS_KEY,
        type=int,
        default=DEFAULT_UPLOAD_MAX_SECONDS,
        doc="The longest an upload may take to arrive, in seconds (default 3600; 0 means no limit). It is a "
        "ceiling on top of the idle limit (`gateway_body_idle_timeout_seconds`): a client that keeps sending "
        "very slowly is still stopped at this.",
    )
    kernel.settings.declare(
        SPOOL_MAX_AGE_HOURS_KEY,
        type=int,
        default=DEFAULT_SPOOL_MAX_AGE_HOURS,
        doc="How many hours an unfinished upload file may sit in the receiving folder before the hourly cleanup "
        "removes it (default 3). A running upload keeps its file fresh, so only the leftovers of a crash qualify.",
    )


class UploadsBusy(Exception):
    """Too many uploads are in progress on this worker. Says of itself that it is capacity, not a bug
    (`http_status`, `retry_after`): the gateway answers 503 with Retry-After."""

    http_status = 503
    retry_after = _RETRY_AFTER_SECONDS

    def __init__(self, active: int, limit: int) -> None:
        super().__init__(f"{active} uploads are in progress on this worker (limit {limit})")


@dataclass(frozen=True)
class UploadSettings:
    streaming: bool
    spool_dir: Path
    max_file_bytes: int
    max_concurrent: int
    min_free_bytes: int
    max_seconds: int

    @classmethod
    def read(cls, *, max_file_bytes: int) -> UploadSettings:
        """Every setting an upload needs, read here on the event loop."""
        return cls(
            streaming=bool(arc.settings.get(STREAMING_KEY)),
            spool_dir=spool_dir(),
            max_file_bytes=max_file_bytes,
            max_concurrent=max(0, int(arc.settings.get(MAX_CONCURRENT_KEY) or 0)),
            min_free_bytes=max(0, int(arc.settings.get(SPOOL_MIN_FREE_MB_KEY) or 0)) * 1024 * 1024,
            max_seconds=max(0, int(arc.settings.get(UPLOAD_MAX_SECONDS_KEY) or 0)),
        )


def spool_dir() -> Path:
    """Where uploads are received: `filer_spool_dir`, or `.incoming` in the local storage root."""
    from filer.providers import PROVIDERS

    override = arc.settings.get(SPOOL_DIR_KEY)
    if override:
        return Path(override).resolve()
    return PROVIDERS["local"]._root() / SPOOL_DIR_NAME  # noqa: SLF001 - the one place that knows the root


class UploadStats:
    """What this worker has done with uploads, for the metrics and the admin status. Event-loop only, no lock."""

    def __init__(self) -> None:
        self.in_progress = 0
        self.received_total = 0
        self.received_bytes_total = 0
        self.failed_total: dict[str, int] = {}

    def failed(self, reason: str) -> None:
        self.failed_total[reason] = self.failed_total.get(reason, 0) + 1

    def snapshot(self) -> dict:
        return {
            "uploads_in_progress": self.in_progress,
            "uploads_received_total": self.received_total,
            "uploads_received_bytes_total": self.received_bytes_total,
            "uploads_failed_total": dict(self.failed_total),
        }


STATS = UploadStats()


def _declared_length(request: Any) -> int | None:
    try:
        value = int(request.headers.get("content-length", ""))
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


class ReceivedUpload:
    """`async with arc.filer.receive_upload(request) as received:` - the file part of the request, on disk.

    `received.file` is a gateway `SpooledFile` (its `path`, `size`, `sha256`, `filename`, `content_type`) or None
    when the request had no part named `file`; `received.fields` are its small text fields. Leaving the block
    deletes whatever is still in the spool (a file you moved into place, with `move=True`, is simply gone)."""

    def __init__(
        self,
        request: Any,
        settings: UploadSettings,
        *,
        field: str = "file",
        check_file: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._request = request
        self._settings = settings
        self._field = field
        self._check_file = check_file
        self._form: Any = None
        self._slot = False

    @property
    def file(self) -> Any:
        return self._form.files.get(self._field) if self._form is not None else None

    @property
    def fields(self) -> dict[str, str]:
        return self._form.fields if self._form is not None else {}

    async def __aenter__(self) -> ReceivedUpload:
        from gateway.request import HTTPError

        settings = self._settings
        if settings.max_concurrent and STATS.in_progress >= settings.max_concurrent:
            STATS.failed("busy")
            raise UploadsBusy(STATS.in_progress, settings.max_concurrent)
        STATS.in_progress += 1
        self._slot = True
        try:
            settings.spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._check_room()
            deadline = asyncio.timeout(settings.max_seconds or None)
            try:
                async with deadline:
                    self._form = await self._receive()
            except TimeoutError:
                if not deadline.expired():
                    raise
                raise HTTPError(
                    408,
                    {"error": "the upload took too long", "limit_seconds": settings.max_seconds},
                ) from None
        except BaseException as exc:
            STATS.failed(_reason(exc))
            await self._release()
            raise
        if self.file is not None:
            STATS.received_total += 1
            STATS.received_bytes_total += self.file.size
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self._release()

    async def _release(self) -> None:
        try:
            if self._form is not None:
                await asyncio.shield(self._form.aclose())
        finally:
            if self._slot:
                self._slot = False
                STATS.in_progress -= 1

    def _check_room(self) -> None:
        from gateway.request import HTTPError

        settings = self._settings
        needed = (
            _declared_length(self._request) or settings.max_file_bytes
        ) + settings.min_free_bytes
        free = shutil.disk_usage(settings.spool_dir).free
        if free < needed:
            raise HTTPError(
                507,
                {
                    "error": "the server has no room left to receive this upload",
                    "needed_bytes": needed,
                    "free_bytes": free,
                },
            )

    async def _receive(self) -> Any:
        from gateway.multipart import parse_multipart_form
        from gateway.multipart_stream import StreamedForm, read_multipart_stream

        settings, request = self._settings, self._request
        if request.stream is not None and settings.streaming:
            return await read_multipart_stream(
                request,
                spool_dir=settings.spool_dir,
                max_file_bytes=settings.max_file_bytes,
                check_file=self._check_file,
            )
        # Not streamed: the body is read whole first (a route that does not stream, or streaming switched off).
        # Bounded by the limit every upload had before streaming existed.
        if request.stream is not None:
            body = await request.stream.read_all(max_bytes=BUFFERED_MAX_BYTES)
        else:
            body = request.body
        parsed = parse_multipart_form(body, request.headers.get("content-type", ""))
        form = StreamedForm(fields=dict(parsed.fields))
        for name, uploaded in parsed.files.items():
            if len(uploaded.content) > settings.max_file_bytes:
                from gateway.request import HTTPError

                raise HTTPError(
                    413, {"error": "file too large", "limit_bytes": settings.max_file_bytes}
                )
            if self._check_file is not None:
                self._check_file(name, uploaded.filename, uploaded.content_type)
            form.files[name] = await asyncio.to_thread(
                _spool_bytes,
                settings.spool_dir,
                name,
                uploaded.filename,
                uploaded.content_type,
                uploaded.content,
            )
        return form


def _spool_bytes(
    directory: Path, field: str, filename: str, content_type: str, content: bytes
) -> Any:
    from gateway.multipart_stream import SPOOL_SUFFIX, SpooledFile

    path = directory / f"upload-{secrets.token_hex(16)}{SPOOL_SUFFIX}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
    return SpooledFile(
        field, filename, content_type, path, len(content), hashlib.sha256(content).hexdigest()
    )


def _reason(exc: BaseException) -> str:
    """A short, stable label for why an upload failed, for the counters."""
    status = getattr(exc, "status_code", None)
    if status == 413:
        return "too_large"
    if status == 408:
        return "timeout"
    if status == 507:
        return "disk_full"
    if isinstance(status, int) and 400 <= status < 500:
        return "rejected"
    name = type(exc).__name__
    if name == "ClientDisconnected":
        return "disconnected"
    if isinstance(exc, asyncio.CancelledError):
        return "cancelled"
    return "error"


def sweep_spool(directory: Path, *, max_age_seconds: float, now: float | None = None) -> int:
    """Delete the spool files in `directory` that have not been written for `max_age_seconds`: what a crashed
    worker leaves behind (a running upload keeps its file fresh). Blocking: run it in a thread. Returns how many
    were removed."""
    from gateway.multipart_stream import SPOOL_SUFFIX

    cutoff = (time.time() if now is None else now) - max_age_seconds
    removed = 0
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return 0
    for entry in entries:
        if not entry.name.endswith(SPOOL_SUFFIX) or not entry.is_file(follow_symlinks=False):
            continue
        with contextlib.suppress(OSError):
            if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                os.unlink(entry.path)
                removed += 1
    if removed:
        _logger.warning("removed %d stale upload file(s) from %s", removed, directory)
    return removed
