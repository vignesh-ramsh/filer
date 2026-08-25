"""filer — ARC provider plugin: secure attachment storage.

Exports `arc.filer`: upload/get_file/sign_url/attach_urls/delete, backed
by pluggable storage providers (filer.providers.PROVIDERS — local disk by
default, S3 alongside it, both usable in the same instance at once).
Files are public or private; a private file's URL is a short-lived,
signature+expiry-validated bearer link, validated identically whether
nginx (production) or gateway itself (`arc run`, dev) sits in front —
see filer.tokens for the exact algorithm and why it deliberately matches
nginx's own `secure_link_md5` scheme rather than inventing a new one.

Full design: docs/filer-attachment-storage-proposal.md. This module
implements that proposal; treat this docstring as a pointer to it, not a
duplicate of it.

Authorization is NOT this plugin's job (docs §8): `sign_url`/
`attach_urls`/`delete` are trusted server-side primitives with no caller
checks of their own, the same posture `arc.relay.call()` already takes —
RBAC lives at whichever business endpoint's role gate a request actually
crosses. filer has no public "sign this file_id for me" HTTP endpoint at
all; a signed URL only ever reaches a client through an endpoint that
already decided the caller may see it.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import arc
from relay.resolvers import FieldResolver

CAPABILITY = "filer"

LOCAL_ROOT_KEY = "filer_local_root"
DEFAULT_STORAGE_KEY = "filer_default_storage"
ALLOWED_CONTENT_TYPES_KEY = "filer_allowed_content_types"
MAX_UPLOAD_BYTES_KEY = "filer_max_upload_bytes"
SCAN_PUBLIC_KEY = "filer_scan_public"
SCAN_PRIVATE_KEY = "filer_scan_private"
CLAMAV_SOCKET_KEY = "filer_clamav_socket"
PURGE_AFTER_DAYS_KEY = "filer_purge_after_days"
DEFAULT_LINK_TTL_KEY = "filer_default_link_ttl_seconds"
SIGNING_SECRET_KEY = "filer_signing_secret"
URL_SIGNING_SCHEME_KEY = "filer_url_signing_scheme"
S3_BUCKET_KEY = "filer_s3_bucket"
S3_REGION_KEY = "filer_s3_region"
S3_ENDPOINT_URL_KEY = "filer_s3_endpoint_url"
S3_ACCESS_KEY_ID_KEY = "filer_s3_access_key_id"
S3_SECRET_ACCESS_KEY_KEY = "filer_s3_secret_access_key"
# The upload ROUTE's own outer ASGI body ceiling (gateway/router.py's
# RouteEntry.max_body_bytes) — deliberately separate from
# MAX_UPLOAD_BYTES_KEY above, which is the live-editable, per-file-content
# business rule checked inside upload() AFTER the body's already been
# read. This one is read ONCE at import time (boot), same "fixed until
# restart" posture gateway_max_body_bytes itself already has — it exists
# so file_upload can accept a much larger request than the gateway-wide
# default (10MB) without raising that shared ceiling for every other
# JSON endpoint too.
MAX_REQUEST_BODY_BYTES_KEY = "filer_max_request_body_bytes"

DEFAULT_STORAGE = "local"
DEFAULT_CLAMAV_SOCKET = "/var/run/clamav/clamd.ctl"
DEFAULT_PURGE_AFTER_DAYS = 30
DEFAULT_LINK_TTL_SECONDS = 300
DEFAULT_MAX_REQUEST_BODY_BYTES = (
    60 * 1024 * 1024
)  # 60MB — generous headroom over the 30-50MB use case named for it

# Explicit allowlist only — content types NOT in this map get ".bin" and
# are always forced to download (never rendered inline), regardless of
# what the uploader's browser claimed the content-type was. Never derive
# an extension from the user's own filename (docs §9 — extension
# spoofing / path-traversal-adjacent risk).
_EXTENSION_FOR: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/zip": ".zip",
}

# Only these ever render inline (Content-Disposition: inline) — every
# other content type is forced to `attachment` in the serve endpoint,
# regardless of what's in _EXTENSION_FOR above. This, plus the global
# X-Content-Type-Options: nosniff gateway's security_headers_middleware
# already sets, is what stops an uploaded .html/.svg/.js from ever being
# rendered same-origin (docs §9/§12 #3).
_INLINE_ALLOWLIST = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"}
)

# Verdicts a dedup source may safely hand its checksum-sibling without a
# fresh scan (docs §6's table) — anything not covered here (pending,
# deleted, or a policy mismatch on 'skipped') falls through to a real
# scan in upload()'s own logic, not this set.
_INHERITABLE_STATUSES = frozenset({"clean", "infected"})

_FILE_FIELDS: dict[str, dict[str, str]] = {}  # table -> {field_name: "FILE"|"MULTIFILE"}

# upload()'s optional `path` — a caller-chosen organizational folder, never
# the filename (storage_key's own server-generated component still owns
# collision/traversal safety, below). "/"-separated segments only.
_UNGROUPED_PATH = "ungrouped"
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_PATH_DEPTH = 4


def _normalize_path(path: str | None) -> str:
    """Empty/omitted -> the shared 'ungrouped' bucket (same for public and
    private, since visibility is already a separate prefix, below) — never
    a silent default file lands at the storage root. Anything else must be
    a clean, bounded "/"-separated path: each segment letters/digits/`_`/
    `-` only (so a literal `.`/`..` segment is already impossible, not
    merely blocked by a second check), no empty segments (rules out a
    leading/trailing/doubled "/"), capped depth. A bad path is a clean,
    named 400 here — LocalProvider's own containment check (providers.py)
    stays as a second, independent backstop, not the only guard."""
    if not path or not path.strip("/"):
        return _UNGROUPED_PATH
    segments = path.strip("/").split("/")
    if len(segments) > _MAX_PATH_DEPTH:
        arc.relay.throw(f"path may be at most {_MAX_PATH_DEPTH} levels deep", code="invalid_path")
    for segment in segments:
        if not _PATH_SEGMENT_RE.match(segment):
            arc.relay.throw(
                f"path segment {segment!r} is invalid — only letters, digits, '_', and '-' are allowed "
                f"per segment, separated by '/'",
                code="invalid_path",
            )
    return "/".join(segments)


class FilerProvider:
    def __init__(self, kernel: Any) -> None:
        self._kernel = kernel

    # ------------------------------------------------------------------ #
    # Settings
    # ------------------------------------------------------------------ #
    def default_storage(self) -> str:
        return arc.settings.get(DEFAULT_STORAGE_KEY)

    def allowed_content_types(self) -> set[str] | None:
        raw = arc.settings.get(ALLOWED_CONTENT_TYPES_KEY)
        if not raw:
            return None
        return {t.strip() for t in raw.split(",") if t.strip()}

    def max_upload_bytes(self) -> int | None:
        return arc.settings.get(MAX_UPLOAD_BYTES_KEY)

    def scan_enabled(self, *, private: bool) -> bool:
        key = SCAN_PRIVATE_KEY if private else SCAN_PUBLIC_KEY
        return arc.settings.get(key)

    def clamav_socket(self) -> str:
        return arc.settings.get(CLAMAV_SOCKET_KEY)

    def max_request_body_bytes(self) -> int:
        return arc.settings.get(MAX_REQUEST_BODY_BYTES_KEY)

    async def antivirus_status(self) -> dict:
        """Live connectivity check against the configured ClamAV socket —
        ClamAV/clamd is the only scanner engine this plugin actually
        integrates with today (docs §7); `available_engines` is a list
        rather than one fixed field so a second engine can be added later
        without an API shape change, but it genuinely only ever has one
        entry right now — no other engine is wired up to claim otherwise."""
        socket_path = self.clamav_socket()
        connected, version = False, None
        try:
            connected = await asyncio.wait_for(_clamd_ping(socket_path), timeout=2.0)
        except Exception:
            connected = False
        if connected:
            try:
                version = await asyncio.wait_for(_clamd_version(socket_path), timeout=2.0)
            except Exception:
                version = None  # VERSION being unavailable/erroring never flips `connected`
        return {
            "engine": "ClamAV",
            "socket": socket_path,
            "connected": connected,
            "version": version,
            "scan_public": self.scan_enabled(private=False),
            "scan_private": self.scan_enabled(private=True),
            "available_engines": ["ClamAV"],
        }

    def purge_after_days(self) -> int:
        return arc.settings.get(PURGE_AFTER_DAYS_KEY)

    def default_link_ttl_seconds(self) -> int:
        return arc.settings.get(DEFAULT_LINK_TTL_KEY)

    def url_signing_scheme(self) -> str:
        """"md5" (the default — nginx secure_link_md5 parity, see
        filer.tokens' own module docstring for why that stays the
        default) or "hmac-sha256" (stronger, opt-in, breaks nginx
        parity). Validated here, not via declare()'s own `type=` (which
        only covers int/float/bool/str, no enum support) — a bad value
        fails clearly the moment anything tries to sign or verify a URL,
        naming exactly what's wrong and what's allowed, rather than
        silently falling back to a different scheme than the operator
        typed."""
        from filer import tokens

        value = arc.settings.get(URL_SIGNING_SCHEME_KEY) or tokens.DEFAULT_SCHEME
        if value not in tokens.SCHEMES:
            raise RuntimeError(
                f"'{URL_SIGNING_SCHEME_KEY}' is set to {value!r} — must be one of "
                f"{sorted(tokens.SCHEMES)}."
            )
        return value

    def _signing_secret(self) -> str:
        """Generated once, at boot, by register()'s own _ensure_signing_secret
        (see its docstring for why NOT lazily here on first use, the old
        shape) — mirrors how `.arc/arc.mkey` bootstraps itself, rather than
        requiring a manual `arc settings set` before the plugin works at
        all. Read fresh every call (not cached at construction) so a
        manually-rotated secret takes effect without a restart, same
        reasoning as LocalProvider's own root.

        register() guarantees this is already set by the time any request
        can reach here — a missing value at this point means register()
        itself never ran (this FilerProvider was constructed outside a
        normal arc.boot()), not a race to paper over here."""
        value = arc.settings.get(SIGNING_SECRET_KEY, reveal=True)
        if not value:
            raise RuntimeError(
                f"'{SIGNING_SECRET_KEY}' is unset — filer.register() should have "
                f"generated it at boot; was this FilerProvider constructed without "
                f"going through arc.boot()?"
            )
        return value

    # ------------------------------------------------------------------ #
    # Upload — dedup (hardlink-or-copy, local only) + scan-verdict
    # inheritance; see docs §6 for the full status-inheritance table.
    # ------------------------------------------------------------------ #
    async def upload(
        self,
        content: bytes,
        filename: str,
        *,
        content_type: str,
        storage: str | None = None,
        private: bool = True,
        path: str | None = None,
        by: str | None = None,
    ) -> dict:
        from filer.providers import PROVIDERS

        storage = storage or self.default_storage()
        if storage not in PROVIDERS:
            arc.relay.throw(f"unknown storage provider '{storage}'", code="unknown_storage")

        allowed = self.allowed_content_types()
        if allowed is not None and content_type not in allowed:
            arc.relay.throw(
                f"content type '{content_type}' is not allowed", code="content_type_not_allowed"
            )
        max_bytes = self.max_upload_bytes()
        if max_bytes is not None and len(content) > max_bytes:
            arc.relay.throw(
                f"file exceeds the {max_bytes}-byte upload limit", code="file_too_large"
            )

        normalized_path = _normalize_path(path)
        checksum = hashlib.sha256(content).hexdigest()
        visibility_dir = "private" if private else "public"
        file_id = f"{'pri' if private else 'pub'}_{secrets.token_urlsafe(16)}"
        ext = _EXTENSION_FOR.get(content_type, ".bin")
        storage_key = f"{visibility_dir}/{normalized_path}/{file_id}{ext}"

        provider = PROVIDERS[storage]
        status, linked = "pending", False
        if storage == "local":
            source = await self._dedup_source(checksum)
            if source is not None:
                try:
                    await provider.link_or_copy(source["storage_key"], storage_key)
                    linked = True
                    status = self._inherit_status(source["status"], private=private)
                except OSError:
                    linked = False
        if not linked:
            await provider.save(storage_key, content, content_type=content_type)

        row = await arc.relay.save(
            "filerfile",
            {
                "file_id": file_id,
                "storage": storage,
                "storage_key": storage_key,
                "original_filename": filename,
                "content_type": content_type,
                "size_bytes": len(content),
                "checksum": checksum,
                "private": private,
                "path": normalized_path,
                "status": status,
            },
            by=by,
        )
        if status == "pending":
            arc.relay.enqueue(_scan, row["id"])
        return row

    async def _dedup_source(self, checksum: str) -> dict | None:
        """Verdict priority: an infected row wins outright (a scanner-
        signature update can flip old verdicts, so infected-anywhere means
        infected-everywhere for these exact bytes), otherwise the most
        recently seen clean/skipped/pending row. 'deleted' rows are never
        sources — the purge job could unlink one mid-race."""
        infected = await arc.relay.get(
            "filerfile",
            {"checksum": checksum, "storage": "local", "status": "infected"},
            arc.relay.all_columns("filerfile"),
        )
        if infected is not None:
            return infected
        rows = await arc.relay.list(
            "filerfile",
            fields=arc.relay.all_columns("filerfile"),
            filters={
                "checksum": checksum,
                "storage": "local",
                "status": {"in": ["clean", "skipped", "pending"]},
            },
            order_by=["-created_at"],
            limit=1,
        )
        return rows[0] if rows else None

    def _inherit_status(self, source_status: str, *, private: bool) -> str:
        if source_status == "infected":
            return "infected"
        if source_status == "clean":
            return "clean"
        if source_status == "skipped":
            # 'skipped' only carries over if THIS upload's own policy would
            # also skip — "never scanned" can't be inherited past a policy
            # that now demands scanning (docs §6's table).
            return "skipped" if not self.scan_enabled(private=private) else "pending"
        return "pending"  # source itself hasn't resolved yet — scan independently

    # ------------------------------------------------------------------ #
    # Read primitives
    # ------------------------------------------------------------------ #
    async def get_file(self, file_id: str) -> dict | None:
        return await arc.relay.get("filerfile", {"file_id": file_id}, arc.relay.all_columns("filerfile"))

    def _url_for(self, row: dict, ttl_seconds: int | None = None) -> str:
        from filer.tokens import sign

        uri = f"/files/{row['file_id']}"
        if not row["private"]:
            return uri
        ttl = ttl_seconds or self.default_link_ttl_seconds()
        expires = int(time.time()) + ttl
        sig = sign(uri, expires, self._signing_secret(), scheme=self.url_signing_scheme())
        return f"{uri}?exp={expires}&sig={sig}"

    async def sign_url(self, file_id: str, *, ttl_seconds: int | None = None) -> str:
        row = await arc.relay.get(
            "filerfile", {"file_id": file_id}, arc.relay.all_columns("filerfile")
        )
        if row is None or row["status"] not in ("clean", "skipped"):
            arc.relay.throw("file not found", status=404, code="not_found")
        return self._url_for(row, ttl_seconds)

    async def attach_urls(self, rows: list[dict], *, table: str) -> list[dict]:
        """One batch `filerfile` query regardless of row/file count, then
        pure computation (an MD5 per URL) — see docs §8. A `FILE` field
        becomes its URL directly (a string, or None if unservable); a
        `MULTIFILE` entry becomes {label, url}."""
        fields = _FILE_FIELDS.get(table, {})
        if not fields or not rows:
            return rows

        ids: set[str] = set()
        for row in rows:
            _collect(row, fields, ids)
        if not ids:
            return rows

        # limit=None: this must resolve metadata for EVERY id in `ids`, not
        # just the first DEFAULT_LIST_LIMIT of them — the batch is already
        # bounded by however many distinct file references `rows` (the
        # caller's own, separately-limited fetch) actually contained.
        meta = {
            m["file_id"]: m
            for m in await arc.relay.list(
                "filerfile",
                filters={"file_id": {"in": list(ids)}},
                fields=["file_id", "private", "status"],
                limit=None,
            )
        }

        def _url(fid: str) -> str | None:
            m = meta.get(fid)
            servable = m is not None and m["status"] in ("clean", "skipped")
            return self._url_for(m) if servable else None

        out = []
        for row in rows:
            row = dict(row)
            for name, kind in fields.items():
                val = row.get(name)
                if not val:
                    continue
                if kind == "FILE":
                    row[name] = _url(val)
                else:  # MULTIFILE
                    row[name] = [{"label": e.get("label"), "url": _url(e["fileid"])} for e in val]
            out.append(row)
        return out

    def url(self, field: str, *, ttl_seconds: int | None = None) -> "_UrlResolver":
        """Marker for arc.relay.list()/get()'s `fields=[...]` — resolves a
        FILE/MULTIFILE column to a signed URL (or, for MULTIFILE, a list
        of {label, url}) after the row fetch:

            await arc.relay.list("employee",
                fields=["full_name", arc.filer.url("profile_photo")])

        A bare field name in `fields` (no arc.filer.url(...)) still
        returns the raw stored value (file_id, or the raw
        [{label,fileid}] array) unchanged — this is opt-in per field, per
        call site. Batched via relay.resolvers.FieldResolver: one extra
        `filerfile` query total per list()/get() call, never one per row
        (see _UrlResolver.prepare() below)."""
        return _UrlResolver(field=field, provider=self, ttl_seconds=ttl_seconds)

    async def delete(self, file_id: str) -> None:
        row = await arc.relay.get(
            "filerfile", {"file_id": file_id}, ["id", "status"]
        )
        if row is None or row["status"] == "deleted":
            return
        await arc.relay.save(
            "filerfile", {"id": row["id"], "status": "deleted", "deleted_at": arc.tz.utcnow()}
        )

    # ------------------------------------------------------------------ #
    # FILE/MULTIFILE discovery — automatic, via the schema registry (docs
    # §4). No per-plugin registration call: filer sweeps every schema
    # already registered at its own register() time, then subscribes to
    # psqldb.on_schema_registered for everything registered afterward
    # (schemas AND patches — a FILE/MULTIFILE field can arrive via either).
    # ------------------------------------------------------------------ #
    def _maybe_watch(self, table: str) -> None:
        psqldb = self._kernel.get("pgdb")
        schema = psqldb.schema(table)
        fields = {f.name: f.type for f in schema.fields if f.type in ("FILE", "MULTIFILE")}
        if not fields:
            return
        _FILE_FIELDS[table] = fields
        relay = self._kernel.get("relay")
        relay.add_hook(table, "validate", _validate_file_fields)
        relay.add_hook(table, "after_delete", _reap_after_delete)
        relay.add_hook(table, "after_save", _reap_after_save)


async def _validate_file_fields(ctx: Any) -> None:
    """Rejects a malformed FILE/MULTIFILE value with a proper 400 BEFORE
    the write happens — added after a hand-typed MULTIFILE JSON textarea
    value (admin-desk's FieldInput.tsx only checks "is this a JSON array",
    not each element's shape) reached _reap_after_save's _collect() as a
    raw AttributeError, which Gateway can only turn into a generic 500
    (it special-cases HTTPError/RelayError, nothing else). Only checks
    fields actually present in ctx.payload — an untouched field on this
    write isn't re-validated just because the row happens to carry one
    (that's _collect's job to survive gracefully, not this hook's job to
    police retroactively)."""
    fields = _FILE_FIELDS.get(ctx.table, {})
    for name, kind in fields.items():
        if name not in ctx.payload:
            continue
        val = ctx.payload[name]
        if not val:
            continue
        if kind == "FILE":
            if not isinstance(val, str):
                arc.relay.throw(
                    f"{name}: must be a file_id string, got {type(val).__name__}.",
                    code="invalid_file_value",
                )
        else:  # MULTIFILE
            if not isinstance(val, list):
                arc.relay.throw(
                    f'{name}: must be a JSON array of {{"label", "fileid"}} objects, '
                    f"got {type(val).__name__}.",
                    code="invalid_multifile_value",
                )
            for i, entry in enumerate(val):
                if not isinstance(entry, dict) or not entry.get("fileid"):
                    arc.relay.throw(
                        f"{name}[{i}]: must be an object with a 'fileid' key, "
                        f"got {entry!r}.",
                        code="invalid_multifile_entry",
                    )


def _collect(row: dict | None, fields: dict[str, str], into: set[str]) -> None:
    """Defensive on purpose, independent of _validate_file_fields above:
    this runs from after_delete/after_save against whatever is ALREADY
    persisted (ctx.old/ctx.new), which can predate this validation (older
    rows, a direct DB write, a future bug) — a malformed entry here should
    never crash a cleanup hook, just get skipped rather than reaped."""
    if row is None:
        return
    for name, kind in fields.items():
        val = row.get(name)
        if not val:
            continue
        if kind == "FILE":
            if isinstance(val, str):
                into.add(val)
        else:  # MULTIFILE
            if not isinstance(val, list):
                continue
            for entry in val:
                if not isinstance(entry, dict):
                    continue
                fid = entry.get("fileid")
                if fid:
                    into.add(str(fid))


@dataclass
class _UrlResolver(FieldResolver):
    """arc.filer.url(field)'s FieldResolver — see FilerProvider.url() and
    relay.resolvers for the prepare()/resolve() contract this fulfills.
    Handles both shapes filer ever stores: a bare file_id string (FILE)
    or a [{label, fileid}] array (MULTIFILE) — dispatched at runtime by
    the raw value's own shape, same as attach_urls() above does."""

    field: str
    provider: "FilerProvider"
    ttl_seconds: int | None = None

    async def prepare(self, raw_values: list[Any]) -> dict[str, dict]:
        ids: set[str] = set()
        for val in raw_values:
            if not val:
                continue
            if isinstance(val, list):
                ids.update(entry["fileid"] for entry in val if entry.get("fileid"))
            else:
                ids.add(str(val))
        if not ids:
            return {}
        # limit=None — same reasoning as _resolve_urls above: must resolve
        # every id this batch was given, already bounded by `ids` itself.
        rows = await arc.relay.list(
            "filerfile",
            filters={"file_id": {"in": list(ids)}},
            fields=["file_id", "private", "status"],
            limit=None,
        )
        return {row["file_id"]: row for row in rows}

    def resolve(self, raw_value: Any, context: dict[str, dict]) -> Any:
        if not raw_value:
            return None

        def _url(file_id: str) -> str | None:
            meta = context.get(file_id)
            if meta is None or meta["status"] not in ("clean", "skipped"):
                return None
            return self.provider._url_for(meta, self.ttl_seconds)

        if isinstance(raw_value, list):
            return [
                {"label": entry.get("label"), "url": _url(entry["fileid"])} for entry in raw_value
            ]
        return _url(str(raw_value))


async def _reap_after_delete(ctx: Any) -> None:
    fields = _FILE_FIELDS.get(ctx.table, {})
    ids: set[str] = set()
    _collect(ctx.old, fields, ids)
    for file_id in ids:
        arc.relay.enqueue(_mark_deleted, file_id)


async def _reap_after_save(ctx: Any) -> None:
    # Handles a FILE/MULTIFILE value CHANGING, not just the row being
    # deleted — e.g. employee.resume swapped from file A to file B: A
    # must be reaped, B must NOT be (it's the row's current file now).
    fields = _FILE_FIELDS.get(ctx.table, {})
    before, after = set(), set()
    _collect(ctx.old, fields, before)
    _collect(ctx.new, fields, after)
    for file_id in before - after:
        arc.relay.enqueue(_mark_deleted, file_id)


async def _mark_deleted(file_id: str) -> None:
    row = await arc.relay.get("filerfile", {"file_id": file_id}, ["id", "status"])
    if row is not None and row["status"] != "deleted":
        await arc.relay.save(
            "filerfile", {"id": row["id"], "status": "deleted", "deleted_at": arc.tz.utcnow()}
        )


async def _scan(filerfile_id: str) -> None:
    from filer.providers import PROVIDERS

    row = await arc.relay.get("filerfile", filerfile_id, ["id", "private", "storage", "storage_key"])
    if row is None:
        return
    if not arc.filer.scan_enabled(private=row["private"]):
        await arc.relay.save("filerfile", {"id": row["id"], "status": "skipped"})
        return
    content = await PROVIDERS[row["storage"]].read(row["storage_key"])
    infected = await _clamd_scan(content)
    await arc.relay.save(
        "filerfile", {"id": row["id"], "status": "infected" if infected else "clean"}
    )


async def _clamd_scan(content: bytes) -> bool:
    """True if ClamAV's INSTREAM command flags `content` as infected.
    Talks to a local clamd over its UNIX socket — the standard local-AV
    integration point, kept behind this one thin function so a different
    scanner could replace it later without touching the rest of filer."""

    def _do() -> bool:
        import socket
        import struct

        sock_path = arc.filer.clamav_socket()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(sock_path)
            sock.sendall(b"zINSTREAM\0")
            chunk_size = 65536
            for offset in range(0, len(content), chunk_size):
                chunk = content[offset : offset + chunk_size]
                sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            sock.sendall(struct.pack("!L", 0))
            response = sock.recv(4096).decode("utf-8", errors="replace")
        return "FOUND" in response

    return await asyncio.to_thread(_do)


async def _clamd_ping(socket_path: str) -> bool:
    """clamd's `PING` command — the actual connectivity check
    (antivirus_status() below). Deliberately NOT `VERSION`: some clamd
    configs disable it outright (`EnableVersionCommand false` in
    clamd.conf, confirmed against a real local install — VERSION returns
    the literal string "COMMAND UNAVAILABLE" there, which an earlier cut
    of this function mistook for "not connected" even though the daemon
    was up and scanning fine). PING has no such opt-out; it's always
    available whenever clamd is actually reachable."""

    def _do() -> bool:
        import socket

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(socket_path)
            sock.sendall(b"zPING\0")
            return sock.recv(4096).strip(b"\x00") == b"PONG"

    return await asyncio.to_thread(_do)


async def _clamd_version(socket_path: str) -> str | None:
    """Best-effort only — VERSION is disabled in some clamd configs (see
    _clamd_ping's docstring); a refusal here must never be read as "not
    connected", only as "version unknown"."""

    def _do() -> str | None:
        import socket

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(socket_path)
            sock.sendall(b"zVERSION\0")
            reply = sock.recv(4096).decode("utf-8", errors="replace").strip()
            return None if "UNAVAILABLE" in reply.upper() else reply

    return await asyncio.to_thread(_do)


def _ensure_scaffold(root: Path) -> None:
    for sub in ("public", "private"):
        d = root / sub
        d.mkdir(parents=True, exist_ok=True)
        (d / ".gitkeep").touch(exist_ok=True)


def _ensure_signing_secret(kernel: Any) -> None:
    """Generates filer_signing_secret ONCE, here at boot — not lazily on
    the first signed URL (FilerProvider._signing_secret's old shape).

    A lazy read-then-write on the request path races across every
    Granian worker PROCESS on a fresh install: each one misses, generates
    a DIFFERENT secret, and writes it — last writer wins, and every URL
    ANY earlier worker already signed becomes permanently unverifiable (a
    403 that looks like an ordinary link expiry, not a config bug).
    Moving the read-then-write to register() alone isn't enough by
    itself, though — N worker processes still boot roughly
    simultaneously, so the check-then-write itself needs a real
    cross-process lock, not just an earlier place in the code to run it.

    flock() on a dedicated lock file, not a Postgres advisory lock
    (psqldb.migrate.migration_lock's own pattern, the precedent this
    otherwise follows): register() runs synchronously, and there's no
    guarantee psqldb's pool is open yet at this exact point in boot, so
    there's no connection available to lock against here."""
    if kernel.settings.get(SIGNING_SECRET_KEY, reveal=True):
        return

    import fcntl

    lock_path = kernel.settings.arc_dir / "filer_signing_secret.lock"
    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            # Re-check under the lock — another worker may have already
            # generated and written one while this process waited for it.
            if not kernel.settings.get(SIGNING_SECRET_KEY, reveal=True):
                kernel.settings.set(SIGNING_SECRET_KEY, secrets.token_urlsafe(32), secret=True)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def register(kernel: Any) -> None:
    # Typed declare (matching authn/gateway's own adoption of this,
    # arc/arc/settings.py's declare()) — every FilerProvider settings
    # method below reads an already-coerced, already-defaulted value
    # instead of hand-parsing a raw string, and a bad value (e.g.
    # filer_purge_after_days set to "a month") now fails at arc.boot()
    # naming the setting, instead of surfacing wherever the purge task
    # first runs. allowed_content_types stays untyped: it's a
    # comma-separated SET, and declare()'s `type` only covers
    # int/float/bool/str, no collection support.
    kernel.settings.declare(LOCAL_ROOT_KEY, doc="Local storage root — defaults to <project>/files.")
    kernel.settings.declare(DEFAULT_STORAGE_KEY, default=DEFAULT_STORAGE, doc="'local' or 's3'.")
    kernel.settings.declare(
        ALLOWED_CONTENT_TYPES_KEY,
        doc="Comma-separated allowed MIME types. Empty/unset allows any.",
    )
    kernel.settings.declare(
        MAX_UPLOAD_BYTES_KEY, type=int, default=None, doc="Per-file upload ceiling. Unset = no cap."
    )
    kernel.settings.declare(
        SCAN_PUBLIC_KEY, type=bool, default=False, doc="Run antivirus scanning on public uploads."
    )
    kernel.settings.declare(
        SCAN_PRIVATE_KEY, type=bool, default=False, doc="Run antivirus scanning on private uploads."
    )
    kernel.settings.declare(CLAMAV_SOCKET_KEY, default=DEFAULT_CLAMAV_SOCKET, doc="clamd socket path.")
    kernel.settings.declare(
        PURGE_AFTER_DAYS_KEY,
        type=int,
        default=DEFAULT_PURGE_AFTER_DAYS,
        doc="Days before a soft-deleted file is purged for good.",
    )
    kernel.settings.declare(
        DEFAULT_LINK_TTL_KEY,
        type=int,
        default=DEFAULT_LINK_TTL_SECONDS,
        doc="Signed-URL default TTL, in seconds.",
    )
    kernel.settings.declare(
        URL_SIGNING_SCHEME_KEY,
        default="md5",
        doc="'md5' (default — required for nginx secure_link_md5 parity, see "
        "filer.tokens' own module docstring) or 'hmac-sha256' (stronger, but "
        "only safe to change if nginx isn't independently validating these "
        "URLs itself).",
    )
    kernel.settings.declare(SIGNING_SECRET_KEY, secret=True, doc="Auto-generated at boot if unset.")
    _ensure_signing_secret(kernel)
    kernel.settings.declare(S3_BUCKET_KEY, doc="S3 bucket name — required when default_storage is 's3'.")
    kernel.settings.declare(S3_REGION_KEY, doc="S3 region.")
    kernel.settings.declare(S3_ENDPOINT_URL_KEY, doc="Override for an S3-compatible endpoint (non-AWS).")
    kernel.settings.declare(S3_ACCESS_KEY_ID_KEY, secret=True)
    kernel.settings.declare(S3_SECRET_ACCESS_KEY_KEY, secret=True)
    kernel.settings.declare(
        MAX_REQUEST_BODY_BYTES_KEY,
        type=int,
        default=DEFAULT_MAX_REQUEST_BODY_BYTES,
        doc="Outer ASGI-level body ceiling for file_upload — bigger than gateway's own default.",
    )

    psqldb = kernel.get("pgdb")
    psqldb.register_model(Path(__file__).parent.parent / "schemas")
    psqldb.register_patches(Path(__file__).parent.parent / "patches")

    relay = kernel.get("relay")
    relay.register_hooks(Path(__file__).parent.parent / "hooks")
    relay.register_api(Path(__file__).parent.parent / "api")
    relay.register_tasks(Path(__file__).parent.parent / "tasks")

    from arc.runtime import find_project_root

    override = kernel.settings.get(LOCAL_ROOT_KEY)
    _ensure_scaffold(Path(override) if override else find_project_root() / "files")

    provider = FilerProvider(kernel)
    kernel.export(CAPABILITY, provider, requires=["pgdb", "relay"], optional_requires=["gateway"])

    # FILE/MULTIFILE discovery (docs §4) — sweep everything already
    # registered (plugins that loaded before filer), then subscribe for
    # everything registered from here on (schemas AND patches).
    for schema in psqldb.schemas():
        provider._maybe_watch(schema.table)
    psqldb.on_schema_registered(provider._maybe_watch)
