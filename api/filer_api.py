"""filer's HTTP surface — exactly two routes, deliberately (docs
§8: filer has no generic public "sign this file_id for me" endpoint;
a signed URL only ever reaches a client through a business endpoint
that already passed its own role gate).

  * POST /files/upload — authenticated. Needs the raw multipart body,
    which no whitelisted function could access before relay's
    `wants_request` addition (see relay/relay/__init__.py) — this is
    that addition's first, and so far only, real consumer.
  * GET  /files/{file_id} — Guest-reachable at the relay layer (a
    public file must be reachable with no auth at all); the function
    body re-checks `private` itself and validates the signature for
    anything private. This is the "no nginx" dev-mode path — nginx,
    when present, validates the identical signature itself and never
    even proxies most requests here (filer/tokens.py's own docstring).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import arc

from filer import MAX_REQUEST_BODY_BYTES_KEY, DEFAULT_MAX_REQUEST_BODY_BYTES

_INLINE_ALLOWLIST = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"}
)

# original_filename is whatever the uploader's browser sent as the
# multipart filename= parameter (gateway.multipart._param) — stored
# verbatim, never sanitized on the way in. Two failure modes this closes,
# both confirmed directly against this exact f-string:
#   * CR/LF survive .encode("latin-1") intact — a filename like
#     'a"\r\nSet-Cookie: x=1\r\n' becomes a second header line once this
#     value reaches send_stream's own header encoding.
#   * Any character outside latin-1 (any CJK/Cyrillic name, an emoji)
#     raises UnicodeEncodeError INSIDE send_stream, after
#     http.response.start has already been sent — the download simply
#     breaks for that file, every time.
_DISPOSITION_STRIP_RE = re.compile(r'[\r\n"\\\x00-\x1f\x7f]')


def _content_disposition(filename: str) -> str:
    """RFC 6266: an ASCII-safe `filename` for clients that don't parse
    `filename*`, plus a percent-encoded `filename*=UTF-8''...` for
    everything else — so a non-Latin-1 name still downloads with its real
    name instead of crashing the response. CR/LF/quote/control characters
    are stripped outright rather than escaped: none are legitimate in a
    filename, and any of them ending up in this exact position is a
    header-injection attempt, not a genuine name."""
    cleaned = _DISPOSITION_STRIP_RE.sub("_", filename or "").strip() or "download"
    ascii_name = cleaned.encode("ascii", "replace").decode("ascii")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned, safe='')}"

# Computed once, at import time (this module loads during relay
# .register_api() -> filer.register(), by which point filer's own
# settings.declare() calls have already run) — the route's own outer
# ASGI body ceiling, deliberately separate from the live-editable,
# per-file-content MAX_UPLOAD_BYTES_KEY checked inside arc.filer.upload()
# itself. See filer/__init__.py's MAX_REQUEST_BODY_BYTES_KEY docstring.
_raw_max_body = arc.settings.get(MAX_REQUEST_BODY_BYTES_KEY)
_MAX_REQUEST_BODY_BYTES = int(_raw_max_body) if _raw_max_body else DEFAULT_MAX_REQUEST_BODY_BYTES


def _require_identity(identity):
    if identity is None:
        arc.relay.throw("authentication required", status=401, code="unauthorized")
    return identity


def _as_bool(value: bool | str, *, default: bool) -> bool:
    """`private` typically arrives as a query-string arg (multipart POST
    bodies can't carry it — the body IS the file), and relay's kwarg
    merging never coerces query-string values beyond a plain string (no
    type coercion is a documented, known limitation — see relay's own
    _wire_gateway_route docstring). Without this, the STRING "false" is
    truthy in Python and would reach asyncpg's BOOLEAN column encoder as
    a raw str, which it rejects outright rather than silently doing the
    wrong thing — this is what actually surfaced the bug during testing."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() not in ("false", "0", "no", "")


@arc.relay.whitelist(
    methods=["POST"], roles=["*"], path="/files/upload", max_body_bytes=_MAX_REQUEST_BODY_BYTES
)
async def file_upload(
    request,
    storage: str | None = None,
    private: bool | str = True,
    path: str | None = None,
    identity=None,
) -> dict:
    identity = _require_identity(identity)
    form = request.form()
    upload = form.files.get("file")
    if upload is None:
        arc.relay.throw("no file part named 'file' in the multipart body", code="missing_file")
    row = await arc.filer.upload(
        upload.content,
        upload.filename,
        content_type=upload.content_type,
        storage=storage,
        private=_as_bool(private, default=True),
        path=path,
        by=identity.email,
    )
    return {
        "file_id": row["file_id"],
        "status": row["status"],
        "private": row["private"],
        "path": row["path"],
    }


@arc.relay.whitelist(methods=["GET"], roles=["Guest"], path="/files/{file_id}")
async def serve_file(file_id: str, exp: int | str | None = None, sig: str | None = None) -> Any:
    from filer.providers import PROVIDERS
    from filer.tokens import verify
    from gateway.request import StreamResponse

    row = await arc.relay.get("filerfile", {"file_id": file_id}, arc.relay.all_columns("filerfile"))
    if row is None or row["status"] not in ("clean", "skipped"):
        arc.relay.throw("not found", status=404, code="not_found")
    if row["private"]:
        # `row["private"]` (the DB row) is authoritative here, never
        # `file_id`'s own pub_/pri_ prefix — the prefix is only a routing
        # hint for nginx's regex location match, not an authorization
        # signal (docs §9's own note on this).
        #
        # `exp` always arrives as a plain query-string str (relay's kwarg
        # merging never coerces beyond that — the same documented,
        # known limitation file_upload's `_as_bool` already works around
        # for `private`); parse it explicitly rather than trust the type
        # annotation, which only helps callers going through
        # arc.relay.call() directly with a real int.
        try:
            exp_int = int(exp) if exp is not None else None
        except (TypeError, ValueError):
            exp_int = None
        if not (
            exp_int is not None
            and sig
            and verify(
                f"/files/{file_id}",
                exp_int,
                sig,
                arc.filer._signing_secret(),
                scheme=arc.filer.url_signing_scheme(),
            )
        ):
            arc.relay.throw("forbidden", status=403, code="forbidden")

    provider = PROVIDERS[row["storage"]]
    inline = row["content_type"] in _INLINE_ALLOWLIST
    disposition = "inline" if inline else _content_disposition(row["original_filename"])
    headers = {"Content-Disposition": disposition}
    if inline:
        # SAMEORIGIN, not the gateway-wide default DENY (see
        # gateway/middleware.py's security_headers_middleware for why an
        # explicit header here is actually respected rather than
        # silently overridden) — needed so an inline-allowlisted file
        # (image/PDF) can render in this app's own preview `<iframe>`.
        # A forced-download `attachment` response never sets this at
        # all, so it keeps the stricter DENY default — framing doesn't
        # matter for a download, and there's no reason to relax it there.
        headers["X-Frame-Options"] = "SAMEORIGIN"
    return StreamResponse(
        source=provider.read_stream(row["storage_key"]),
        media_type=row["content_type"],
        headers=headers,
    )
