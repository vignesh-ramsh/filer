"""filer.content_types
-----------------
`filer_allowed_content_types`: the only list of what may be uploaded. A whitelist that starts closed.

  * Never set: the built-in DEFAULT_ALLOWED_CONTENT_TYPES below - the usual pictures, documents, spreadsheets,
    presentations, plain text, CSV and zip archives - and nothing else. Scripts, source code, web pages, SVG and
    programs (`text/html`, `image/svg+xml`, `application/javascript`, `application/x-msdownload`, ...) are not in it,
    and neither is the catch-all `application/octet-stream` that browsers use for anything they cannot name.
  * Set to a list: exactly that list, replacing the default. Comma-separated; letter case and parameters
    (`; charset=utf-8`) do not matter. Exact types only - there are no wildcards, so `image/*` names nothing.
  * Set to an EMPTY list: no file is allowed. Every upload is refused as an unallowed file type. Closed means closed: a
    blank box is not "allow everything".

The type is whatever the uploader's browser wrote in the multipart part header. For the types that have an unmistakable
start (pictures, PDF, ZIP and the Office formats built on it, gzip) `filer_verify_content_type` (filer/sniff.py) checks
the first bytes against it, so the claim cannot be a lie there; for text and CSV nothing can check it.
"""

from __future__ import annotations

import re

from .sniff import normalise

#: What is allowed until someone sets the list. It covers what ARC itself uploads and takes in (data exports are CSV
#: and XLSX) and what the HR plugin stores (photos, scanned documents). `application/vnd.ms-excel` is what Windows
#: browsers call a CSV file, and `application/x-zip-compressed` what they call a zip.
DEFAULT_ALLOWED_CONTENT_TYPES = (
    "image/png, image/jpeg, image/gif, image/webp, image/bmp, image/tiff, "
    "application/pdf, "
    "application/msword, "
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document, "
    "application/vnd.ms-excel, "
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, "
    "application/vnd.ms-powerpoint, "
    "application/vnd.openxmlformats-officedocument.presentationml.presentation, "
    "application/vnd.oasis.opendocument.text, "
    "application/vnd.oasis.opendocument.spreadsheet, "
    "application/vnd.oasis.opendocument.presentation, "
    "application/rtf, text/rtf, "
    "text/plain, text/csv, "
    "application/zip, application/x-zip-compressed"
)

_SEPARATORS = re.compile(r"[,;\s]+")


def parse(raw: str | None) -> frozenset[str]:
    """The `filer_allowed_content_types` value as a set of lower-case media types without parameters.

    * `None` (the setting was never given a value): the default list.
    * An empty set when the value names nothing (empty, blank, only separators): nothing is allowed."""
    text = DEFAULT_ALLOWED_CONTENT_TYPES if raw is None else raw
    return frozenset(entry for entry in (normalise(part) for part in _SEPARATORS.split(text)) if entry)


def problem(content_type: str | None, allowed: frozenset[str]) -> str | None:
    """None when `content_type` is one of the `allowed` types; otherwise a sentence saying why not. With an empty
    `allowed` nothing matches, and the sentence says the list itself is empty."""
    if not allowed:
        return (
            "this file type is not allowed: the list of allowed content types on this server is empty, "
            "so no files are accepted"
        )
    media = normalise(content_type)
    if media in allowed:
        return None
    if not media:
        return "this file type is not allowed: the file has no content type"
    return f"content type '{media}' is not allowed"
