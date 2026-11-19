"""filer.sniff
-----------------
Does a file's content agree with the type its uploader said it was?

The content type of an upload is whatever the uploader's browser (or script) wrote in the multipart part header. It
is not verified by anything, so `filer_allowed_content_types` on its own was a list of what a client is willing to
SAY, and a file stored as `image/png` could be anything. This module looks at the first bytes of the file, the
"magic number" most binary formats begin with, and refuses a file whose declared type needs one it does not have, and
a program (ELF, Windows PE, Mach-O) presented as something other than a program.

What it deliberately does not do:

  * It does not decide what a file IS. A type with no reliable signature (text, CSV, JSON, SVG, legacy Office files,
    anything unknown) is not checked - nobody can tell a CSV from a text file by its first bytes, and Windows browsers
    label CSV `application/vnd.ms-excel`, so a rule for it would refuse honest files.
  * It does not open archives. A `.docx` is checked for the ZIP signature, not for being a Word document.
  * It is not antivirus. ClamAV (`filer_scan_*`) is.

A file is served `inline` only for png/jpeg/gif/webp/pdf and always with `X-Content-Type-Options: nosniff`, so a
mislabelled file could never run as a page; this makes the stored type trustworthy, for the allow-list and for
anything else that reads it. Switched off with `filer_verify_content_type`.
"""

from __future__ import annotations

#: How many bytes from the start of the file are looked at. A PDF may put its header up to 1024 bytes in, and a PE
#: file's "PE" marker sits where its DOS header points (normally below 0x200): 2 KiB covers both.
HEAD_BYTES = 2048

_PNG = b"\x89PNG\r\n\x1a\n"
_PE_MAGIC = b"PE\x00\x00"
_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_ZIP = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")  # a file, an empty archive, a spanned one


def sniff(head: bytes) -> str | None:
    """The kind of file whose signature `head` (the first bytes) carries, or None when it carries none of the ones
    this module knows. One of: png, jpeg, gif, webp, bmp, tiff, ico, pdf, zip, gzip, executable."""
    if head.startswith(_PNG):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:4] == b"\x00\x00\x01\x00":
        return "ico"
    if head[:2] == b"BM" and len(head) >= 14:  # two letters alone are far too common a start for text
        return "bmp"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(_ZIP):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if _is_executable(head):
        return "executable"
    return None


def _is_executable(head: bytes) -> bool:
    if head.startswith(b"\x7fELF") or head[:4] in _MACHO:
        return True
    if head[:2] == b"MZ" and len(head) >= 0x40:
        # "MZ" alone is the start of any text beginning with those two letters: a real PE file's DOS header says
        # where its "PE\0\0" marker is (offset 0x3C), and it is there.
        offset = int.from_bytes(head[0x3C:0x40], "little")
        return head[offset : offset + 4] == _PE_MAGIC
    return False


#: Declared type -> the kinds of file it may really be. Only types whose first bytes are unambiguous are listed.
EXPECTED: dict[str, frozenset[str]] = {
    "image/png": frozenset({"png"}),
    "image/jpeg": frozenset({"jpeg"}),
    "image/jpg": frozenset({"jpeg"}),
    "image/pjpeg": frozenset({"jpeg"}),
    "image/gif": frozenset({"gif"}),
    "image/webp": frozenset({"webp"}),
    "image/bmp": frozenset({"bmp"}),
    "image/tiff": frozenset({"tiff"}),
    "image/x-icon": frozenset({"ico"}),
    "image/vnd.microsoft.icon": frozenset({"ico"}),
    "application/pdf": frozenset({"pdf"}),
    "application/gzip": frozenset({"gzip"}),
    "application/x-gzip": frozenset({"gzip"}),
    # ZIP itself, and the formats that are ZIP files inside: Office Open XML, OpenDocument, Java archives
    "application/zip": frozenset({"zip"}),
    "application/x-zip-compressed": frozenset({"zip"}),
    "application/java-archive": frozenset({"zip"}),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": frozenset({"zip"}),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": frozenset({"zip"}),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": frozenset({"zip"}),
    "application/vnd.oasis.opendocument.text": frozenset({"zip"}),
    "application/vnd.oasis.opendocument.spreadsheet": frozenset({"zip"}),
    "application/vnd.oasis.opendocument.presentation": frozenset({"zip"}),
}

#: Declared types that make no claim about the content: a program may be sent as one of these.
GENERIC_TYPES = frozenset({"", "application/octet-stream", "binary/octet-stream"})

#: Declared types that say "this is a program".
EXECUTABLE_TYPES = frozenset(
    {
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-elf",
        "application/x-sharedlib",
        "application/x-mach-binary",
    }
)


def normalise(declared: str | None) -> str:
    """The media type of a Content-Type value: lower case, without parameters (`; charset=...`)."""
    return (declared or "").split(";", 1)[0].strip().lower()


def mismatch(declared: str | None, head: bytes) -> str | None:
    """None when the first bytes `head` agree with the declared type; otherwise a sentence saying how they do not
    (for the error the uploader sees)."""
    media = normalise(declared)
    kind = sniff(head)
    expected = EXPECTED.get(media)
    if expected is not None:
        if kind in expected:
            return None
        found = f"looks like {_describe(kind)}" if kind else "does not look like that kind of file"
        return f"the file is declared as '{media}' but its content {found}"
    if kind == "executable" and media not in GENERIC_TYPES and media not in EXECUTABLE_TYPES:
        return f"the file is declared as '{media}' but its content is a program"
    return None


def _describe(kind: str) -> str:
    return {"executable": "a program", "zip": "a ZIP archive", "gzip": "a gzip archive"}.get(kind, f"a {kind.upper()} file")
