"""filer.clamd
-------------
A small ClamAV (clamd) client over its UNIX socket: `INSTREAM`, `PING`, `VERSION`.

`scan_stream` sends a file to clamd piece by piece as it is read from storage, so scanning a file never loads it
into memory (the job used to `read()` the whole file, then send it). What it reports, and why each case is its own
result rather than "clean unless it says FOUND":

  * "clean"     - clamd scanned every byte and found nothing;
  * "infected"  - clamd named a signature;
  * "too_large" - clamd refused the stream because it is over its own `StreamMaxLength` (`INSTREAM size limit
                  exceeded`). The file was NOT scanned. The caller decides what that means (filer marks it
                  skipped: an unscanned file is never called clean);
  * ClamdError  - clamd was unreachable, timed out, or answered with an error: nothing is known about the file,
                  so the job leaves it pending and a later run tries again.

Blocking socket work runs in a worker thread (`asyncio.to_thread`, one hop per piece, like the storage providers).
The socket path and the timeout are read by the caller on the event loop and passed in: the settings store must
not be read from a worker thread.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

#: clamd reads a stream as a series of (4-byte big-endian length, bytes) frames ended by a zero length. Each
#: piece handed to `scan_stream` is cut into frames of at most this many bytes.
MAX_FRAME_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0


class ClamdError(Exception):
    """clamd could not give a verdict (unreachable, timed out, or an error reply). Retryable: nothing is known
    about the file."""


@dataclass(frozen=True)
class ScanResult:
    verdict: str  # "clean" | "infected" | "too_large"
    signature: str | None = None  # the signature clamd named, when infected
    scanned_bytes: int = 0

    @property
    def infected(self) -> bool:
        return self.verdict == "infected"


def parse_reply(reply: str) -> ScanResult:
    """Turn clamd's answer to an INSTREAM into a result, or raise ClamdError for one that says nothing about
    the file. Replies look like `stream: OK`, `stream: Eicar-Test-Signature FOUND`, `INSTREAM size limit
    exceeded. ERROR` (the NUL that ends a `z` command's reply is dropped first)."""
    text = reply.replace("\x00", "").strip()
    if text.endswith("FOUND"):
        signature = text.split(":", 1)[-1].strip()[: -len("FOUND")].strip() or None
        return ScanResult("infected", signature)
    if text.endswith("OK"):
        return ScanResult("clean")
    if "size limit exceeded" in text.lower():
        return ScanResult("too_large")
    raise ClamdError(f"clamd answered {text or 'nothing'!r}")


def _connect(socket_path: str, timeout: float) -> socket.socket:
    """Connect to clamd's socket. On a UNIX socket whose listen queue is full a non-blocking connect fails at
    once with EAGAIN instead of waiting its turn (a busy clamd, many scans at the same moment): retry with a
    short growing pause until `timeout` has passed, as a blocking connect would have waited."""
    deadline = time.monotonic() + timeout
    pause = 0.01
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(socket_path)
            return sock
        except BlockingIOError:
            sock.close()
            if time.monotonic() + pause >= deadline:
                raise TimeoutError(
                    f"clamd's connection queue stayed full for {timeout:g} s"
                ) from None
            time.sleep(pause)
            pause = min(pause * 2, 0.25)
        except OSError:
            sock.close()
            raise


def _read_reply(sock: socket.socket) -> str:
    """Everything clamd sends until it closes the connection or ends the reply with its NUL."""
    parts: list[bytes] = []
    while True:
        piece = sock.recv(4096)
        if not piece:
            break
        parts.append(piece)
        if piece.endswith(b"\x00"):
            break
    return b"".join(parts).decode("utf-8", errors="replace")


async def _send(sock: socket.socket, data: bytes) -> bool:
    """Send `data`; False when clamd has hung up (its reply, already waiting, says why), ClamdError for any
    other socket failure."""
    try:
        await asyncio.to_thread(sock.sendall, data)
        return True
    except (BrokenPipeError, ConnectionResetError):
        return False
    except OSError as exc:
        raise ClamdError(f"sending to clamd failed: {exc}") from exc


async def scan_stream(
    socket_path: str,
    pieces: AsyncIterator[bytes],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ScanResult:
    """Send `pieces` to clamd and return its verdict. `timeout` bounds every single socket operation (connect,
    each send, the wait for the verdict), not the whole scan: a big file may take longer than that in total as
    long as clamd keeps taking it. An error raised BY `pieces` (the file is missing from storage, say) is not
    clamd's and propagates as it is."""
    try:
        sock = await asyncio.to_thread(_connect, socket_path, timeout)
    except OSError as exc:
        raise ClamdError(f"cannot reach clamd at {socket_path}: {exc}") from exc
    try:
        alive = await _send(sock, b"zINSTREAM\0")
        sent = 0
        try:
            async for piece in pieces:
                for offset in range(0, len(piece), MAX_FRAME_BYTES):
                    frame = piece[offset : offset + MAX_FRAME_BYTES]
                    alive = await _send(sock, struct.pack("!L", len(frame)) + frame)
                    if not alive:
                        break
                    sent += len(frame)
                if not alive:
                    break
        finally:
            aclose = getattr(pieces, "aclose", None)
            if aclose is not None:
                await aclose()
        if alive:
            await _send(sock, struct.pack("!L", 0))
        try:
            reply = await asyncio.to_thread(_read_reply, sock)
        except OSError as exc:
            raise ClamdError(f"clamd did not answer: {exc}") from exc
        result = parse_reply(reply)
        return ScanResult(result.verdict, result.signature, sent)
    finally:
        await asyncio.to_thread(sock.close)


async def command(socket_path: str, name: bytes, *, timeout: float = 2.0) -> str:
    """One simple clamd command (`PING`, `VERSION`) and its reply."""

    def _do() -> str:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall(b"z" + name + b"\0")
            return _read_reply(sock).replace("\x00", "").strip()

    return await asyncio.to_thread(_do)
